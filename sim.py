# NOTE:
# If you're running this on a Linux system and want to avoid interference from the kernel's own SYN cookie mechanism,
# you can temporarily disable it using the following command:
#     sudo sysctl -w net.ipv4.tcp_syncookies=0
# To re-enable it after testing:
#     sudo sysctl -w net.ipv4.tcp_syncookies=1
# To check current status:
#     sysctl net.ipv4.tcp_syncookies

import os
import time
import json
import random
import struct
import hmac
import hashlib
import threading
import socket
import psutil
import statistics
from datetime import datetime, timezone
from subprocess import run, PIPE
from scapy.all import *

# === CONSTANTS ===
SERVER_PORT = 12345
INTERFACE = "eth0"
SECRET_KEY = b'super_secret_key'
NONCE_SIZE = 8
TCP_NONCE_KIND = 254  # experimental TCP option

# ============================================================
# === TRADITIONAL SYN COOKIE (RFC 4987 / Linux kernel style) ===
# ============================================================
# Real traditional SYN cookies encode 3 fields into the 32-bit ISN:
#   Bits 31-27 (5 bits) : t  — timestamp counter (increases every 64 sec)
#   Bits 26-24 (3 bits) : m  — MSS index (maps to one of 8 standard MSS values)
#   Bits 23-0  (24 bits): hash — truncated HMAC over (src_ip, src_port, dst_ip,
#                                dst_port, t) using a rotating secret
#
# This matches the Linux kernel implementation (net/ipv4/syncookies.c)
# MSS table mirrors the kernel's tcp_msstable[]

_MSS_TABLE = [536, 1300, 1440, 1460, 1480, 1500, 4460, 9000]
# Rotating secret: split into two halves, swap every 60 seconds (like kernel)
_SYNCOOKIE_SECRET = [
    hashlib.sha256(b'syncookie_secret_0').digest(),
    hashlib.sha256(b'syncookie_secret_1').digest(),
]

def _trad_timestamp():
    """64-second counter — same granularity as Linux kernel."""
    return int(time.time()) >> 6   # divide by 64

def _trad_hash(src_ip, src_port, dst_ip, dst_port, t):
    """
    Truncated HMAC over the 5-tuple + timestamp counter.
    Uses the active half of the rotating secret, mirrors syncookies.c.
    """
    secret_idx = t & 1
    secret     = _SYNCOOKIE_SECRET[secret_idx]
    msg        = (socket.inet_aton(src_ip)
                  + struct.pack(">H", src_port)
                  + socket.inet_aton(dst_ip)
                  + struct.pack(">HH", dst_port, t & 0xFFFF))
    digest = hmac.new(secret, msg, hashlib.sha256).digest()
    return struct.unpack(">I", digest[:4])[0] & 0x00FFFFFF  # 24-bit hash

def trad_generate_syn_cookie(src_ip, src_port, dst_ip, dst_port, mss=1460):
    """
    Generate a real-style SYN cookie ISN:
      [t:5][mss_idx:3][hash:24]
    """
    t       = _trad_timestamp() & 0x1F          # 5-bit timestamp
    mss_idx = min(range(len(_MSS_TABLE)),
                  key=lambda i: abs(_MSS_TABLE[i] - mss)) & 0x7  # 3-bit MSS index
    h       = _trad_hash(src_ip, src_port, dst_ip, dst_port, t)
    cookie  = (t << 27) | (mss_idx << 24) | h
    return cookie & 0xFFFFFFFF

def trad_validate_syn_cookie(src_ip, src_port, dst_ip, dst_port, cookie):
    """
    Validate by extracting t and mss_idx from cookie, recomputing hash.
    Checks current timestamp AND previous (to tolerate clock tick boundary).
    Returns (valid: bool, mss: int)
    """
    t       = (cookie >> 27) & 0x1F
    mss_idx = (cookie >> 24) & 0x7
    h_recv  = cookie & 0x00FFFFFF
    now     = _trad_timestamp()
    for delta in (0, 1):
        t_check = (now - delta) & 0x1F
        if t_check == t:
            h_expected = _trad_hash(src_ip, src_port, dst_ip, dst_port, t)
            if h_expected == h_recv:
                return True, _MSS_TABLE[mss_idx]
    return False, 0

# ============================================================
# === ANALYZER FUNCTION ===
# ============================================================
def analyze_syn_cookies(pcap_file, server_ip, server_port=12345):
    if not os.path.exists(pcap_file):
        print(f"[!] File not found: {pcap_file}")
        return

    packets = rdpcap(pcap_file)

    print(f"[*] Loaded {len(packets)} packets from '{pcap_file}'\n")
    print("Detected SYN-ACK packets (SYN cookies):")
    print("-" * 110)

    found = False

    for pkt in packets:
        if IP in pkt and TCP in pkt:
            ip = pkt[IP]
            tcp = pkt[TCP]

            # Extract nonce from TCP options (if present)
            nonce = None
            for opt in tcp.options:
                if opt[0] == TCP_NONCE_KIND:
                    nonce = opt[1]

            # SYN-ACK (server → client)
            if tcp.flags == 0x12 and ip.src == server_ip and tcp.sport == server_port:
                print(
                    f"[+] {ip.src}:{tcp.sport} → {ip.dst}:{tcp.dport} | "
                    f"SEQ(cookie): {tcp.seq} | "
                    f"ACK: {tcp.ack} | "
                    f"WIN: {tcp.window} | "
                    f"NONCE: {nonce.hex() if nonce else 'N/A'}"
                )
                found = True

            # ACK (client → server)
            elif tcp.flags == 0x10 and ip.dst == server_ip and tcp.dport == server_port:
                print(
                    f"[✓] {ip.src}:{tcp.sport} → {ip.dst}:{tcp.dport} | "
                    f"ACK(response): {tcp.ack} | "
                    f"WIN: {tcp.window}"
                )
                found = True

    if not found:
        print("[!] No SYN-ACK packets from the specified server were found.")
# ============================================================
# === CLIENT FUNCTION  ===
# ============================================================

def run_client():
    SERVER_IP   = input("Enter the server IP (e.g., 10.211.55.6): ").strip()
    SERVER_PORT = int(input("Enter the server port (e.g., 12345): ").strip())

    # === Section 11: perf collectors ===
    _proc          = psutil.Process(os.getpid())
    _cpu_count     = psutil.cpu_count(logical=True) or 1
    _rtt_ms        = []
    _cpu_samples   = []
    _handshake_tuples = []
    _session_start = time.perf_counter()

    # get the real local IP this machine will use to reach SERVER_IP
    try:
        _s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _s.connect((SERVER_IP, 80))
        LOCAL_IP = _s.getsockname()[0]
        _s.close()
    except Exception:
        LOCAL_IP = "127.0.0.1"

    while True:
        CLIENT_PORT = random.randint(1024, 65535)
        start_time  = time.perf_counter()
        _proc.cpu_percent(interval=None)

        ip  = IP(dst=SERVER_IP)
        syn = TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="S", seq=1000)
        send(ip / syn, verbose=0)
        print(f"[+] SYN sent from port {CLIENT_PORT}")

        def handle_syn_ack(pkt):
            if pkt.haslayer(TCP) and pkt[IP].src == SERVER_IP and pkt[TCP].flags == "SA":
                cookie = pkt[TCP].seq
                print(f"[✓] SYN-ACK received with cookie (seq): {cookie}")

                ack_pkt = IP(dst=SERVER_IP) / TCP(
                    sport=CLIENT_PORT,
                    dport=SERVER_PORT,
                    flags="A",
                    seq=1001,
                    ack=cookie + 1
                )
                send(ack_pkt, verbose=0)

                end    = time.perf_counter()
                rtt_ms = (end - start_time) * 1000
                _rtt_ms.append(rtt_ms)
                _cpu_samples.append(_proc.cpu_percent(interval=None) / _cpu_count)
                _handshake_tuples.append((LOCAL_IP, CLIENT_PORT, SERVER_IP))
                print(f"[✓] ACK sent. Round-trip time: {end - start_time:.4f} sec")

        sniff(
            filter=f"tcp and src host {SERVER_IP} and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack != 0",
            prn=handle_syn_ack,
            timeout=3,
            store=False
        )

        if input("Try again? (y/n): ").lower() != 'y':
            break

    # ================================================================
    # Section 11 — Client Performance Report
    # Reports real measured network RTT for the enhanced mechanism only.
    # Traditional RTT is not comparable (no real network transmission).
    # CPU sampled around each handshake, normalized per-core.
    # ================================================================
    n_runs = len(_rtt_ms)

    if n_runs == 0:
        print("\n[!] No completed handshakes — performance report skipped.")
        return

    avg_cpu_enh = statistics.mean(_cpu_samples) if _cpu_samples else 0.0
    session_elapsed = time.perf_counter() - _session_start
    enh_tput = n_runs / session_elapsed if session_elapsed > 0 else 0

    W = 67
    def srow(label, val):
        print(f"  {label:<40} {str(val):>16}")
    def divider():
        print(f"  {'-'*58}")

    print("\n" + "=" * W)
    print("  SECTION 11 — CLIENT PERFORMANCE REPORT")
    print("  Nonce-Enhanced SYN Cookie (real network measurements)")
    print("=" * W)

    print("\n  11.1  Handshake Latency (real end-to-end network RTT)")
    divider()
    srow("  Completed handshakes",         f"{n_runs}")
    srow("  Avg RTT (ms)",                 f"{statistics.mean(_rtt_ms):.4f}")
    srow("  Min RTT (ms)",                 f"{min(_rtt_ms):.4f}")
    srow("  Max RTT (ms)",                 f"{max(_rtt_ms):.4f}")
    if n_runs > 1:
        srow("  Stdev RTT (ms)",           f"{statistics.stdev(_rtt_ms):.4f}")
    print("  (Traditional RTT not reported — no real network leg in baseline)")

    print("\n  11.2  CPU Overhead (normalized per-core, during handshake)")
    divider()
    srow("  Avg CPU % (enhanced)",         f"{avg_cpu_enh:.2f}%")

    print("\n  11.3  Throughput (handshakes / session duration)")
    divider()
    srow("  Session duration (sec)",       f"{session_elapsed:.2f}")
    srow("  Connections/sec (enhanced)",   f"{enh_tput:.2f}")

    print("\n" + "=" * W + "\n")
# ============================================================
# === SERVER FUNCTION ===
# ============================================================

def start_server():
    nonce_table = {}

    # === Section 11: perf collectors ===
    _proc          = psutil.Process(os.getpid())
    _cpu_count     = psutil.cpu_count(logical=True) or 1  # for per-core normalization
    _perf_gen_ms   = []   # nonce-enhanced: generation time per SYN
    _perf_val_ms   = []   # nonce-enhanced: validation time per ACK
    _perf_cpu      = []   # CPU % sampled during handling (normalized per-core)
    _perf_valid    = []   # bool per ACK
    _syn_tuples    = []
    _session_start = [None]

    json_file = f"syn_cookie_log_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
    with open(json_file, "w") as f:
        json.dump([], f, indent=4)

    def generate_nonce():
        secure = os.urandom(NONCE_SIZE)
        extra = random.getrandbits(64).to_bytes(8, "big")
        return secure + extra

    def generate_syn_cookie(client_ip, client_port, nonce):
        timestamp = int(time.time()) // 60
        msg = f"{client_ip}:{client_port}:{timestamp}".encode() + nonce
        digest = hmac.new(SECRET_KEY, msg, hashlib.sha256).digest()
        return struct.unpack(">I", digest[:4])[0]

    def validate_syn_cookie(client_ip, client_port, received_seq, nonce):
        timestamp = int(time.time()) // 60
        msg = f"{client_ip}:{client_port}:{timestamp}".encode() + nonce
        expected = hmac.new(SECRET_KEY, msg, hashlib.sha256).digest()
        expected_seq = struct.unpack(">I", expected[:4])[0]
        return expected_seq == received_seq

    def log_json(client_ip, client_port, nonce, cookie):
        entry = {
            "timestamp": int(time.time()),
            "client_ip": client_ip,
            "client_port": client_port,
            "nonce": nonce.hex(),
            "syn_cookie": cookie
        }
        with open(json_file, "r+") as f:
            data = json.load(f)
            data.append(entry)
            f.seek(0)
            json.dump(data, f, indent=4)

    def handle_packet(pkt):
        if pkt.haslayer(TCP) and pkt[TCP].flags == "S":
            client_ip   = pkt[IP].src
            client_port = pkt[TCP].sport
            server_ip   = pkt[IP].dst

            if _session_start[0] is None:
                _session_start[0] = time.perf_counter()

            # === Section 11: time nonce-enhanced generation ===
            _proc.cpu_percent(interval=None)
            t0     = time.perf_counter()
            nonce  = generate_nonce()
            cookie = generate_syn_cookie(client_ip, client_port, nonce)
            _perf_gen_ms.append((time.perf_counter() - t0) * 1000)
            _perf_cpu.append(_proc.cpu_percent(interval=None) / _cpu_count)
            _syn_tuples.append((client_ip, client_port, server_ip))

            nonce_table[(client_ip, client_port)] = nonce
            log_json(client_ip, client_port, nonce, cookie)
            print(f"[+] Cookie generated for {client_ip}:{client_port} → {cookie}")

            ip  = IP(src=server_ip, dst=client_ip)
            tcp = TCP(
                sport=SERVER_PORT,
                dport=client_port,
                flags="SA",
                seq=cookie,
                ack=pkt[TCP].seq + 1,
                window=0,
                options=[("MSS", 1460), (TCP_NONCE_KIND, nonce)]
            )
            send(ip / tcp, verbose=0)

        elif pkt.haslayer(TCP) and pkt[TCP].flags == "A":
            client_ip       = pkt[IP].src
            client_port     = pkt[TCP].sport
            received_cookie = pkt[TCP].ack - 1
            nonce           = nonce_table.get((client_ip, client_port))

            # === Section 11: time nonce-enhanced validation ===
            t0    = time.perf_counter()
            valid = nonce and validate_syn_cookie(client_ip, client_port, received_cookie, nonce)
            _perf_val_ms.append((time.perf_counter() - t0) * 1000)
            _perf_valid.append(bool(valid))

            if valid:
                print(f"[✓] Valid ACK from {client_ip}:{client_port}")
                del nonce_table[(client_ip, client_port)]
            else:
                print(f"[✗] Invalid ACK from {client_ip}:{client_port}")

    # ===============================
    # PCAP SETUP 
    # ===============================
    capture_file = input("Enter a name for the packet capture file (e.g., server_capture.pcap): ").strip()
    if not os.path.isabs(capture_file):
        capture_file = os.path.join(os.getcwd(), capture_file)

    print(f"[*] PCAP will be saved to: {capture_file}")
    print("[*] Capturing traffic. Press ENTER to stop and save.")

    sniffer = AsyncSniffer(
        iface=INTERFACE,
        filter=f"tcp port {SERVER_PORT}",
        prn=handle_packet,
        store=True
    )
    sniffer.start()
    input()
    packets = sniffer.stop()
    wrpcap(capture_file, packets)

    print(f"[✓] Capture saved to '{capture_file}'")
    print(f"[✓] JSON log saved to '{json_file}'")

    # ================================================================
    # Section 11 — Server Performance Report
    # Both mechanisms timed on pure crypto operations only:
    #   Traditional: HMAC(ip:port:timestamp) → truncate 32 bits
    #   Enhanced:    os.urandom() + HMAC(ip:port:timestamp:nonce) → truncate 32 bits
    # No packet sending, logging, or table ops included in timing.
    # CPU sampled around the same pure crypto block, normalized per-core.
    # Traditional replayed N_REPS times for stable statistics.
    # ================================================================
    n_syns          = len(_perf_gen_ms)
    enh_valid_count = sum(_perf_valid)

    if n_syns == 0:
        print("\n[!] No packets processed — performance report skipped.")
        return

    n_flood_syns = n_syns - enh_valid_count

    # Enhanced: valid handshakes only for latency/throughput
    enh_gen_valid = [_perf_gen_ms[i] for i in range(min(len(_perf_gen_ms), len(_perf_valid))) if _perf_valid[i]]
    enh_val_valid = [v for v, ok in zip(_perf_val_ms, _perf_valid) if ok]
    n_valid       = len(enh_gen_valid)

    # Enhanced CPU: sampled across ALL SYNs (flood + legit) — reflects real load
    avg_cpu_enh = statistics.mean(_perf_cpu) if _perf_cpu else 0.0

    if n_valid == 0:
        print("\n[!] No valid handshakes — run legitimate client alongside server.")
        return

    # --- Traditional baseline: replay same valid tuples, N_REPS repetitions ---
    # Pure crypto only: HMAC(ip:port:timestamp) → struct.unpack truncate
    # No nonce, no table, no send — isolates exactly the crypto cost difference
    N_REPS = max(100, n_valid * 20)   # at least 100 runs for stable stats
    valid_tuples = [_syn_tuples[i] for i in range(min(len(_syn_tuples), len(_perf_valid))) if _perf_valid[i]]

    print(f"[*] Running traditional baseline replay ({N_REPS} iterations) ...")

    trad_gen_ms      = []
    trad_val_ms      = []
    trad_cpu_samples = []
    _trad_proc  = psutil.Process(os.getpid())
    _trad_cores = psutil.cpu_count(logical=True) or 1

    for i in range(N_REPS):
        cip, cport, sip = valid_tuples[i % len(valid_tuples)]

        # --- generation: pure crypto only ---
        # Uses same key and message format as enhanced, minus the nonce
        # This isolates exactly the cost of adding os.urandom() + nonce to HMAC input
        _trad_proc.cpu_percent(interval=None)
        t0        = time.perf_counter()
        timestamp = int(time.time()) // 60
        msg       = f"{cip}:{cport}:{timestamp}".encode()
        digest    = hmac.new(SECRET_KEY, msg, hashlib.sha256).digest()
        cookie    = struct.unpack(">I", digest[:4])[0]
        trad_gen_ms.append((time.perf_counter() - t0) * 1000)
        trad_cpu_samples.append(_trad_proc.cpu_percent(interval=None) / _trad_cores)

        # --- validation: pure crypto only ---
        t0     = time.perf_counter()
        msg2   = f"{cip}:{cport}:{timestamp}".encode()
        digest2 = hmac.new(SECRET_KEY, msg2, hashlib.sha256).digest()
        _      = struct.unpack(">I", digest2[:4])[0] == cookie
        trad_val_ms.append((time.perf_counter() - t0) * 1000)

    avg_cpu_trad = statistics.mean(trad_cpu_samples) if trad_cpu_samples else 0.0

    # Also repeat enhanced crypto N_REPS times for fair stdev comparison
    enh_gen_rep = []
    enh_val_rep = []
    for i in range(N_REPS):
        cip, cport, sip = valid_tuples[i % len(valid_tuples)]
        t0     = time.perf_counter()
        nonce  = os.urandom(NONCE_SIZE) + random.getrandbits(64).to_bytes(8, "big")
        ts     = int(time.time()) // 60
        msg    = f"{cip}:{cport}:{ts}".encode() + nonce
        digest = hmac.new(SECRET_KEY, msg, hashlib.sha256).digest()
        _      = struct.unpack(">I", digest[:4])[0]
        enh_gen_rep.append((time.perf_counter() - t0) * 1000)

        t0     = time.perf_counter()
        msg2   = f"{cip}:{cport}:{ts}".encode() + nonce
        digest2 = hmac.new(SECRET_KEY, msg2, hashlib.sha256).digest()
        _      = struct.unpack(">I", digest2[:4])[0]
        enh_val_rep.append((time.perf_counter() - t0) * 1000)

    # Throughput: N_REPS / total pure crypto time
    trad_total = (sum(trad_gen_ms) + sum(trad_val_ms)) / 1000
    enh_total  = (sum(enh_gen_rep) + sum(enh_val_rep)) / 1000
    trad_tput  = N_REPS / trad_total if trad_total > 0 else 0
    enh_tput   = N_REPS / enh_total  if enh_total  > 0 else 0
    tput_diff  = ((trad_tput - enh_tput) / trad_tput * 100) if trad_tput > 0 else 0

    gen_overhead = ((statistics.mean(enh_gen_rep) - statistics.mean(trad_gen_ms)) /
                     statistics.mean(trad_gen_ms) * 100) if statistics.mean(trad_gen_ms) > 0 else 0

    W = 67
    def row(label, t_val, e_val):
        print(f"  {label:<36} {str(t_val):>12}  {str(e_val):>12}")
    def divider():
        print(f"  {'-'*62}")

    print("\n" + "=" * W)
    print("  SECTION 11 — SERVER PERFORMANCE REPORT")
    print("  Traditional (RFC 4987)  vs  Nonce-Enhanced")
    print("  (Pure crypto operations only — no packet I/O included)")
    print("=" * W)
    print(f"  {'Metric':<36} {'Traditional':>12}  {'Enhanced':>12}")
    divider()

    print(f"\n  Traffic summary:")
    print(f"    Total SYNs received      : {n_syns}")
    print(f"    Completed handshakes     : {enh_valid_count}")
    print(f"    Flood/incomplete SYNs    : {n_flood_syns}")
    print(f"    Baseline replay runs     : {N_REPS}")

    print("\n  11.1  Handshake Latency (pure crypto, {N_REPS} runs)".format(N_REPS=N_REPS))
    divider()
    row("  Avg generation time (ms)",
        f"{statistics.mean(trad_gen_ms):.4f}",
        f"{statistics.mean(enh_gen_rep):.4f}")
    row("  Min generation time (ms)",
        f"{min(trad_gen_ms):.4f}",
        f"{min(enh_gen_rep):.4f}")
    row("  Max generation time (ms)",
        f"{max(trad_gen_ms):.4f}",
        f"{max(enh_gen_rep):.4f}")
    row("  Stdev generation time (ms)",
        f"{statistics.stdev(trad_gen_ms):.4f}",
        f"{statistics.stdev(enh_gen_rep):.4f}")
    row("  Avg validation time (ms)",
        f"{statistics.mean(trad_val_ms):.4f}",
        f"{statistics.mean(enh_val_rep):.4f}")
    row("  Min validation time (ms)",
        f"{min(trad_val_ms):.4f}",
        f"{min(enh_val_rep):.4f}")
    row("  Max validation time (ms)",
        f"{max(trad_val_ms):.4f}",
        f"{max(enh_val_rep):.4f}")
    row("  Stdev validation time (ms)",
        f"{statistics.stdev(trad_val_ms):.4f}",
        f"{statistics.stdev(enh_val_rep):.4f}")
    print(f"\n  Generation overhead (enhanced vs traditional): {gen_overhead:+.2f}%")

    print("\n  11.2  CPU Overhead (pure crypto, normalized per-core)")
    divider()
    row("  Avg CPU % during processing",
        f"{avg_cpu_trad:.2f}%",
        f"{avg_cpu_enh:.2f}%")

    print("\n  11.3  Throughput (connections/sec, pure crypto)")
    divider()
    row("  Baseline runs measured",    f"{N_REPS}",           f"{N_REPS}")
    row("  Total crypto time (ms)",    f"{trad_total*1000:.4f}", f"{enh_total*1000:.4f}")
    row("  Connections/sec",           f"{trad_tput:.2f}",    f"{enh_tput:.2f}")
    print(f"\n  Throughput reduction (enhanced vs traditional): {tput_diff:.2f}%")

    print("\n" + "=" * W + "\n")

# ============================================================
# === FLOODER ===
# ============================================================

def run_flood():
    TARGET_IP = input("Enter the target IP: ").strip()
    THREADS = int(input("Enter number of threads: ") or 20)
    stop_flag = threading.Event()

    def send_syn():
        while not stop_flag.is_set():
            ip = IP(dst=TARGET_IP)
            tcp = TCP(
                sport=random.randint(1024, 65535),
                dport=SERVER_PORT,
                flags="S",
                seq=random.randint(0, 2**32 - 1)
            )
            send(ip / tcp, verbose=0)

    print(f"[*] Launching SYN flood to {TARGET_IP}:{SERVER_PORT}")
    for _ in range(THREADS):
        threading.Thread(target=send_syn, daemon=True).start()

    input("[*] Press ENTER to stop the SYN flood...")
    stop_flag.set()
    
# ============================================================
# === PING ===
# ============================================================
def ping_server():
    server_ip = input("Enter IP to ping: ").strip()
    result = run(["ping", "-c", "4", server_ip], stdout=PIPE, stderr=PIPE, text=True)
    print(result.stdout if result.returncode == 0 else result.stderr)
# ============================================================
# === SHOW IP ===
# ============================================================
def show_ip():
    result = run("ifconfig", shell=True, stdout=PIPE, text=True)
    for line in result.stdout.splitlines():
        if "inet " in line and "127.0.0.1" not in line:
            print(line.strip())
# ============================================================
# === NMAP ===
# ============================================================
def run_nmap_scan():
    target = input("Enter the target IP or hostname for Nmap scan: ").strip()
    ports = input("Enter port range or list (e.g., 20-1000 or 22,80,443): ").strip()
    if not target:
        print("[!] No target provided.")
        return
    command = ["nmap", "-sS", "-p", ports if ports else "1-1024", target]
    print(f"[*] Running Nmap command: {' '.join(command)}\n")
    try:
        result = run(command, stdout=PIPE, stderr=PIPE, text=True)
        print(result.stdout if result.returncode == 0 else result.stderr)
    except FileNotFoundError:
        print("[!] Nmap is not installed or not in PATH.")

# ============================================================
# === MENU ===
# ============================================================

print(r"""
 _   _  ___        ______   ___   _  
| \ | |/ _ \__  __/ ___\ \ / / \ | | 
|  \| | | | \ \/ /\___ \ V /|  \| | 
| |\  | |_| |>  <  ___) || | | |\  | 
|_| \_|\___//_/\_\|____/ |_| |_| \_|

SYN Cookie and DoS Simulator — designed for educational purposes only
""")

def menu():
    print("\n==== SYN Cookie Simulator Menu ====")
    print("1. Start SYN Cookie Server")
    print("2. Run Legitimate Client")
    print("3. Launch SYN Flood")
    print("4. Ping a Target IP")
    print("5. Show Host IP Address")
    print("6. Analyze PCAP for SYN-ACK Cookies")
    print("7. Perform Nmap Scan")
    print("0. Exit")
    return input("Select an option: ")

def main():
    while True:
        choice = menu()
        if choice == "1":
            start_server()
        elif choice == "2":
            run_client()
        elif choice == "3":
            run_flood()
        elif choice == "4":
            ping_server()
        elif choice == "5":
            show_ip()
        elif choice == "6":
            analyze_syn_cookies(
                input("PCAP file: ").strip(),
                input("Server IP: ").strip()
            )
        elif choice == "7":
            run_nmap_scan()
        elif choice == "0":
            print("Exiting.")
            break
        else:
            print("Invalid choice. Try again.")

main()
