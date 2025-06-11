import socket
import ipaddress
import threading
import time

TARGET_PORTS = [21, 22, 23, 25, 53, 135, 445, 3389, 3306, 4321]
SOCKET_TIMEOUT = 0.5
print_lock = threading.Lock()

def scan_port(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(SOCKET_TIMEOUT)
        try:
            sock.connect((ip, port))
            with print_lock:
                print(f"[+] {ip}:{port} is OPEN")
            return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

def scan_host(ip):
    with print_lock:
        print(f"[>] Scanning host: {ip}")
    open_ports = []
    for port in TARGET_PORTS:
        if scan_port(ip, port):
            open_ports.append(port)
    if open_ports:
        with print_lock:
            print(f"[!] Host {ip} has open ports: {open_ports}")
    else:
        with print_lock:
            print(f"[-] Host {ip} has no open target ports.")

def subnet_scan(network_cidr):
    try:
        network = ipaddress.ip_network(network_cidr, strict=False)
    except ValueError:
        print("[x] Invalid CIDR format.")
        return

    print(f"[i] Starting scan on subnet: {network}")
    threads = []

    for ip in network.hosts():
        t = threading.Thread(target=scan_host, args=(str(ip),))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    print(f"[✓] Finished scan on subnet: {network}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python netscanner.py <subnet>\nExample: python netscanner.py 192.168.1.0/24")
    else:
        subnet_scan(sys.argv[1])