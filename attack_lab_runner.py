import json
import socket
import sys
import time
import urllib.request


DASHBOARD = "http://localhost:5001"


def can_get(url, timeout=2):
    try:
        urllib.request.urlopen(url, timeout=timeout).read()
        return True
    except Exception:
        return False


def connect_once(port, timeout=2):
    sock = socket.socket()
    sock.settimeout(timeout)
    try:
        sock.connect(("127.0.0.1", port))
    except Exception:
        pass
    finally:
        sock.close()


def print_stats():
    try:
        data = urllib.request.urlopen(f"{DASHBOARD}/api/stats", timeout=3).read()
        stats = json.loads(data)
        threats = [c for c in stats.get("connections", []) if c.get("is_threat")]
        print("Detected threats:", len(threats))
        print(threats[0] if threats else "NONE")
    except Exception as exc:
        print("Detected threats: unavailable")
        print(f"Dashboard stats error: {exc}")


def system_check():
    print("============================================================")
    print("  SYSTEM CHECK")
    print("============================================================")
    print()
    status = "OK" if can_get(f"{DASHBOARD}/api/status") else "FAIL (is network.py running?)"
    print("Dashboard API:", status)

    ports = [
        (2222, "SSH"),
        (2121, "FTP"),
        (2323, "Telnet"),
        (13389, "RDP"),
        (5901, "VNC"),
        (7001, "ScanTrap"),
        (7005, "ScanTrap"),
        (7010, "ScanTrap"),
    ]
    fail = 0
    for port, name in ports:
        sock = socket.socket()
        sock.settimeout(1)
        result = sock.connect_ex(("127.0.0.1", port))
        sock.close()
        if result == 0:
            print(f"  [OK]   {port}  ({name})")
        else:
            print(f"  [FAIL] {port}  ({name})")
            fail += 1

    print()
    if fail == 0:
        print("All OK - ready to test.")
    else:
        print(f"WARNING: {fail} port(s) not reachable. Is app.py running?")


def brute(name, port, expected):
    print(f"  Running: {name.upper()} Brute Force (25 attempts, 0.35s delay) -> port {port}")
    print(f"  Watch: {DASHBOARD}")
    print()
    for index in range(25):
        connect_once(port, timeout=2)
        time.sleep(0.35)
        if (index + 1) % 5 == 0:
            print(f"  {index + 1}/25 attempts")
    print(f"Done. Check dashboard for {expected}.")
    print()
    print_stats()


def ddos(name, port):
    print(f"  Running: {name.upper()} DDoS Flood (200 connections, no delay) -> port {port}")
    print(f"  Watch: {DASHBOARD}")
    print()
    start = time.time()
    for index in range(200):
        connect_once(port, timeout=0.05)
        if (index + 1) % 50 == 0:
            elapsed = max(time.time() - start, 0.001)
            print(f"  {index + 1}/200  ({(index + 1) / elapsed:.0f} conn/s)")
    print(f"Done in {time.time() - start:.1f}s. Check dashboard for DDoS.")
    print()
    print_stats()


def scan():
    print("  Running: Port Scan (trap ports 7001-7010)")
    print(f"  Watch: {DASHBOARD}")
    print()
    for port in range(7001, 7011):
        sock = socket.socket()
        sock.settimeout(0.3)
        sock.connect_ex(("127.0.0.1", port))
        sock.close()
        print(f"  TRIED {port}")
        time.sleep(0.05)
    print("Scan done. Check dashboard for PortScan.")
    print()
    print_stats()


def main(argv):
    if len(argv) < 2:
        print("Usage: attack_lab_runner.py system|brute|ddos|scan")
        return 2

    command = argv[1].lower()
    if command == "system":
        system_check()
        return 0
    if command == "brute" and len(argv) == 5:
        brute(argv[2], int(argv[3]), argv[4])
        return 0
    if command == "ddos" and len(argv) == 4:
        ddos(argv[2], int(argv[3]))
        return 0
    if command == "scan":
        scan()
        return 0

    print("Invalid attack_lab_runner.py arguments:", " ".join(argv[1:]))
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
