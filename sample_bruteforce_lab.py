"""
Sample "brute force" traffic generator for LOCAL / LAB testing only.

Generates many short TCP connection attempts to one port (default 22) so
network.py's PacketAnomalyDetector can flag Brute Force (same src, dst in
{21,22,23,3389,5900}, packet count >= 25 in ~60s).

LEGAL: Only run against systems you own or have explicit permission to test.

Usage (PowerShell / cmd):
  python sample_bruteforce_lab.py --host 192.168.1.50 --port 22 --count 35

Tips:
  - Use a real lab VM/device that listens on that port, or even a closed port
    on your LAN (you still get outbound SYNs visible to capture).
  - If you hit DoS/DDoS first, lower --count or increase --delay.
  - Run Network Flow Monitor as Administrator with REAL capture started.
"""

from __future__ import annotations

import argparse
import socket
import sys
import time


def tcp_knock(host: str, port: int, timeout: float = 0.4) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
    except OSError:
        pass
    finally:
        try:
            s.close()
        except OSError:
            pass


def main() -> int:
    p = argparse.ArgumentParser(description="Lab-only TCP connection burst (brute-force style).")
    p.add_argument("--host", default="127.0.0.1", help="Target IP (your lab machine)")
    p.add_argument("--port", type=int, default=22, help="Target port (22 SSH, 3389 RDP, …)")
    p.add_argument("--count", type=int, default=35, help="Connection attempts (>= 25 for detector)")
    p.add_argument("--delay", type=float, default=0.05, help="Seconds between attempts")
    p.add_argument("-y", action="store_true", help="Skip confirmation prompt")
    args = p.parse_args()

    if args.port not in (21, 22, 23, 3389, 5900):
        print(
            "Note: monitor's 'Brute Force' rule uses ports "
            "21, 22, 23, 3389, 5900. Using another port may not trigger that label.",
            file=sys.stderr,
        )

    print("=" * 60)
    print("  LAB ONLY — authorized testing against your own equipment")
    print("=" * 60)
    print(f"  Target : {args.host}:{args.port}")
    print(f"  Attempts: {args.count}, delay: {args.delay}s")
    print()

    if not args.y:
        s = input("Type YES to run: ").strip()
        if s.upper() != "YES":
            print("Aborted.")
            return 1

    for i in range(args.count):
        tcp_knock(args.host, args.port)
        if args.delay > 0:
            time.sleep(args.delay)
        if (i + 1) % 10 == 0 or i == 0:
            print(f"  ... {i + 1}/{args.count} attempts")

    print("\nDone. Check Network Flow Monitor ML / prediction feed for 'Brute Force'.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
