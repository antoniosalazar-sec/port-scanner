#!/usr/bin/env python3
"""
TCP Port Scanner - Version 3 (with banner grabbing)
Usage: python port_scanner.py <IP> <start_port> <end_port> [threads]
"""

import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed


def grab_banner(sock):
    """
    Tries to read a banner (service identification string) from an
    already-connected socket. Returns the banner as a string, or an
    empty string if nothing could be read.
    """
    try:
        # Some services send a banner immediately after connecting
        # (e.g. FTP, SMTP). We give it a short window to arrive.
        sock.settimeout(1)
        banner = sock.recv(1024)
        # Decode bytes to text; ignore characters that aren't valid UTF-8
        # instead of crashing on them.
        return banner.decode(errors="ignore").strip()
    except socket.error:
        # No banner arrived in time, or the service doesn't send one
        # unprompted (e.g. HTTP waits for a request first).
        return ""


def scan_port(target_ip, port):
    """
    Attempts to open a TCP connection to the given port and grab
    a service banner if available.
    Returns a tuple (port, is_open: bool, banner: str)
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)

    try:
        result = sock.connect_ex((target_ip, port))
        is_open = result == 0

        banner = ""
        if is_open:
            # Only try to grab a banner if the port actually accepted
            # the connection - no point reading from a closed socket.
            banner = grab_banner(sock)

        return (port, is_open, banner)
    except socket.error:
        return (port, False, "")
    finally:
        sock.close()


def main():
    if len(sys.argv) < 4:
        print(f"Usage: python {sys.argv[0]} <IP> <start_port> <end_port> [threads]")
        sys.exit(1)

    target_ip = sys.argv[1]
    start_port = int(sys.argv[2])
    end_port = int(sys.argv[3])
    max_workers = int(sys.argv[4]) if len(sys.argv) > 4 else 100

    print(f"Scanning {target_ip} from port {start_port} to {end_port}")
    print(f"Using {max_workers} threads\n")

    # Each entry is now a tuple (port, banner) instead of just a port number,
    # since we want to show the banner in the final summary too.
    open_ports = []
    ports_to_scan = range(start_port, end_port + 1)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(scan_port, target_ip, port)
            for port in ports_to_scan
        ]

        for future in as_completed(futures):
            port, is_open, banner = future.result()
            if is_open:
                if banner:
                    print(f"[+] Port {port} OPEN - {banner}")
                else:
                    print(f"[+] Port {port} OPEN")
                open_ports.append((port, banner))

    # Sort by port number; each item is a (port, banner) tuple, so we
    # tell sort() to compare using only the first element of each tuple.
    open_ports.sort(key=lambda item: item[0])

    print(f"\nScan complete. {len(open_ports)} open port(s) found:")
    for port, banner in open_ports:
        if banner:
            print(f"  {port}: {banner}")
        else:
            print(f"  {port}: (no banner)")


if __name__ == "__main__":
    main()
