#!/usr/bin/env python3
"""
TCP Port Scanner - Version 2 (with threading)
Usage: python port_scanner.py <IP> <start_port> <end_port> [threads]
"""

import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed


def scan_port(target_ip, port):
    """
    Attempts to open a TCP connection to the given port.
    Returns a tuple (port, is_open: bool)
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)

    try:
        result = sock.connect_ex((target_ip, port))
        return (port, result == 0)
    except socket.error:
        return (port, False)
    finally:
        sock.close()


def main():
    if len(sys.argv) < 4:
        print(f"Usage: python {sys.argv[0]} <IP> <start_port> <end_port> [threads]")
        sys.exit(1)

    target_ip = sys.argv[1]
    start_port = int(sys.argv[2])
    end_port = int(sys.argv[3])

    # Number of threads: default to 100 if not specified by the user
    max_workers = int(sys.argv[4]) if len(sys.argv) > 4 else 100

    print(f"Scanning {target_ip} from port {start_port} to {end_port}")
    print(f"Using {max_workers} threads\n")

    open_ports = []
    ports_to_scan = range(start_port, end_port + 1)

    # Create a pool of reusable threads. The 'with' block ensures the pool
    # is shut down properly when we're done, even if something fails inside.
    with ThreadPoolExecutor(max_workers=max_workers) as executor:

        # executor.submit(function, arg1, arg2) schedules scan_port(target_ip, port)
        # to run on a thread from the pool and immediately returns a "future"
        # object (a placeholder for a result that will arrive later).
        # We do this for EVERY port in the range without waiting for
        # one to finish before scheduling the next.
        futures = [
            executor.submit(scan_port, target_ip, port)
            for port in ports_to_scan
        ]

        # as_completed(futures) yields each future AS IT FINISHES
        # (not in the order we submitted them). That's why ports may
        # print out of order.
        for future in as_completed(futures):
            # .result() returns whatever scan_port() returned for that future:
            # the (port, is_open) tuple
            port, is_open = future.result()
            if is_open:
                print(f"[+] Port {port} OPEN")
                open_ports.append(port)

    # Sort the list at the end since results arrived out of order
    open_ports.sort()
    print(f"\nScan complete. Open ports: {open_ports}")


if __name__ == "__main__":
    main()
