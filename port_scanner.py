#!/usr/bin/env python3
"""
TCP Port Scanner - Version 4 (with argparse CLI)
Usage: python port_scanner.py <target> -p <start-end> [-t threads]
"""

import argparse
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
        sock.settimeout(1)
        banner = sock.recv(1024)
        return banner.decode(errors="ignore").strip()
    except socket.error:
        return ""


def scan_port(target_ip, port, timeout):
    """
    Attempts to open a TCP connection to the given port and grab
    a service banner if available.
    Returns a tuple (port, is_open: bool, banner: str)
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        result = sock.connect_ex((target_ip, port))
        is_open = result == 0

        banner = ""
        if is_open:
            banner = grab_banner(sock)

        return (port, is_open, banner)
    except socket.error:
        return (port, False, "")
    finally:
        sock.close()


def parse_port_range(port_range_str):
    """
    Parses a string like "1-1000" or "80" into a (start, end) tuple.
    Raises argparse.ArgumentTypeError if the format is invalid, so
    argparse can show a clean error message instead of a raw traceback.
    """
    if "-" in port_range_str:
        # A range was given, e.g. "1-1000"
        parts = port_range_str.split("-")
        if len(parts) != 2:
            raise argparse.ArgumentTypeError(
                f"Invalid port range: '{port_range_str}'. Use format START-END."
            )
        start, end = parts
    else:
        # A single port was given, e.g. "80" -> scan just that one port
        start = end = port_range_str

    try:
        start_port = int(start)
        end_port = int(end)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"Ports must be numbers, got: '{port_range_str}'"
        )

    if not (0 <= start_port <= 65535 and 0 <= end_port <= 65535):
        raise argparse.ArgumentTypeError("Ports must be between 0 and 65535.")

    if start_port > end_port:
        raise argparse.ArgumentTypeError(
            f"Start port ({start_port}) cannot be greater than end port ({end_port})."
        )

    return (start_port, end_port)


def build_arg_parser():
    """
    Builds and returns the argparse parser that defines all the
    command-line flags this script accepts.
    """
    parser = argparse.ArgumentParser(
        description="A simple multithreaded TCP port scanner with banner grabbing."
    )

    # Positional argument: required, no flag needed, just the value itself
    parser.add_argument(
        "target",
        help="Target IP address or hostname to scan (e.g. 192.168.1.1)"
    )

    # Optional flags: identified by -p/--ports, -t/--threads, etc.
    parser.add_argument(
        "-p", "--ports",
        type=parse_port_range,
        default=(1, 1024),
        help="Port range to scan, e.g. 1-1000 or 80 (default: 1-1024)"
    )

    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=100,
        help="Number of concurrent threads to use (default: 100)"
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Connection timeout in seconds (default: 1.0)"
    )

    return parser


def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    start_port, end_port = args.ports

    # Resolve the hostname to an IP address ONCE, before launching any
    # threads. If we let each thread resolve the hostname independently
    # inside scan_port(), dozens of near-simultaneous DNS lookups for the
    # same name can slow down or silently fail for some threads - making
    # ports that are actually open look closed just because that thread's
    # DNS lookup didn't finish in time.
    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"Error: could not resolve hostname '{args.target}'")
        sys.exit(1)

    print(f"Scanning {args.target} ({target_ip}) from port {start_port} to {end_port}")
    print(f"Using {args.threads} threads, {args.timeout}s timeout\n")

    open_ports = []
    ports_to_scan = range(start_port, end_port + 1)

    try:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = [
                executor.submit(scan_port, target_ip, port, args.timeout)
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
    except KeyboardInterrupt:
        # Ctrl+C was pressed. cancel_futures=True (Python 3.9+) drops any
        # queued-but-not-yet-started tasks instead of waiting for them,
        # so we don't hang waiting for hundreds of pending scans to finish.
        print("\nScan interrupted by user. Shutting down...")
        executor.shutdown(wait=False, cancel_futures=True)
        sys.exit(1)

    open_ports.sort(key=lambda item: item[0])

    print(f"\nScan complete. {len(open_ports)} open port(s) found:")
    for port, banner in open_ports:
        if banner:
            print(f"  {port}: {banner}")
        else:
            print(f"  {port}: (no banner)")


if __name__ == "__main__":
    main()
