#!/usr/bin/env python3
"""
TCP Port Scanner - Version 1 (basic, no threading)
Usage: python port_scanner.py <IP> <start_port> <end_port>
"""

import socket
import sys


def scan_port(target_ip, port):
    """
    Attempts to open a TCP connection to the given port.
    Returns True if the port is open, False otherwise.
    """
    # Create a socket object: AF_INET = IPv4, SOCK_STREAM = TCP
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Timeout: how long we wait before considering the port closed/filtered.
    # Without this, a firewall-filtered port could hang the script indefinitely.
    sock.settimeout(1)

    try:
        # connect_ex() attempts to connect and returns an error code
        # instead of raising an exception (unlike connect()).
        # A return value of 0 means the connection succeeded -> port open.
        result = sock.connect_ex((target_ip, port))
        return result == 0
    except socket.error:
        # Any network error (unreachable host, etc.) is treated
        # as "port not available".
        return False
    finally:
        # Always close the socket, whether it succeeded or failed.
        sock.close()


def main():
    if len(sys.argv) != 4:
        print(f"Usage: python {sys.argv[0]} <IP> <start_port> <end_port>")
        sys.exit(1)

    target_ip = sys.argv[1]
    start_port = int(sys.argv[2])
    end_port = int(sys.argv[3])

    print(f"Scanning {target_ip} from port {start_port} to {end_port}\n")

    open_ports = []

    # range(start, end + 1) because range() doesn't include the last number
    for port in range(start_port, end_port + 1):
        if scan_port(target_ip, port):
            print(f"[+] Port {port} OPEN")
            open_ports.append(port)

    print(f"\nScan complete. Open ports: {open_ports}")


# Ensures main() only runs if this file is executed directly,
# not when imported as a module from another script.
if __name__ == "__main__":
    main()
