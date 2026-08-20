# Port Scanner

A TCP port scanner written in Python. This project is part of my cybersecurity portfolio.

## ⚠️ Disclaimer

This tool is intended for educational purposes and authorized security testing only.
Only scan systems and networks you own or have explicit permission to test.
Unauthorized port scanning may be illegal in your jurisdiction.

## Features

- Sequential TCP connect scan
- Configurable port range
- Simple command-line interface
- Multithreaded scanning (configurable number of threads)
- Banner grabbing for service identification

## Requirements

- Python 3.x (no external dependencies)

## Usage

```bash
python port_scanner.py <target_ip> <start_port> <end_port> [threads]
```

### Example

```bash
python port_scanner.py 192.168.1.1 1 1000
```

## How it works

The scanner attempts a TCP connection to each port in the given range using
`socket.connect_ex()`. If the connection succeeds, the port is reported as open.

## Roadmap

- [x] Multithreading for faster scans
- [x] Banner grabbing (service/version detection)
- [ ] JSON/CSV export
- [ ] Command-line flags (argparse)

## License

MIT
