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
- Argparse-based CLI with input validation
- Graceful cancellation with Ctrl+C

## Requirements

- Python 3.x (no external dependencies)

## Usage

```bash
python port_scanner.py <target> [-p PORTS] [-t THREADS] [--timeout SECONDS]
```

### Example

```bash
python port_scanner.py scanme.nmap.org -p 1-1000 -t 50 --timeout 2
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `target` | IP address or hostname to scan | required |
| `-p`, `--ports` | Port range, e.g. `1-1000` or `80` | `1-1024` |
| `-t`, `--threads` | Number of concurrent threads | `100` |
| `--timeout` | Connection timeout in seconds | `1.0` |

## How it works

The scanner resolves the target hostname to an IP address once, then attempts
a TCP connection to each port in the given range using `socket.connect_ex()`
across a pool of worker threads. If a connection succeeds, it also tries to
read a service banner from the open port before reporting it.

## Notes

High thread counts against a single target may trigger rate limiting on the
server side, causing open ports to appear closed. If you get inconsistent
results, try lowering `-t` and increasing `--timeout`.

## Roadmap

- [x] Multithreading for faster scans
- [x] Banner grabbing (service/version detection)
- [x] Command-line flags (argparse)
- [ ] JSON/CSV export
- [ ] Unit tests

## License

MIT
