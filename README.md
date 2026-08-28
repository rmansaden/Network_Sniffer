# Network Sniffer

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9%2B-3776AB?logo=python&logoColor=white" alt="Python 3.9+">
  <img src="https://img.shields.io/badge/Scapy-2.5%2B-1F6FEB?logo=python&logoColor=white" alt="Scapy 2.5+">
  <img src="https://img.shields.io/badge/Platform-Linux-FCC624?logo=linux&logoColor=black" alt="Linux">
  <img src="https://img.shields.io/badge/License-Educational-555555" alt="Educational project">
</p>

A lightweight network sniffer written in Python and powered by [Scapy](https://scapy.net/). The project provides a basic packet viewer, an advanced analyzer with protocol statistics, and JSON/CSV export capabilities.

> **Responsible use:** Capture traffic only on networks and devices you own or are explicitly authorized to monitor. Packet payloads may contain sensitive information.

## Features

- Capture and display IPv4 TCP, UDP, and ICMP traffic
- Show source and destination addresses, ports, TTL, TCP flags, and payloads
- Apply BPF filters and select a network interface
- Capture a fixed number of packets or run for a defined timeout
- Track TCP, UDP, ICMP, ARP, and other packet counts
- Export captured packet metadata to JSON or CSV
- Run automated tests without root privileges or Internet traffic

## Requirements

- Python 3.9 or newer
- Linux recommended for packet capture
- `pip` and `python3-venv`
- Administrator privileges for live capture on most systems

## Installation

```bash
git clone <REPOSITORY_URL>
cd network_sniffer
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

On Debian or Ubuntu, install the system prerequisites when needed:

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv
```

## Usage

### Basic capture

```bash
# Continuous capture; stop with Ctrl+C
sudo .venv/bin/python sniffer.py

# Capture 20 packets on eth0
sudo .venv/bin/python sniffer.py --count 20 --interface eth0

# Capture HTTPS traffic for up to 10 seconds
sudo .venv/bin/python sniffer.py --timeout 10 --filter "tcp port 443"
```

### Advanced analysis

```bash
# Capture 20 packets and print protocol statistics
sudo .venv/bin/python sniffer_advanced.py --count 20

# Capture DNS traffic for up to 30 seconds
sudo .venv/bin/python sniffer_advanced.py --timeout 30 --filter "udp port 53"
```

Both capture modes support `--count`, `--timeout`, `--filter`, and `--interface`. A count of `0` means continuous capture.

### JSON and CSV export

```bash
sudo .venv/bin/python sniffer_export.py --count 50 --output capture.json
sudo .venv/bin/python sniffer_export.py --timeout 20 --filter "tcp" --output capture.csv
```

Output files are written to the current directory. Do not publish captures containing private IP addresses, credentials, or payload data.

## Testing

The test script checks Python syntax, module imports, CLI help output, packet analysis, and JSON/CSV export using synthetic packets. It does not start a live capture and does not require `sudo`:

```bash
source .venv/bin/activate
./test_sniffer.sh
```

For a syntax-only check:

```bash
python -m py_compile sniffer.py sniffer_advanced.py sniffer_export.py
```

## Project structure

```text
network_sniffer/
├── .gitignore             # Local environments, caches, and captures
├── requirements.txt       # Python dependencies
├── sniffer.py             # Basic capture and display
├── sniffer_advanced.py    # Advanced analysis and statistics
├── sniffer_export.py      # JSON/CSV capture export
├── test_sniffer.sh        # Automated smoke tests
└── README.md              # Project documentation
```

## Troubleshooting

- **Permission denied:** Run live capture with `sudo`, or configure Python network capabilities according to your system security policy.
- **Invalid filter:** Use libpcap BPF syntax, such as `tcp`, `udp port 53`, or `host 192.168.1.1`.
- **No packets captured:** Check the interface name with `ip link` and generate authorized traffic on that interface.
- **Scapy is missing:** Activate the virtual environment and run `python -m pip install -r requirements.txt`.


## License

Educational project created as part of the Code Alpha 2026 internship.
