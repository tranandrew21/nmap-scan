# Nmap Network Scan Automation

A simple Python wrapper around **Nmap** to automate network scans, parse open ports/services, and export results to CSV.

## Features
- Run Nmap with configurable flags (default `-sV -T4`)
- Parse grepable output and extract open ports/services per host
- Export structured CSV for analysis or reporting

## Requirements
- Python 3.8+
- Nmap installed and available on PATH

## Quick Start
```bash
# Run a scan of the /24 subnet and save results to CSV
python nmap_scan.py --targets 192.168.1.0/24 --out report.csv --args "-sV -T4"
```

## Notes
- Ensure you have authorization to scan any target networks.
- For more advanced parsing or CVE mapping, consider pairing this with the 'Automated Vulnerability Scanner' project.
