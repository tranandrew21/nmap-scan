#!/usr/bin/env python3
"""
Nmap Network Scan Automation
----------------------------
Lightweight Python wrapper to run Nmap scans on targets, parse results, and export to CSV.

Designed for learning and small lab use. Requires nmap installed on the host.

Usage example:
python nmap_scan.py --targets 192.168.1.0/24 --out report.csv --args "-sV -T4"
"""

import argparse      # For parsing command-line arguments
import csv           # For writing scan results to a CSV file
import subprocess    # For running the Nmap command in the system shell
import sys           # For exiting with custom error messages

# ----------------------------
# Argument Parsing
# ----------------------------
def parse_args():
    """
    Defines and parses command-line arguments for the script.
    Example:
      python nmap_scan.py --targets 192.168.1.0/24 --out results.csv --args "-sV -T4"
    """
    p = argparse.ArgumentParser(description="Nmap Network Scan Automation")
    p.add_argument("--targets", required=True, help="Target host or subnet (e.g., 192.168.1.0/24)")
    p.add_argument("--out", help="CSV output file", default="nmap_report.csv")
    p.add_argument("--args", help="Extra nmap args (quoted)", default="-sV -T4")
    return p.parse_args()


# ----------------------------
# Run Nmap Command
# ----------------------------
def run_nmap(targets, extra_args):
    """
    Executes the Nmap command using subprocess and captures the output in 'grepable' format (-oG).
    Returns the raw text output from Nmap.
    """
    cmd = ["nmap"] + extra_args.split() + ["-oG", "-", targets]

    try:
        # Runs the command and captures the standard output (text mode)
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        return out

    except FileNotFoundError:
        # Triggered if Nmap is not installed or not found in system PATH
        sys.exit("Nmap not found: install Nmap and ensure it is on your PATH.")

    except subprocess.CalledProcessError as e:
        # Triggered if Nmap fails to execute properly (non-zero return code)
        sys.exit(f"Nmap failed (code {e.returncode}):\n{e.output}")


# ----------------------------
# Parse Nmap Output (-oG Format)
# ----------------------------
def parse_grepable(output):
    """
    Parses Nmap's '-oG' (grepable) output.
    Extracts each host and its open ports, storing them as structured data.

    Example Nmap line:
      Host: 192.168.1.1 ()  Ports: 22/open/tcp//ssh///, 80/open/tcp//http///
    """
    results = []

    for line in output.splitlines():
        if not line.startswith("Host: "):
            # Skip unrelated lines
            continue

        parts = line.split("\t")  # Each field in the line is tab-separated
        host_ip = parts[0].split()[1]  # Extract IP after 'Host:'
        
        # Extract the section starting with "Ports:" if it exists
        ports_part = next((p for p in parts if p.startswith("Ports: ")), "Ports: ").replace("Ports: ", "")

        open_ports = []
        for pe in ports_part.split(","):
            pe = pe.strip()
            if not pe:
                continue

            # Format: port/status/proto//service///
            cols = pe.split("/")

            # Example: ['22', 'open', 'tcp', '', 'ssh', '', '', '']
            if len(cols) >= 5 and cols[1] == "open":
                port = cols[0]
                proto = cols[2]
                service = cols[4]
                open_ports.append({"port": port, "proto": proto, "service": service})

        results.append({"ip": host_ip, "open": open_ports})

    return results


# ----------------------------
# Write Results to CSV
# ----------------------------
def write_csv(findings, outpath):
    """
    Writes the parsed Nmap results to a CSV file.
    Each row represents one open port on a given host.
    """
    with open(outpath, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        # CSV Header
        w.writerow(["ip", "port", "proto", "service"])

        # Flatten data into rows
        for host in findings:
            for svc in host["open"]:
                w.writerow([host["ip"], svc["port"], svc["proto"], svc["service"]])


# ----------------------------
# Main Entry Point
# ----------------------------
def main():
    """
    Main program logic:
      1. Parse CLI arguments
      2. Run Nmap
      3. Parse the output
      4. Save the results to CSV
    """
    args = parse_args()

    print(f"[+] Running nmap on {args.targets} with args: {args.args}")
    output = run_nmap(args.targets, args.args)

    print("[+] Parsing results...")
    findings = parse_grepable(output)

    print(f"[+] Writing CSV report to {args.out}")
    write_csv(findings, args.out)

    print(f"[✓] Scan complete! CSV report saved as: {args.out}")


# Only execute main() when this file is run directly, not imported
if __name__ == "__main__":
    main()
