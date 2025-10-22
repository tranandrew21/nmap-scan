#!/usr/bin/env python3
"""
Nmap Network Scan Automation - improved robustness

Usage:
    python nmap_scan.py --targets 192.168.1.0/24 --out report.csv --args "-sV -T4"
"""

import argparse, csv, subprocess, sys, shlex, re


def parse_args():
    """
    Parse command-line arguments for targets, output file, extra Nmap args, and debug mode.
    """
    p = argparse.ArgumentParser(description="Nmap Network Scan Automation (robust)")
    p.add_argument("--targets", required=True, help="Target host or subnet (e.g., 192.168.1.0/24)")
    p.add_argument("--out", help="CSV output file", default="nmap_report.csv")
    p.add_argument("--args", help="Extra nmap args (quoted)", default="-sV -T4")
    p.add_argument("--debug", action="store_true", help="Print raw nmap output (for debugging)")
    return p.parse_args()


def run_nmap(targets, extra_args):
    """
    Run an Nmap scan using subprocess and capture output.
    Uses '-oG -' for grepable output that can be parsed later.
    """
    # Safely split the Nmap arguments string into a list
    extra_list = shlex.split(extra_args)
    cmd = ["nmap"] + extra_list + ["-oG", "-", targets]

    try:
        # Run Nmap and capture stdout/stderr combined as text
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        return out
    except FileNotFoundError:
        # Handle missing Nmap installation
        sys.exit("ERROR: Nmap not found. Install Nmap and ensure it is on your PATH.")
    except subprocess.CalledProcessError as e:
        # Handle non-zero exit codes (failed scans, permission issues, etc.)
        print("DEBUG: Nmap returned non-zero exit code. Output follows:\n", e.output, file=sys.stderr)
        sys.exit(f"ERROR: Nmap failed (code {e.returncode}). See debug output above.")


def parse_grepable(output):
    """
    Parse '-oG' (grepable) Nmap output into structured data.

    Returns:
        List of dictionaries:
        [
            {"ip": "192.168.1.10", "open": [{"port": "22", "proto": "tcp", "service": "ssh"}, ...]},
            ...
        ]
    """
    results = []

    # Each host line starts with "Host: X.X.X.X"
    for line in output.splitlines():
        if not line.strip().startswith("Host:"):
            continue

        # Extract IP address from the line
        m = re.match(r"Host:\s+([\d\.]+)", line)
        if not m:
            continue
        ip = m.group(1)

        # Extract the 'Ports:' section, if present
        ports_part = ""
        if "Ports:" in line:
            parts = line.split("Ports:", 1)
            ports_part = parts[1].strip()

        # Example: "22/open/tcp//ssh///, 80/open/tcp//http///"
        open_ports = []
        for pe in ports_part.split(","):
            pe = pe.strip()
            if not pe:
                continue

            # Split port entries by "/"
            cols = pe.split("/")
            # Example -> ["22", "open", "tcp", "", "ssh", "", "", ""]
            if len(cols) >= 5 and cols[1] == "open":
                port = cols[0]
                proto = cols[2]
                service = cols[4] if cols[4] else ""
                open_ports.append({"port": port, "proto": proto, "service": service})

        # Append results for each host
        results.append({"ip": ip, "open": open_ports})

    return results


def write_csv(findings, outpath):
    """
    Write the scan results to a CSV file with columns:
    ip, port, proto, service
    """
    with open(outpath, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["ip", "port", "proto", "service"])

        for host in findings:
            # Handle hosts with no open ports
            if not host.get("open"):
                w.writerow([host["ip"], "", "", ""])
            else:
                for svc in host["open"]:
                    w.writerow([
                        host["ip"],
                        svc.get("port", ""),
                        svc.get("proto", ""),
                        svc.get("service", "")
                    ])


def main():
    """
    Entry point: parse arguments, run Nmap, parse results, and write CSV.
    """
    args = parse_args()
    print(f"[+] Running nmap on {args.targets} with args: {args.args}")

    # Run Nmap scan
    raw = run_nmap(args.targets, args.args)

    # Optionally print raw output for debugging
    if args.debug:
        print("---- RAW NMAP OUTPUT ----\n")
        print(raw)
        print("---- END RAW OUTPUT ----\n")

    # Parse and save results
    findings = parse_grepable(raw)
    write_csv(findings, args.out)
    print(f"[+] CSV report written to {args.out}")


if __name__ == "__main__":
    main()
