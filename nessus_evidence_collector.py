#!/usr/bin/env python3
"""
Nessus Evidence Collector
Parses a .nessus file and collects evidence for each finding via active verification.

Usage:
    python3 nessus_evidence_collector.py -f scan.nessus -o evidence_output/
    python3 nessus_evidence_collector.py -f scan.nessus -o evidence_output/ --min-severity medium
    python3 nessus_evidence_collector.py -f scan.nessus -o evidence_output/ --passive  # No active checks

Author: Dan / URM Consulting
"""

import argparse
import datetime
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional
import urllib.request
import urllib.error

# ─────────────────────────────────────────────
# COLOUR OUTPUT
# ─────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

def banner():
    print(f"""{C.CYAN}{C.BOLD}
╔═══════════════════════════════════════════════╗
║       Nessus Evidence Collector v1.0          ║
║       URM Consulting — Pentest Tooling        ║
╚═══════════════════════════════════════════════╝{C.RESET}
""")

def log(msg, level="INFO"):
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    colours = {"INFO": C.BLUE, "OK": C.GREEN, "WARN": C.YELLOW, "ERR": C.RED}
    col = colours.get(level, C.RESET)
    print(f"{C.BOLD}[{ts}]{C.RESET} {col}[{level}]{C.RESET} {msg}")

# ─────────────────────────────────────────────
# DATA STRUCTURES
# ─────────────────────────────────────────────
SEVERITY_MAP = {0: "informational", 1: "low", 2: "medium", 3: "high", 4: "critical"}
SEVERITY_NUM = {v: k for k, v in SEVERITY_MAP.items()}

@dataclass
class Finding:
    plugin_id: str
    plugin_name: str
    severity: str
    severity_num: int
    host: str
    port: str
    protocol: str
    service: str
    description: str
    solution: str
    synopsis: str
    plugin_output: str
    cve: list = field(default_factory=list)
    cvss_base: str = ""
    cvss3_base: str = ""
    see_also: str = ""
    evidence: dict = field(default_factory=dict)

# ─────────────────────────────────────────────
# NESSUS PARSER
# ─────────────────────────────────────────────
def parse_nessus(filepath: str) -> list[Finding]:
    log(f"Parsing {filepath} ...")
    tree = ET.parse(filepath)
    root = tree.getroot()
    findings = []

    for report_host in root.iter("ReportHost"):
        host = report_host.get("name", "unknown")

        # Pull host properties
        host_props = {}
        for tag in report_host.findall("HostProperties/tag"):
            host_props[tag.get("name")] = tag.text or ""

        ip = host_props.get("host-ip", host)

        for item in report_host.findall("ReportItem"):
            sev_num = int(item.get("severity", 0))
            plugin_id = item.get("pluginID", "")
            port = item.get("port", "0")
            protocol = item.get("protocol", "tcp")
            service = item.get("svc_name", "")
            plugin_name = item.get("pluginName", "unknown")

            def get_text(tag, default=""):
                el = item.find(tag)
                return (el.text or default).strip() if el is not None else default

            cves = [el.text for el in item.findall("cve") if el.text]

            finding = Finding(
                plugin_id=plugin_id,
                plugin_name=plugin_name,
                severity=SEVERITY_MAP.get(sev_num, "informational"),
                severity_num=sev_num,
                host=ip,
                port=port,
                protocol=protocol,
                service=service,
                description=get_text("description"),
                solution=get_text("solution"),
                synopsis=get_text("synopsis"),
                plugin_output=get_text("plugin_output"),
                cve=cves,
                cvss_base=get_text("cvss_base_score"),
                cvss3_base=get_text("cvss3_base_score"),
                see_also=get_text("see_also"),
            )
            findings.append(finding)

    log(f"Parsed {len(findings)} findings across {len(set(f.host for f in findings))} hosts.", "OK")
    return findings

# ─────────────────────────────────────────────
# EVIDENCE COLLECTORS
# ─────────────────────────────────────────────
def run_cmd(cmd: list[str], timeout=15) -> tuple[str, str, int]:
    """Run a subprocess and return (stdout, stderr, returncode)."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", -1
    except FileNotFoundError:
        return "", f"Command not found: {cmd[0]}", -2
    except Exception as e:
        return "", str(e), -3

def tool_available(name: str) -> bool:
    out, _, rc = run_cmd(["which", name])
    return rc == 0

def collect_port_banner(host: str, port: int, proto: str, timeout=5) -> str:
    """Grab a raw banner from a TCP/UDP port."""
    evidence = ""
    if proto.lower() != "tcp":
        return "(UDP — banner grab skipped)"
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        try:
            # Some services send a banner immediately
            banner = sock.recv(1024).decode(errors="replace").strip()
            if banner:
                evidence = f"[Banner]\n{banner}"
        except Exception:
            pass
        # Try an HTTP GET if no banner
        if not evidence:
            try:
                sock.sendall(b"GET / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                resp = sock.recv(2048).decode(errors="replace")
                evidence = f"[HTTP Response (first 2048 bytes)]\n{resp}"
            except Exception:
                pass
        sock.close()
    except Exception as e:
        evidence = f"[Connection failed: {e}]"
    return evidence or "(no banner retrieved)"

def collect_ssl_cert(host: str, port: int) -> str:
    """Dump TLS certificate details."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(socket.create_connection((host, port), timeout=5),
                             server_hostname=host) as ssock:
            cert = ssock.getpeercert(binary_form=False)
            cipher = ssock.cipher()
            proto = ssock.version()
            lines = [f"Protocol : {proto}", f"Cipher   : {cipher}"]
            if cert:
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer  = dict(x[0] for x in cert.get("issuer",  []))
                lines.append(f"Subject  : {subject}")
                lines.append(f"Issuer   : {issuer}")
                lines.append(f"NotBefore: {cert.get('notBefore','')}")
                lines.append(f"NotAfter : {cert.get('notAfter','')}")
                sans = cert.get("subjectAltName", [])
                if sans:
                    lines.append(f"SANs     : {[v for _, v in sans]}")
            return "\n".join(lines)
    except Exception as e:
        return f"[SSL grab failed: {e}]"

def collect_nmap(host: str, port: str, proto: str) -> str:
    """Run a targeted nmap service/version scan on the specific port."""
    if not tool_available("nmap"):
        return "[nmap not found — install with: sudo apt install nmap]"
    proto_flag = "-sU" if proto.lower() == "udp" else "-sT"
    cmd = ["nmap", proto_flag, "-sV", "-p", port, "--open", "-Pn", host]
    out, err, rc = run_cmd(cmd, timeout=60)
    return out if out else f"[nmap error: {err}]"

def collect_curl(host: str, port: str, proto: str) -> str:
    """HTTP/HTTPS header grab via curl."""
    if not tool_available("curl"):
        return "[curl not found]"
    scheme = "https" if port in ("443", "8443") else "http"
    url = f"{scheme}://{host}:{port}/"
    cmd = ["curl", "-sk", "-I", "--max-time", "10", url]
    out, err, rc = run_cmd(cmd, timeout=15)
    return out if out else f"[curl error: {err}]"

def collect_testssl(host: str, port: str) -> str:
    """Run testssl.sh if available for TLS assessment."""
    if not tool_available("testssl.sh") and not tool_available("testssl"):
        return "[testssl.sh not found — install from https://testssl.sh]"
    binary = "testssl.sh" if tool_available("testssl.sh") else "testssl"
    cmd = [binary, "--quiet", "--color", "0", f"{host}:{port}"]
    out, err, rc = run_cmd(cmd, timeout=120)
    return out[:5000] if out else f"[testssl error: {err}]"  # cap at 5k chars

def collect_smbclient(host: str) -> str:
    """Enumerate SMB shares anonymously."""
    if not tool_available("smbclient"):
        return "[smbclient not found]"
    cmd = ["smbclient", "-L", host, "-N", "--no-pass"]
    out, err, rc = run_cmd(cmd, timeout=15)
    return out or err

def collect_rdp_check(host: str, port: str) -> str:
    """Basic RDP connectivity check via nc."""
    if not tool_available("nc"):
        return "[nc not found]"
    cmd = ["nc", "-zv", "-w", "5", host, port]
    out, err, rc = run_cmd(cmd, timeout=10)
    return (out + err).strip()

# ─────────────────────────────────────────────
# PLUGIN-TO-EVIDENCE ROUTER
# ─────────────────────────────────────────────

# Known plugin IDs and their evidence strategies
PLUGIN_STRATEGIES = {
    # SSL/TLS
    "10863": ["ssl_cert", "testssl"],   # SSL certificate info
    "56984": ["ssl_cert", "testssl"],   # SSL/TLS deprecated protocol
    "20007": ["ssl_cert", "testssl"],   # SSL version 2 and 3
    "42873": ["ssl_cert"],              # SSL medium strength ciphers
    "65821": ["ssl_cert"],              # SSL RC4 cipher
    "83875": ["ssl_cert", "testssl"],   # POODLE
    "104743": ["ssl_cert", "testssl"],  # TLS 1.0/1.1 deprecated
    # HTTP
    "10107": ["curl", "banner"],        # HTTP server type and version
    "11213": ["curl"],                  # HTTP TRACE
    "44135": ["curl"],                  # X-Frame-Options missing
    "10336": ["curl"],                  # HTTP directory listing
    "11032": ["curl"],                  # Unsupported web server
    # SMB / Windows
    "57608": ["smb"],                   # SMB signing not required
    "96982": ["smb"],                   # SMB signing disabled
    "10736": ["smb"],                   # DCE Services
    "11011": ["smb"],                   # Microsoft Windows SMB shares
    # RDP
    "18405": ["rdp"],                   # RDP
    "51192": ["ssl_cert"],              # Self-signed cert (often RDP)
    # Generic
    "default": ["banner", "nmap"],
}

def get_strategies(plugin_id: str, service: str, port: str) -> list[str]:
    strategies = PLUGIN_STRATEGIES.get(plugin_id)
    if strategies:
        return strategies

    # Heuristic fallbacks by service/port
    if service in ("https", "ssl") or port in ("443", "8443", "8080"):
        return ["ssl_cert", "curl", "banner"]
    if service in ("http", "www") or port in ("80", "8080", "8000"):
        return ["curl", "banner"]
    if service in ("smb", "microsoft-ds") or port in ("445", "139"):
        return ["smb", "nmap"]
    if service in ("rdp", "ms-wbt-server") or port == "3389":
        return ["rdp", "nmap"]

    return PLUGIN_STRATEGIES["default"]

def collect_evidence_for_finding(finding: Finding, passive: bool) -> dict:
    evidence = {}
    host = finding.host
    port = finding.port
    proto = finding.protocol
    service = finding.service

    # Always capture the Nessus plugin output as primary evidence
    if finding.plugin_output:
        evidence["nessus_plugin_output"] = finding.plugin_output

    if passive:
        return evidence  # Passive mode: Nessus output only

    strategies = get_strategies(finding.plugin_id, service, port)

    for strategy in strategies:
        try:
            if strategy == "banner":
                evidence["banner_grab"] = collect_port_banner(host, int(port), proto)
            elif strategy == "ssl_cert":
                evidence["ssl_certificate"] = collect_ssl_cert(host, int(port))
            elif strategy == "nmap":
                evidence["nmap_scan"] = collect_nmap(host, port, proto)
            elif strategy == "curl":
                evidence["http_headers"] = collect_curl(host, port, proto)
            elif strategy == "testssl":
                evidence["testssl_output"] = collect_testssl(host, port)
            elif strategy == "smb":
                evidence["smb_enumeration"] = collect_smbclient(host)
            elif strategy == "rdp":
                evidence["rdp_check"] = collect_rdp_check(host, port)
        except Exception as e:
            evidence[f"{strategy}_error"] = str(e)

    return evidence

# ─────────────────────────────────────────────
# DEDUPLICATION
# ─────────────────────────────────────────────
def deduplicate(findings: list[Finding]) -> list[Finding]:
    """
    For active evidence collection, deduplicate by (host, port, plugin_id)
    so we don't hit the same service multiple times unnecessarily.
    """
    seen = {}
    out = []
    for f in findings:
        key = (f.host, f.port, f.plugin_id)
        if key not in seen:
            seen[key] = True
            out.append(f)
    return out

# ─────────────────────────────────────────────
# OUTPUT WRITERS
# ─────────────────────────────────────────────
def severity_label(s: str) -> str:
    colours = {
        "critical": C.RED + C.BOLD,
        "high":     C.RED,
        "medium":   C.YELLOW,
        "low":      C.BLUE,
        "informational": C.CYAN,
    }
    return f"{colours.get(s, '')}{s.upper()}{C.RESET}"

def write_txt_evidence(finding: Finding, output_dir: Path):
    safe_name = re.sub(r"[^\w\-]", "_", finding.plugin_name)[:60]
    filename = f"{finding.severity_num}_{safe_name}_{finding.host}_{finding.port}.txt"
    filepath = output_dir / filename

    with open(filepath, "w") as f:
        f.write("=" * 70 + "\n")
        f.write(f"NESSUS EVIDENCE — {finding.plugin_name}\n")
        f.write("=" * 70 + "\n\n")
        f.write(f"Plugin ID   : {finding.plugin_id}\n")
        f.write(f"Severity    : {finding.severity.upper()}\n")
        f.write(f"Host        : {finding.host}\n")
        f.write(f"Port        : {finding.port}/{finding.protocol}\n")
        f.write(f"Service     : {finding.service}\n")
        f.write(f"CVE(s)      : {', '.join(finding.cve) or 'N/A'}\n")
        f.write(f"CVSS Base   : {finding.cvss_base or 'N/A'}\n")
        f.write(f"CVSSv3 Base : {finding.cvss3_base or 'N/A'}\n")
        f.write(f"Collected   : {datetime.datetime.now().isoformat()}\n\n")
        f.write("-" * 70 + "\n")
        f.write("SYNOPSIS\n")
        f.write("-" * 70 + "\n")
        f.write(finding.synopsis + "\n\n")
        f.write("-" * 70 + "\n")
        f.write("DESCRIPTION\n")
        f.write("-" * 70 + "\n")
        f.write(finding.description + "\n\n")
        f.write("-" * 70 + "\n")
        f.write("SOLUTION\n")
        f.write("-" * 70 + "\n")
        f.write(finding.solution + "\n\n")
        if finding.see_also:
            f.write("-" * 70 + "\n")
            f.write("REFERENCES\n")
            f.write("-" * 70 + "\n")
            f.write(finding.see_also + "\n\n")

        for key, value in finding.evidence.items():
            f.write("=" * 70 + "\n")
            f.write(f"EVIDENCE: {key.upper().replace('_', ' ')}\n")
            f.write("=" * 70 + "\n")
            f.write(str(value) + "\n\n")

def write_json_summary(findings: list[Finding], output_dir: Path):
    summary = []
    for f in findings:
        summary.append({
            "plugin_id":   f.plugin_id,
            "plugin_name": f.plugin_name,
            "severity":    f.severity,
            "host":        f.host,
            "port":        f.port,
            "protocol":    f.protocol,
            "service":     f.service,
            "cve":         f.cve,
            "cvss_base":   f.cvss_base,
            "cvss3_base":  f.cvss3_base,
            "evidence_keys": list(f.evidence.keys()),
            "evidence":    f.evidence,
        })

    with open(output_dir / "evidence_summary.json", "w") as f:
        json.dump(summary, f, indent=2)

def write_html_report(findings: list[Finding], output_dir: Path):
    sev_order = ["critical", "high", "medium", "low", "informational"]
    sev_colours = {
        "critical": "#c0392b",
        "high":     "#e67e22",
        "medium":   "#f1c40f",
        "low":      "#2980b9",
        "informational": "#7f8c8d",
    }

    grouped = {s: [] for s in sev_order}
    for f in findings:
        grouped.setdefault(f.severity, []).append(f)

    counts = {s: len(grouped[s]) for s in sev_order}
    total  = sum(counts.values())

    rows = []
    for sev in sev_order:
        for f in grouped[sev]:
            ev_html = ""
            for k, v in f.evidence.items():
                ev_html += f"""
                <div class="evidence-block">
                  <div class="evidence-title">{k.replace('_',' ').upper()}</div>
                  <pre>{v[:3000]}</pre>
                </div>"""
            rows.append(f"""
            <tr>
              <td><span class="badge" style="background:{sev_colours[sev]}">{sev.upper()}</span></td>
              <td>{f.plugin_id}</td>
              <td>{f.plugin_name}</td>
              <td>{f.host}</td>
              <td>{f.port}/{f.protocol}</td>
              <td>{', '.join(f.cve) or '—'}</td>
              <td>
                <details>
                  <summary>Show Evidence ({len(f.evidence)} item(s))</summary>
                  {ev_html}
                </details>
              </td>
            </tr>""")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Nessus Evidence Report</title>
<style>
  body {{ font-family: 'Segoe UI', sans-serif; background:#1a1a2e; color:#eee; margin:0; padding:20px; }}
  h1 {{ color:#00d4ff; }}
  .summary {{ display:flex; gap:16px; flex-wrap:wrap; margin-bottom:24px; }}
  .card {{ background:#16213e; border-radius:8px; padding:16px 24px; min-width:140px; text-align:center; }}
  .card .num {{ font-size:2em; font-weight:bold; }}
  table {{ width:100%; border-collapse:collapse; background:#16213e; border-radius:8px; overflow:hidden; }}
  th {{ background:#0f3460; padding:10px; text-align:left; color:#00d4ff; }}
  td {{ padding:8px 10px; border-bottom:1px solid #0f3460; vertical-align:top; font-size:0.9em; }}
  tr:hover {{ background:#0f3460; }}
  .badge {{ border-radius:4px; padding:2px 8px; color:#fff; font-size:0.8em; font-weight:bold; }}
  details summary {{ cursor:pointer; color:#00d4ff; }}
  pre {{ background:#0a0a1a; padding:10px; border-radius:4px; white-space:pre-wrap; font-size:0.8em; max-height:300px; overflow-y:auto; }}
  .evidence-block {{ margin:8px 0; }}
  .evidence-title {{ color:#aaa; font-size:0.75em; font-weight:bold; margin-bottom:4px; }}
  .ts {{ color:#555; font-size:0.8em; margin-top:8px; }}
</style>
</head>
<body>
<h1>🔍 Nessus Evidence Report</h1>
<p class="ts">Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Total findings: {total}</p>
<div class="summary">
  {"".join(f'<div class="card"><div class="num" style="color:{sev_colours[s]}">{counts[s]}</div><div>{s.upper()}</div></div>' for s in sev_order)}
</div>
<table>
  <thead>
    <tr><th>Severity</th><th>Plugin ID</th><th>Finding</th><th>Host</th><th>Port</th><th>CVE</th><th>Evidence</th></tr>
  </thead>
  <tbody>
    {"".join(rows)}
  </tbody>
</table>
</body>
</html>"""

    with open(output_dir / "evidence_report.html", "w") as f:
        f.write(html)

# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main():
    banner()

    parser = argparse.ArgumentParser(
        description="Collect active evidence for Nessus findings"
    )
    parser.add_argument("-f", "--file", required=True,
                        help="Path to .nessus file")
    parser.add_argument("-o", "--output", default="nessus_evidence",
                        help="Output directory (default: nessus_evidence/)")
    parser.add_argument("--min-severity",
                        choices=["informational","low","medium","high","critical"],
                        default="low",
                        help="Minimum severity to collect evidence for (default: low)")
    parser.add_argument("--passive", action="store_true",
                        help="Passive mode: collect Nessus output only, no active checks")
    parser.add_argument("--delay", type=float, default=0.5,
                        help="Delay between evidence collections in seconds (default: 0.5)")
    parser.add_argument("--no-info", action="store_true",
                        help="Skip informational findings entirely")
    args = parser.parse_args()

    # Validate input
    nessus_file = Path(args.file)
    if not nessus_file.exists():
        log(f"File not found: {nessus_file}", "ERR")
        sys.exit(1)

    # Set up output directory
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    log(f"Output directory: {output_dir.resolve()}")

    # Parse
    findings = parse_nessus(str(nessus_file))

    # Filter severity
    min_sev = SEVERITY_NUM.get(args.min_severity, 1)
    if args.no_info:
        min_sev = max(min_sev, 1)
    findings = [f for f in findings if f.severity_num >= min_sev]
    log(f"Filtered to {len(findings)} findings at severity >= {args.min_severity}")

    # Sort by severity descending
    findings.sort(key=lambda f: f.severity_num, reverse=True)

    # Deduplicate for active checks
    unique = deduplicate(findings)
    log(f"Unique (host, port, plugin) combinations: {len(unique)}")

    if args.passive:
        log("Passive mode enabled — skipping active evidence collection", "WARN")
    else:
        log("Active evidence collection enabled", "WARN")
        log("Ensure you have authorisation to test the target systems!", "WARN")

    # Collect evidence
    for i, finding in enumerate(unique, 1):
        pct = f"[{i}/{len(unique)}]"
        log(f"{pct} {severity_label(finding.severity)} {finding.plugin_name} — "
            f"{finding.host}:{finding.port}")

        finding.evidence = collect_evidence_for_finding(finding, passive=args.passive)
        write_txt_evidence(finding, output_dir)

        if args.delay > 0 and not args.passive:
            time.sleep(args.delay)

    # Write outputs
    write_json_summary(unique, output_dir)
    log("Wrote evidence_summary.json", "OK")

    write_html_report(unique, output_dir)
    log("Wrote evidence_report.html", "OK")

    # Print summary
    print(f"\n{C.BOLD}{'─'*50}{C.RESET}")
    print(f"{C.GREEN}{C.BOLD}Evidence collection complete!{C.RESET}")
    print(f"  Findings processed : {len(unique)}")
    print(f"  Output directory   : {output_dir.resolve()}")
    print(f"  Text files         : {len(list(output_dir.glob('*.txt')))}")
    print(f"  HTML report        : {output_dir}/evidence_report.html")
    print(f"  JSON summary       : {output_dir}/evidence_summary.json")
    print(f"{C.BOLD}{'─'*50}{C.RESET}\n")

if __name__ == "__main__":
    main()
