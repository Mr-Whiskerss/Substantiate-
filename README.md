# Substantiate-
# Nessus Evidence Collector

> Automatically parse `.nessus` scan files and collect active evidence for every finding — banner grabs, TLS certificates, HTTP headers, nmap scans, and more.

Built for penetration testers who want to go from a raw Nessus export to a structured, evidenced report without manually verifying every finding by hand.

---

## Features

- **Full `.nessus` XML parsing** — extracts plugin ID, severity, host, port, service, CVEs, CVSS scores, plugin output, description, solution, and references
- **Intelligent evidence routing** — maps known plugin IDs and service types to appropriate collection strategies
- **Active evidence collection** via:
  - Raw TCP banner grabs
  - TLS/SSL certificate inspection (subject, issuer, SANs, cipher suite, expiry)
  - HTTP/HTTPS header grabs via `curl`
  - Targeted `nmap -sV` service scans per port
  - Full TLS assessment via `testssl.sh`
  - Anonymous SMB share enumeration via `smbclient`
  - RDP connectivity checks
- **Passive mode** — Nessus plugin output only, no active probing
- **Three output formats:**
  - Per-finding `.txt` evidence files (named by severity, plugin, host, port)
  - `evidence_summary.json` — machine-readable full dump
  - `evidence_report.html` — interactive dark-themed report with collapsible evidence blocks
- **Zero external Python dependencies** — stdlib only
- Optional system tools used if available, gracefully skipped if not

---

## Requirements

**Python:** 3.9+

**Optional system tools** (used when available):

| Tool | Purpose |
|------|---------|
| `nmap` | Service/version scanning |
| `curl` | HTTP header grabs |
| `testssl.sh` | Full TLS assessment |
| `smbclient` | SMB share enumeration |
| `nc` | RDP connectivity checks |

Install on Kali/Debian:
```bash
sudo apt install nmap curl smbclient netcat-openbsd
# testssl.sh: https://testssl.sh
```

---

## Installation

```bash
git clone https://github.com/Mr-Whiskerss/nessus-evidence-collector.git
cd nessus-evidence-collector
chmod +x nessus_evidence_collector.py
```

No `pip install` required.

---

## Usage

```bash
python3 nessus_evidence_collector.py -f <scan.nessus> -o <output_dir/> [options]
```

### Examples

```bash
# Standard run — low+ severity, active checks
python3 nessus_evidence_collector.py -f scan.nessus -o ./evidence/

# High and critical only
python3 nessus_evidence_collector.py -f scan.nessus -o ./evidence/ --min-severity high

# Passive mode — no active probing (Nessus output only)
python3 nessus_evidence_collector.py -f scan.nessus -o ./evidence/ --passive

# Slower, gentler active collection with 2s delay between checks
python3 nessus_evidence_collector.py -f scan.nessus -o ./evidence/ --delay 2

# Skip informational findings entirely
python3 nessus_evidence_collector.py -f scan.nessus -o ./evidence/ --no-info
```

### Arguments

| Flag | Default | Description |
|------|---------|-------------|
| `-f, --file` | *(required)* | Path to `.nessus` file |
| `-o, --output` | `nessus_evidence/` | Output directory |
| `--min-severity` | `low` | Minimum severity: `informational`, `low`, `medium`, `high`, `critical` |
| `--passive` | `False` | Skip active checks; collect Nessus output only |
| `--delay` | `0.5` | Seconds between active evidence collections |
| `--no-info` | `False` | Exclude informational findings |

---

## Output Structure

```
evidence/
├── 4_SSL_Certificate_Cannot_Be_Trusted_10.0.0.1_443.txt
├── 3_SMB_Signing_Not_Required_10.0.0.5_445.txt
├── 2_TLS_Deprecated_Protocol_10.0.0.1_8443.txt
├── ...
├── evidence_summary.json
└── evidence_report.html
```

Each `.txt` file contains:
- Plugin metadata (ID, severity, CVEs, CVSS scores)
- Synopsis, description, and solution from Nessus
- All collected evidence blocks labelled by type

The HTML report provides a filterable, collapsible view of all findings and their evidence — suitable for internal review before writing up the formal report.

---

## Evidence Routing

The tool maps findings to collection strategies based on plugin ID first, then falls back to service/port heuristics:

| Signal | Strategies |
|--------|-----------|
| Plugin ID known (e.g. `57608` — SMB signing) | SMB enumeration + nmap |
| Service: `https`, port `443/8443` | SSL cert + curl + banner |
| Service: `smb`, port `445/139` | SMB enumeration + nmap |
| Service: `rdp`, port `3389` | RDP check + nmap |
| Service: `http`, port `80/8080` | curl + banner |
| Default | Banner grab + nmap |

---

## Disclaimer

This tool is intended for use during **authorised penetration testing engagements only**. Active evidence collection sends traffic to target hosts. Ensure you have written permission before running against any system you do not own.

The author accepts no liability for misuse.

---

## Author

**Dan** — Penetration Tester @ [URM Consulting](https://www.urmconsulting.com)  
GitHub: [@Mr-Whiskerss](https://github.com/Mr-Whiskerss)
