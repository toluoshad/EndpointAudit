# EndpointAudit 🔍

**A workstation security and compliance checker for regulated environments — built for finance and law firm IT support teams.**

---

## What It Does

EndpointAudit is a Python command-line tool that audits a macOS workstation against a baseline security policy. It produces a clear, readable report that an IT support technician can use to quickly assess whether a machine is compliant before a user starts work — or to diagnose issues during a support call.

It checks six key areas:

| Check | What It Looks For |
|---|---|
| 🖥 System Info | Hostname, OS version, CPU, RAM, disk usage |
| 🔥 Firewall | Whether the macOS Application Firewall is active |
| 🔒 Disk Encryption | Whether FileVault (full-disk encryption) is enabled |
| ⏱ Screen Lock Policy | Screen saver timeout and password-on-wake settings |
| 👤 User & Admin Audit | Who has admin rights on the machine |
| 🔄 OS Update Status | Whether the machine has pending security updates |

Each check is marked **[ PASS ]** or **[ FAIL ]** with a plain-English recommendation if remediation is needed.

---

## Why This Matters in Finance & Law

Firms in regulated industries (FCA, SRA, ISO 27001, Cyber Essentials) must ensure that every endpoint meets minimum security standards. A machine with FileVault off, an unlocked screen, or an unpatched OS is a compliance risk — and a potential breach waiting to happen.

This tool gives IT support staff a fast, repeatable way to verify a machine is secure — whether it's a new starter's laptop, a machine returned from repair, or a spot-check during a compliance audit.

---

## Requirements

- macOS (tested on macOS 12 Monterey and above)
- Python 3.8+
- No third-party libraries required — uses the Python standard library only

---

## How to Run

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/EndpointAudit.git
cd EndpointAudit

# 2. Run the audit
python3 endpoint_audit.py
```

> Some checks (e.g. FileVault status) may require `sudo` for full output:
> ```bash
> sudo python3 endpoint_audit.py
> ```

---

## Sample Output

```
============================================================
  ENDPOINTAUDIT — WORKSTATION COMPLIANCE REPORT
============================================================
  Generated : 2025-06-01 09:42:11
  Tool      : EndpointAudit v1.0.0
  Purpose   : Security & compliance check for regulated environments

============================================================
  2. FIREWALL
============================================================
  Status:                        ENABLED  [ PASS ]
  Stealth Mode:                  ENABLED

============================================================
  3. DISK ENCRYPTION (FileVault)
============================================================
  FileVault Status:              DISABLED  [ FAIL ]

  ⚠ RECOMMENDATION: Enable FileVault to encrypt the disk.
    System Preferences > Security & Privacy > FileVault

============================================================
  COMPLIANCE SUMMARY
============================================================
  [ PASS ]  Firewall
  [ FAIL ]  Disk Encryption (FileVault)
  [ PASS ]  Screen Lock Policy
  [ PASS ]  User & Admin Rights
  [ FAIL ]  OS Update Status

  Overall: 3/5 checks passed
  Status : NON-COMPLIANT — Remediation required. See details above.
```

Reports are saved automatically to a `/reports` folder as both `.txt` and `.json` files.

---

## Project Structure

```
EndpointAudit/
├── endpoint_audit.py     # Main audit script
├── reports/              # Auto-created — stores generated reports
│   ├── audit_report_YYYYMMDD_HHMMSS.txt
│   └── audit_report_YYYYMMDD_HHMMSS.json
└── README.md
```

---

## Roadmap / Future Features

- [ ] HTML report output with colour-coded pass/fail badges
- [ ] Windows support (using PowerShell checks via subprocess)
- [ ] Antivirus/EDR detection check
- [ ] Export summary via email (SMTP)
- [ ] Config file to customise compliance thresholds (e.g. max screen lock time)

---

## About

Built as a portfolio project to demonstrate practical IT support skills relevant to finance and law firm environments — including knowledge of endpoint security, hardware auditing, compliance requirements, and scripting.

---

## Licence

MIT — free to use, adapt, and build on.
