#!/usr/bin/env python3
"""
EndpointAudit - Workstation Security & Compliance Checker
Designed for regulated environments such as finance and law firms.
Author: [Tolulope Oshadiya]
Version: 1.0.0
"""

import subprocess
import platform
import datetime
import os
import sys
import json

# ─────────────────────────────────────────────
# HELPER: Run a shell command and return output
# ─────────────────────────────────────────────
def run_cmd(command):
    """Runs a shell command and returns the output as a string."""
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return "TIMEOUT"
    except Exception as e:
        return f"ERROR: {e}"


# ─────────────────────────────────────────────
# SECTION 1: System Info
# ─────────────────────────────────────────────
def get_system_info():
    """Collects basic system and hardware information."""
    print("\n[1/6] Collecting system information...")

    hostname = platform.node()
    os_version = platform.mac_ver()[0]
    kernel = platform.release()
    uptime_raw = run_cmd("uptime | sed 's/.*up //' | sed 's/,.*//'")

    # CPU info
    cpu_brand = run_cmd("sysctl -n machdep.cpu.brand_string")
    cpu_cores = run_cmd("sysctl -n hw.logicalcpu")

    # RAM info
    ram_bytes = run_cmd("sysctl -n hw.memsize")
    try:
        ram_gb = round(int(ram_bytes) / (1024 ** 3), 1)
        ram_display = f"{ram_gb} GB"
    except ValueError:
        ram_display = "Unknown"

    # Disk info
    disk_raw = run_cmd("df -h / | tail -1")
    disk_parts = disk_raw.split()
    if len(disk_parts) >= 5:
        disk_total = disk_parts[1]
        disk_used = disk_parts[2]
        disk_avail = disk_parts[3]
        disk_pct = disk_parts[4]
    else:
        disk_total = disk_used = disk_avail = disk_pct = "Unknown"

    return {
        "hostname": hostname,
        "os_version": f"macOS {os_version}",
        "kernel": kernel,
        "uptime": uptime_raw,
        "cpu": cpu_brand,
        "cpu_cores": cpu_cores,
        "ram": ram_display,
        "disk_total": disk_total,
        "disk_used": disk_used,
        "disk_available": disk_avail,
        "disk_used_pct": disk_pct,
    }


# ─────────────────────────────────────────────
# SECTION 2: Firewall Check
# ─────────────────────────────────────────────
def check_firewall():
    """Checks if the macOS Application Firewall is enabled."""
    print("[2/6] Checking firewall status...")

    raw = run_cmd(
        "defaults read /Library/Preferences/com.apple.alf globalstate 2>/dev/null"
    )

    if raw == "1" or raw == "2":
        status = "ENABLED"
        compliant = True
    elif raw == "0":
        status = "DISABLED"
        compliant = False
    else:
        status = f"UNKNOWN (raw value: {raw})"
        compliant = False

    stealth = run_cmd(
        "defaults read /Library/Preferences/com.apple.alf stealthenabled 2>/dev/null"
    )
    stealth_status = "ENABLED" if stealth == "1" else "DISABLED"

    return {
        "firewall_status": status,
        "stealth_mode": stealth_status,
        "compliant": compliant,
    }


# ─────────────────────────────────────────────
# SECTION 3: Disk Encryption (FileVault)
# ─────────────────────────────────────────────
def check_encryption():
    """Checks if FileVault disk encryption is active."""
    print("[3/6] Checking disk encryption (FileVault)...")

    raw = run_cmd("fdesetup status 2>/dev/null")

    if "On" in raw:
        status = "ENABLED"
        compliant = True
    elif "Off" in raw:
        status = "DISABLED"
        compliant = False
    else:
        status = f"UNKNOWN — try running with sudo for full access"
        compliant = False

    return {
        "filevault_status": status,
        "compliant": compliant,
    }


# ─────────────────────────────────────────────
# SECTION 4: Screen Lock / Auto-Lock Policy
# ─────────────────────────────────────────────
def check_screen_lock():
    """Checks screen saver timeout and password requirement settings."""
    print("[4/6] Checking screen lock policy...")

    # Check if password is required after screensaver
    pw_required = run_cmd(
        "defaults read com.apple.screensaver askForPassword 2>/dev/null"
    )
    pw_delay = run_cmd(
        "defaults read com.apple.screensaver askForPasswordDelay 2>/dev/null"
    )

    password_on_wake = pw_required == "1"

    try:
        delay_seconds = int(pw_delay)
        delay_display = f"{delay_seconds} seconds"
        # Compliant if password required immediately or within 5 seconds
        delay_compliant = delay_seconds <= 5
    except ValueError:
        delay_display = "Unknown"
        delay_compliant = False

    # Screen saver idle time
    idle_time_raw = run_cmd(
        "defaults -currentHost read com.apple.screensaver idleTime 2>/dev/null"
    )
    try:
        idle_seconds = int(idle_time_raw)
        if idle_seconds == 0:
            idle_display = "Never (NOT SET)"
            idle_compliant = False
        else:
            idle_minutes = round(idle_seconds / 60, 1)
            idle_display = f"{idle_minutes} minutes"
            idle_compliant = idle_seconds <= 600  # 10 min or less = compliant
    except ValueError:
        idle_display = "Unknown"
        idle_compliant = False

    overall_compliant = password_on_wake and delay_compliant and idle_compliant

    return {
        "password_required_on_wake": "YES" if password_on_wake else "NO",
        "password_delay": delay_display,
        "screen_saver_timeout": idle_display,
        "compliant": overall_compliant,
    }


# ─────────────────────────────────────────────
# SECTION 5: User & Admin Rights Audit
# ─────────────────────────────────────────────
def check_users():
    """Lists local user accounts and identifies admin users."""
    print("[5/6] Auditing user accounts and admin rights...")

    # Get all local, non-system users
    all_users_raw = run_cmd(
        "dscl . list /Users | grep -v '^_' | grep -v 'root' | grep -v 'daemon' | grep -v 'nobody'"
    )
    all_users = [u for u in all_users_raw.splitlines() if u.strip()]

    # Get admin group members
    admin_raw = run_cmd("dscl . -read /Groups/admin GroupMembership 2>/dev/null")
    admin_users = []
    if "GroupMembership:" in admin_raw:
        admin_users = admin_raw.replace("GroupMembership:", "").split()

    user_details = []
    for user in all_users:
        is_admin = user in admin_users
        user_details.append({
            "username": user,
            "is_admin": is_admin,
        })

    admin_count = sum(1 for u in user_details if u["is_admin"])
    # Best practice: only 1 admin account on a standard workstation
    compliant = admin_count <= 1

    return {
        "users": user_details,
        "total_users": len(user_details),
        "admin_count": admin_count,
        "compliant": compliant,
    }


# ─────────────────────────────────────────────
# SECTION 6: OS Update Status
# ─────────────────────────────────────────────
def check_updates():
    """Checks for available macOS software updates."""
    print("[6/6] Checking for software updates (this may take a moment)...")

    raw = run_cmd("softwareupdate -l 2>&1")

    if "No new software available" in raw:
        status = "UP TO DATE"
        pending = []
        compliant = True
    elif "Software Update found" in raw or "* Label:" in raw or "* " in raw:
        status = "UPDATES AVAILABLE"
        # Parse update names
        pending = [
            line.strip().lstrip("* ")
            for line in raw.splitlines()
            if line.strip().startswith("*") and "Label:" not in line
        ]
        compliant = False
    else:
        status = "UNABLE TO CHECK — ensure network access"
        pending = []
        compliant = False

    return {
        "update_status": status,
        "pending_updates": pending if pending else ["None found"],
        "compliant": compliant,
    }


# ─────────────────────────────────────────────
# REPORT GENERATION
# ─────────────────────────────────────────────
def generate_report(results):
    """Builds and saves a plain-text audit report."""

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    date_slug = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"audit_report_{date_slug}.txt"
    filepath = os.path.join(os.path.dirname(__file__), "reports", filename)

    os.makedirs(os.path.dirname(filepath), exist_ok=True)

    lines = []

    def add(text=""):
        lines.append(text)

    def section(title):
        add()
        add("=" * 60)
        add(f"  {title}")
        add("=" * 60)

    def item(label, value, width=30):
        add(f"  {label:<{width}} {value}")

    def compliance_badge(compliant):
        return "[ PASS ]" if compliant else "[ FAIL ]"

    # ── Header ──
    add("=" * 60)
    add("  ENDPOINTAUDIT — WORKSTATION COMPLIANCE REPORT")
    add("=" * 60)
    add(f"  Generated : {timestamp}")
    add(f"  Tool      : EndpointAudit v1.0.0")
    add(f"  Purpose   : Security & compliance check for regulated environments")

    # ── System Info ──
    section("1. SYSTEM INFORMATION")
    s = results["system"]
    item("Hostname:", s["hostname"])
    item("Operating System:", s["os_version"])
    item("Kernel Version:", s["kernel"])
    item("System Uptime:", s["uptime"])
    add()
    item("CPU:", s["cpu"])
    item("CPU Cores:", s["cpu_cores"])
    item("RAM:", s["ram"])
    add()
    item("Disk Total:", s["disk_total"])
    item("Disk Used:", f"{s['disk_used']} ({s['disk_used_pct']})")
    item("Disk Available:", s["disk_available"])

    # ── Firewall ──
    section("2. FIREWALL")
    f = results["firewall"]
    badge = compliance_badge(f["compliant"])
    item("Status:", f"{f['firewall_status']}  {badge}")
    item("Stealth Mode:", f["stealth_mode"])
    if not f["compliant"]:
        add()
        add("  ⚠ RECOMMENDATION: Enable the macOS Application Firewall.")
        add("    System Preferences > Security & Privacy > Firewall")

    # ── Encryption ──
    section("3. DISK ENCRYPTION (FileVault)")
    e = results["encryption"]
    badge = compliance_badge(e["compliant"])
    item("FileVault Status:", f"{e['filevault_status']}  {badge}")
    if not e["compliant"]:
        add()
        add("  ⚠ RECOMMENDATION: Enable FileVault to encrypt the disk.")
        add("    System Preferences > Security & Privacy > FileVault")

    # ── Screen Lock ──
    section("4. SCREEN LOCK POLICY")
    sc = results["screen_lock"]
    badge = compliance_badge(sc["compliant"])
    item("Password on Wake:", f"{sc['password_required_on_wake']}  {badge}")
    item("Password Delay:", sc["password_delay"])
    item("Screen Saver Timeout:", sc["screen_saver_timeout"])
    if not sc["compliant"]:
        add()
        add("  ⚠ RECOMMENDATION: Set screen saver timeout to ≤10 minutes")
        add("    and require password immediately on wake.")

    # ── Users ──
    section("5. USER & ADMIN RIGHTS AUDIT")
    u = results["users"]
    badge = compliance_badge(u["compliant"])
    item("Total Local Users:", str(u["total_users"]))
    item("Admin Accounts:", f"{u['admin_count']}  {badge}")
    add()
    add("  User List:")
    for user in u["users"]:
        role = "ADMIN" if user["is_admin"] else "standard"
        add(f"    - {user['username']:<20} [{role}]")
    if not u["compliant"]:
        add()
        add("  ⚠ RECOMMENDATION: Limit admin accounts to IT-managed accounts only.")
        add("    Standard users should not have admin rights on regulated machines.")

    # ── Updates ──
    section("6. SOFTWARE UPDATE STATUS")
    up = results["updates"]
    badge = compliance_badge(up["compliant"])
    item("Status:", f"{up['update_status']}  {badge}")
    if up["pending_updates"] and up["pending_updates"] != ["None found"]:
        add()
        add("  Pending Updates:")
        for update in up["pending_updates"]:
            add(f"    - {update}")
    if not up["compliant"]:
        add()
        add("  ⚠ RECOMMENDATION: Apply all pending updates promptly.")
        add("    Unpatched systems are a primary vector for security breaches.")

    # ── Summary ──
    section("COMPLIANCE SUMMARY")
    checks = [
        ("Firewall", results["firewall"]["compliant"]),
        ("Disk Encryption (FileVault)", results["encryption"]["compliant"]),
        ("Screen Lock Policy", results["screen_lock"]["compliant"]),
        ("User & Admin Rights", results["users"]["compliant"]),
        ("OS Update Status", results["updates"]["compliant"]),
    ]
    passed = sum(1 for _, c in checks if c)
    total = len(checks)
    add()
    for name, compliant in checks:
        badge = "[ PASS ]" if compliant else "[ FAIL ]"
        add(f"  {badge}  {name}")
    add()
    add(f"  Overall: {passed}/{total} checks passed")
    if passed == total:
        add("  Status : COMPLIANT — This machine meets baseline security policy.")
    else:
        add("  Status : NON-COMPLIANT — Remediation required. See details above.")
    add()
    add("=" * 60)
    add("  END OF REPORT")
    add("=" * 60)

    report_text = "\n".join(lines)

    # Print to terminal
    print("\n")
    print(report_text)

    # Save to file
    with open(filepath, "w") as f:
        f.write(report_text)

    print(f"\n  ✓ Report saved to: {filepath}\n")

    # Also save raw JSON for programmatic use
    json_path = filepath.replace(".txt", ".json")
    with open(json_path, "w") as jf:
        json.dump(results, jf, indent=2)

    print(f"  ✓ JSON data saved to: {json_path}\n")


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main():
    print("=" * 60)
    print("  EndpointAudit — Workstation Compliance Checker")
    print("  Designed for finance & law firm IT environments")
    print("=" * 60)

    if platform.system() != "Darwin":
        print("\n  ⚠ Warning: This tool is designed for macOS.")
        print("  Some checks may not work correctly on other systems.\n")

    results = {
        "system": get_system_info(),
        "firewall": check_firewall(),
        "encryption": check_encryption(),
        "screen_lock": check_screen_lock(),
        "users": check_users(),
        "updates": check_updates(),
    }

    generate_report(results)


if __name__ == "__main__":
    main()
