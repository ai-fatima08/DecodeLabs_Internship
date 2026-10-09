import getpass
import json
import platform
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).parent
OS = platform.system()
PS = ["powershell", "-NoProfile", "-Command"]

COMMANDS = {
    "Windows": {
        "password": PS
        + [
            r"$u=(Get-LocalUser $env:USERNAME).PasswordRequired; $l=([string]((net accounts) -match 'Minimum password length')).Split(':')[1].Trim(); $u.ToString() + ',' + $l"
        ],
        "firewall": PS
        + ["(Get-NetFirewallProfile | Where-Object Enabled -eq False).Count"],
        "encryption": PS
        + ["(Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus"],
        "admins": PS + ["(Get-LocalGroupMember -Group Administrators).Count"],
        "updates": PS
        + [
            r"$v=(Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction SilentlyContinue).NoAutoUpdate; if($v -eq 1){'disabled'}else{'enabled'}"
        ],
        "guest": PS + ["(Get-LocalUser Guest).Enabled"],
        "antivirus": PS + ["(Get-MpComputerStatus).RealTimeProtectionEnabled"],
        "uac": PS
        + [
            r"(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').EnableLUA"
        ],
        "rdp": PS
        + [
            r"(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server').fDenyTSConnections"
        ],
    },
    "Darwin": {
        "password": ["defaults", "read", "com.apple.screensaver", "askForPassword"],
        "firewall": [
            "/usr/libexec/ApplicationFirewall/socketfilterfw",
            "--getglobalstate",
        ],
        "encryption": ["fdesetup", "status"],
        "admins": ["dscl", ".", "-read", "/Groups/admin", "GroupMembership"],
        "updates": [
            "defaults",
            "read",
            "/Library/Preferences/com.apple.SoftwareUpdate",
            "AutomaticCheckEnabled",
        ],
        "guest": [
            "defaults",
            "read",
            "/Library/Preferences/com.apple.loginwindow",
            "GuestEnabled",
        ],
        "antivirus": ["spctl", "--status"],
        "uac": ["csrutil", "status"],
        "rdp": ["sh", "-c", "nc -z -w1 localhost 22 && echo open || echo closed"],
    },
    "Linux": {
        "password": ["sh", "-c", "grep -c pam_pwquality /etc/pam.d/common-password"],
        "firewall": [
            "sh",
            "-c",
            "ufw status 2>/dev/null || systemctl is-active firewalld",
        ],
        "encryption": ["sh", "-c", "lsblk -o TYPE | grep -c crypt"],
        "admins": ["sh", "-c", "getent group sudo | cut -d: -f4"],
        "updates": ["sh", "-c", "systemctl is-enabled unattended-upgrades 2>&1"],
        "guest": ["sh", "-c", "getent passwd guest || echo none"],
    },
}

# check -> (plain explanation, {os: command}). USERNAME is replaced at runtime.
FIXES = {
    "password": (
        "Use a long passphrase (4+ random words) and make the system enforce a minimum length of 8 or more.",
        {
            "Windows": "net accounts /minpwlen:8",
            "Darwin": "defaults write com.apple.screensaver askForPassword -int 1",
            "Linux": "sudo apt install libpam-pwquality",
        },
    ),
    "firewall": (
        "Turn the firewall on so unauthorized inbound traffic is blocked.",
        {
            "Windows": "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True",
            "Darwin": "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on",
            "Linux": "sudo ufw enable",
        },
    ),
    "encryption": (
        "Encrypt the disk so a stolen laptop reveals nothing. Save the recovery key somewhere safe BEFORE you start.",
        {
            "Windows": "Enable-BitLocker -MountPoint C: -RecoveryPasswordProtector",
            "Darwin": "sudo fdesetup enable",
            "Linux": "",
        },
    ),
    "admins": (
        "Remove accounts you do not recognise from the admin group and use a standard account for daily work.",
        {
            "Windows": "Remove-LocalGroupMember -Group Administrators -Member USERNAME",
            "Darwin": "sudo dseditgroup -o edit -d USERNAME -t user admin",
            "Linux": "sudo deluser USERNAME sudo",
        },
    ),
    "updates": (
        "Turn automatic updates back on so known flaws get patched.",
        {
            "Windows": r"Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name NoAutoUpdate",
            "Darwin": "sudo softwareupdate --schedule on",
            "Linux": "sudo apt install unattended-upgrades",
        },
    ),
    "guest": (
        "Disable the Guest account. It lets untrusted users onto your machine.",
        {
            "Windows": "Disable-LocalUser -Name Guest",
            "Darwin": "sudo defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false",
            "Linux": "sudo userdel guest",
        },
    ),
}

FIXES.update(
    {
        "antivirus": (
            "Turn on real-time protection (Windows Defender) or Gatekeeper. Ignore this if you use another antivirus.",
            {
                "Windows": "Set-MpPreference -DisableRealtimeMonitoring $false",
                "Darwin": "sudo spctl --master-enable",
                "Linux": "",
            },
        ),
        "uac": (
            "Turn on User Account Control / System Integrity Protection so programs cannot change the system silently. Restart afterwards.",
            {
                "Windows": r"Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1",
                "Darwin": "Restart into Recovery Mode and run: csrutil enable",
                "Linux": "",
            },
        ),
        "rdp": (
            "Turn off remote access if you do not use it. Attackers try to log in through it.",
            {
                "Windows": r"Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 1",
                "Darwin": "sudo systemsetup -setremotelogin off",
                "Linux": "",
            },
        ),
    }
)


def run(cmd):
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        return (out.stdout or out.stderr).strip()
    except Exception as exc:
        return "unavailable: " + exc.__class__.__name__


def grade(check, out):
    o = out.lower()
    errors = (
        "failed",
        "can't",
        "cannot",
        "not found",
        "no such",
        "denied",
        "not recognized",
        "does not exist",
        "exception",
        "error",
    )
    if not o or o.startswith("unavailable") or any(e in o for e in errors):
        return (
            "Unverified",
            0.0,
            "Could not be verified. Usually this needs Administrator rights.",
        )
    if check == "password":
        if OS == "Windows":
            req, _, ln = o.partition(",")
            if req == "false":
                return "High", 7.5, "This account does not require a password."
            if ln.isdigit() and int(ln) < 8:
                return (
                    "Medium",
                    5.3,
                    "Password policy allows very short passwords (minimum length "
                    + ln
                    + ").",
                )
            return "Pass", 0.0, "Password required and policy length is acceptable."
        bad = o in ("0", "false")
        return (
            (
                "Medium",
                5.3,
                "Password is not enforced after sleep, or no password-quality rules.",
            )
            if bad
            else ("Pass", 0.0, "Password protection looks fine.")
        )
    if check == "firewall":
        bad = (
            o in ("1", "2", "3")
            or "disabled" in o
            or "inactive" in o
            or "state = 0" in o
        )
        return (
            ("Critical", 9.1, "Firewall is off.")
            if bad
            else ("Pass", 0.0, "Firewall active.")
        )
    if check == "encryption":
        bad = o in ("0", "off", "none") or "is off" in o or o.startswith("0")
        return (
            ("High", 7.8, "Disk is not encrypted.")
            if bad
            else ("Pass", 0.0, "Disk encryption on.")
        )
    if check == "admins":
        n = len(o.replace(",", " ").split())
        n = n - 1 if OS == "Darwin" else n
        return (
            ("Medium", 5.5, "Too many admin accounts. Review them.")
            if n > 2
            else ("Pass", 0.0, "Admin group is small.")
        )
    if check == "updates":
        bad = "disabled" in o or o in ("0", "false") or "inactive" in o
        return (
            ("High", 7.2, "Automatic updates are off.")
            if bad
            else ("Pass", 0.0, "Updates enabled.")
        )
    if check == "guest":
        return (
            ("Medium", 6.1, "Guest account is enabled.")
            if o in ("true", "1")
            else ("Pass", 0.0, "No active guest account.")
        )
    if check == "antivirus":
        bad = o in ("false", "0") or "disabled" in o
        return (
            ("High", 7.4, "Real-time antivirus protection is off.")
            if bad
            else ("Pass", 0.0, "Antivirus protection is on.")
        )
    if check == "uac":
        bad = o == "0" or "disabled" in o
        return (
            ("High", 7.0, "UAC / System Integrity Protection is off.")
            if bad
            else ("Pass", 0.0, "UAC / System Integrity Protection is on.")
        )
    if check == "rdp":
        bad = o in ("0", "open")
        return (
            ("Medium", 5.9, "Remote access is enabled.")
            if bad
            else ("Pass", 0.0, "Remote access is off.")
        )
    return "Pass", 0.0, ""


def os_release():
    rel = platform.release()
    if OS == "Windows":
        try:
            if int(platform.version().split(".")[2]) >= 22000:
                rel = "11"  # Python still reports Windows 11 as "10"
        except Exception:
            pass
    return rel


def audit():
    results = []
    for name, cmd in COMMANDS.get(OS, COMMANDS["Linux"]).items():
        out = run(cmd)
        sev, score, note = grade(name, out)
        fix = None
        if sev == "Unverified":
            fix = {
                "text": "Close the terminal, reopen it with Run as administrator, then run python app.py and scan again.",
                "cmd": "",
            }
        elif sev != "Pass":
            text, cmds = FIXES[name]
            fix = {
                "text": text,
                "cmd": cmds.get(OS, "").replace("USERNAME", getpass.getuser()),
            }
        results.append(
            {
                "check": name,
                "severity": sev,
                "cvss": score,
                "note": note,
                "output": out[:140],
                "fix": fix,
            }
        )
    return {
        "os": OS,
        "host": platform.node(),
        "release": os_release(),
        "results": results,
    }


class Handler(BaseHTTPRequestHandler):
    def send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/api/audit":
            return self.send(200, json.dumps(audit()).encode(), "application/json")
        if self.path in ("/", "/index.html"):
            return self.send(
                200, (ROOT / "index.html").read_bytes(), "text/html; charset=utf-8"
            )
        self.send(404, b"Not found", "text/plain")

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print("Vulnix running at http://localhost:8000")
    HTTPServer(("127.0.0.1", 8000), Handler).serve_forever()
