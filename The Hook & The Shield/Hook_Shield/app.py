import re
from urllib.parse import urlparse
from flask import Flask, request, jsonify, send_from_directory, render_template

app = Flask(__name__, static_folder=".")

BRANDS = [
    "microsoft",
    "paypal",
    "amazon",
    "google",
    "apple",
    "netflix",
    "chatgpt",
    "openai",
    "linkedin",
    "facebook",
    "dhl",
    "fedex",
    "bank",
    "quanta",
]
FREE_MAIL = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "proton.me"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy"}
RISKY_EXT = (
    ".iso",
    ".js",
    ".scr",
    ".exe",
    ".vbs",
    ".html",
    ".htm",
    ".lnk",
    ".bat",
    ".zip",
)
HOST_WORDS = ("login", "secure", "verify", "update", "account", "signin", "support")

# Dangling DNS
DANGLING_PROVIDERS = [
    "s3.amazonaws.com",
    "s3-website",
    "cloudfront.net",
    "azurewebsites.net",
    "cloudapp.azure.com",
    "blob.core.windows.net",
    "herokuapp.com",
    "github.io",
    "netlify.app",
    "vercel.app",
    "surge.sh",
    "readthedocs.io",
    "zendesk.com",
    "freshdesk.com",
    "statuspage.io",
    "fastly.net",
    "trafficmanager.net",
    "cloudfront",
    "amazonaws.com",
    "herokudns.com",
]

TRIGGERS = {
    "Urgency": [
        "urgent",
        "immediately",
        "asap",
        "within 24",
        "30 minutes",
        "expires",
        "final notice",
        "act now",
        "before the close of business",
        "suspended",
        "locked",
        "expires in 24",
    ],
    "Authority": [
        "ceo",
        "director",
        "it security",
        "it support",
        "legal department",
        "government",
        "irs",
        "police",
        "cfo",
        "founder",
        "executive",
    ],
    "Fear": [
        "unauthorized",
        "legal action",
        "terminated",
        "suspicious activity",
        "breach",
        "payment failed",
        "penalty",
        "overdue",
        "locked out",
        "compromised",
    ],
    "Greed": [
        "winner",
        "prize",
        "reward",
        "gift card",
        "free",
        "claim your",
        "refund",
        "bonus",
    ],
    "Curiosity": [
        "see what",
        "you won't believe",
        "view meeting details",
        "shared a document",
        "voicemail",
        "click to see",
        "just between us",
    ],
    "Secrecy / Bypass": [
        "strictly confidential",
        "do not discuss",
        "bypass",
        "keep this between us",
        "don't tell",
        "skip the",
        "avoid the normal",
    ],
    "Sensitive info": [
        "password",
        "otp",
        "mfa code",
        "verification code",
        "ssn",
        "card number",
        "billing",
        "bank details",
        "update your payment",
        "wire transfer",
        "routing number",
    ],
}

# BitB
BITB_HINTS = [
    r"pop[- ]?up",
    r"sign[- ]?in\s+window",
    r"sso\s+window",
    r"login\s+popup",
    r"open\s+the\s+window",
    r"drag\s+the\s+window",
    r"can'?t\s+be\s+dragged",
    r"proceed\s+with\s+the\s+popup",
    r"window\.close",
    r"browser\s+window",
]

# MFA fatigue keywords
MFA_FATIGUE_HINTS = [
    r"approve\s+sign[- ]?in",
    r"approve\s+the\s+request",
    r"approve\s+push",
    r"mfa\s+request",
    r"authenticator\s+push",
    r"multiple\s+pushes",
    r"repeated\s+notifications?",
    r"tap\s+approve",
    r"deny\s+or\s+approve",
    r"just\s+approve\s+it",
    r"approve\s+to\s+stop",
]


def url_issues(url):
    """Return (host, [issues]) for a URL. Detects typosquatting, homoglyphs,
    combosquatting, subdomain traps, dangling DNS providers, and more."""
    issues = []
    p = urlparse(url if "//" in url else "http://" + url)
    host = (p.hostname or "").lower()
    parts = host.split(".")
    label = parts[-2] if len(parts) >= 2 else host
    root = ".".join(parts[-2:])

    if re.fullmatch(r"[\d.]+", host):
        issues.append("Raw IP address used instead of a domain name")
    if root in SHORTENERS:
        issues.append("URL shortener hides the real destination")
    if "xn--" in host or not host.isascii():
        issues.append("Homoglyph / punycode characters (lookalike alphabet)")
    if "@" in p.netloc:
        issues.append("'@' in URL: real destination is after the @")
    if p.scheme == "http":
        issues.append("Unencrypted http:// link")
    if len(parts) >= 5:
        issues.append("Deeply nested subdomains (subdomain trap)")

    # Dangling DNS / cloud-provider takeover risk
    for prov in DANGLING_PROVIDERS:
        if prov in host:
            issues.append(
                f"Dangling DNS risk: hosted on {prov} (takeover target if CNAME abandoned)"
            )
            break

    norm = (
        label.replace("0", "o").replace("1", "l").replace("rn", "m").replace("vv", "w")
    )
    for b in BRANDS:
        if label != b and norm == b:
            issues.append(f"Typosquatting: '{label}' imitates '{b}'")
        elif b in label and label != b:
            issues.append(f"Combosquatting: brand '{b}' padded inside '{label}'")
        elif b in ".".join(parts[:-2]):
            issues.append(
                f"Subdomain trap: '{b}' is a subdomain, true root is '{root}'"
            )

    if any(w in label for w in HOST_WORDS) and "-" in label:
        issues.append("Security words chained to the domain (e.g. secure-login)")
    return host, list(dict.fromkeys(issues))


def parse_from_header(text):
    """Return dict {name, addr, domain, raw} if a From: header exists."""
    m = re.search(r"^from:\s*(.+)$", text, re.I | re.M)
    if not m:
        return None
    raw = m.group(1).strip()
    fm = re.match(r"\s*\"?(.*?)\"?\s*<([^>]+)>", raw)
    if fm:
        name, addr = fm.group(1).strip(), fm.group(2).strip()
    else:
        name, addr = "", raw
    domain = addr.split("@")[-1].lower().strip() if "@" in addr else ""
    return {"name": name, "addr": addr, "domain": domain, "raw": raw}


def build_header_report(text):
    """Full email header breakdown for the Show Headers demo."""
    from_h = parse_from_header(text) or {
        "name": "",
        "addr": "",
        "domain": "",
        "raw": "",
    }
    rp = re.search(r"^reply-to:\s*(.+)$", text, re.I | re.M)
    rt = re.search(r"^return-path:\s*(.+)$", text, re.I | re.M)
    sub = re.search(r"^subject:\s*(.+)$", text, re.I | re.M)
    to = re.search(r"^to:\s*(.+)$", text, re.I | re.M)
    date = re.search(r"^date:\s*(.+)$", text, re.I | re.M)
    msgid = re.search(r"^message-id:\s*(.+)$", text, re.I | re.M)
    spf = re.search(r"^received-spf:\s*(.+)$", text, re.I | re.M)
    dkim = re.search(r"^dkim-signature:\s*(.+)$", text, re.I | re.M)
    dmarc = re.search(r"^authentication-results:\s*(.+)$", text, re.I | re.M)

    reply_domain = ""
    if rp:
        rp_val = rp.group(1).strip()
        if "@" in rp_val:
            reply_domain = rp_val.split("@")[-1].strip(" >")

    warnings = []
    if from_h["domain"] and from_h["domain"] in FREE_MAIL:
        warnings.append(
            f"From domain '{from_h['domain']}' is a free-mail provider (unusual for corporate senders)."
        )
    if from_h["name"] and re.search(
        r"ceo|director|support|security|hr|finance|bank|it", from_h["name"], re.I
    ):
        warnings.append(f"Display name '{from_h['name']}' claims authority.")
    if reply_domain and reply_domain != from_h["domain"]:
        warnings.append(
            f"Reply-To domain '{reply_domain}' differs from From domain '{from_h['domain']}'."
        )
    if sub and re.search(r"^\s*(fw|fwd):", sub.group(1), re.I):
        warnings.append(
            "Subject begins with FW:/Fwd: — check whether you were in the original thread."
        )
    if from_h["domain"]:
        _, dom_issues = url_issues("https://" + from_h["domain"])
        warnings.extend([f"From-domain issue: {i}" for i in dom_issues])
    if not spf:
        warnings.append(
            "No Received-SPF header — SPF authentication not visible (or header was stripped)."
        )
    if not dkim:
        warnings.append(
            "No DKIM-Signature header — sender domain signing not verified."
        )
    if not dmarc:
        warnings.append("No Authentication-Results header — DMARC status unknown.")

    return {
        "from": from_h,
        "reply_to": rt.group(1).strip() if rt else "",
        "return_path": rt.group(1).strip() if rt else "",
        "to": to.group(1).strip() if to else "",
        "subject": sub.group(1).strip() if sub else "",
        "date": date.group(1).strip() if date else "",
        "message_id": msgid.group(1).strip() if msgid else "",
        "spf": spf.group(1).strip() if spf else "",
        "dkim_present": bool(dkim),
        "dmarc_present": bool(dmarc),
        "warnings": warnings,
    }


def analyze(text):
    low = re.sub(r"\b(non|not)[- ]urgent\b", " ", text.lower())
    score, flags, why = 0, [], []

    def flag(n, title, detail, pts):
        nonlocal score
        score += pts
        flags.append({"id": n, "title": title, "detail": detail})

    # --- Header checks ---
    fh = parse_from_header(text)
    rp = re.search(r"^reply-to:\s*(.+)$", text, re.I | re.M)
    if fh:
        name, addr, dom = fh["name"], fh["addr"], fh["domain"]
        if dom in FREE_MAIL and (
            name
            and re.search(
                r"ceo|director|support|security|hr|finance|bank|it", name, re.I
            )
        ):
            flag(
                1,
                "Sender-domain mismatch",
                f"Display name '{name}' but address is a free mail domain ({dom})",
                30,
            )
        for b in BRANDS:
            if b in name.lower() and b not in dom:
                flag(
                    1,
                    "Sender-domain mismatch",
                    f"Display name claims '{b}' but routes via {dom}",
                    30,
                )
                break
        if re.search(r"urgent|confidential|immediate", name, re.I):
            flag(
                5,
                "Suspicious display name",
                "Urgency/secrecy words inside the sender name",
                10,
            )
        _, di = url_issues("https://" + dom)
        if di:
            flag(1, "Spoofed sender domain", "; ".join(di), 20)
    if (
        rp
        and fh
        and rp.group(1).split("@")[-1].strip(" >")
        != fh["addr"].split("@")[-1].strip(" >")
    ):
        flag(
            1,
            "Reply-To mismatch",
            "Replies are routed to a different domain than the sender",
            20,
        )
    if re.search(r"^subject:\s*(fw|fwd):", text, re.I | re.M):
        flag(
            2,
            "Fake forwarded chain",
            "FW: subject on a thread you were never part of",
            8,
        )

    # --- Links ---
    links = []
    for u in dict.fromkeys(re.findall(r"(?:https?://|www\.)[^\s<>\"')]+", text)):
        host, iss = url_issues(u)
        links.append({"url": u, "host": host, "issues": iss, "risky": bool(iss)})
        if iss:
            score += min(15 * len(iss), 30)
    if any(l["risky"] for l in links):
        flags.append(
            {
                "id": 7,
                "title": "Suspicious link(s)",
                "detail": f"{sum(l['risky'] for l in links)} link(s) failed domain checks",
            }
        )
    if (
        re.search(r"(click|sign in|log in|verify).{0,40}(link|below|here)", low)
        and links
    ):
        flag(
            7,
            "Link-driven credential prompt",
            "Pushes you to a login page instead of manual navigation",
            10,
        )

    # --- psychology keywords---
    kw = []
    for trig, words in TRIGGERS.items():
        hit = [w for w in words if w in low]
        if hit:
            kw.append({"trigger": trig, "words": hit})
            score += min(6 * len(hit), 15)
    trigs = {k["trigger"] for k in kw}
    if "Secrecy / Bypass" in trigs:
        flag(
            5,
            "Urgent bypass request",
            "Demands secrecy or skipping normal procedure",
            20,
        )
    if "Sensitive info" in trigs:
        flag(
            6,
            "Request for sensitive info",
            "Asks for credentials, MFA codes or payment changes",
            15,
        )
    if "Urgency" in trigs and "Fear" in trigs:
        flag(
            7,
            "Alarmist activity alert",
            "Fear + deadline combination to cut rational thought",
            10,
        )

    # --- Attachments ---
    for ext in RISKY_EXT:
        if re.search(re.escape(ext) + r"\b", low) and re.search(
            r"attach|\.\w+\s*$|file", low
        ):
            flag(
                4, "Dangerous attachment", f"Uncommon/executable extension '{ext}'", 25
            )
            break
    if re.search(r"scan.{0,30}(qr|code)|qr code", low):
        flag(10, "QR code prompt", "Quishing: bypasses desktop URL filters", 20)
    if re.search(r"call.{0,30}\+?\d[\d\-\s()x]{6,}|1-800", low) and not links:
        flag(9, "Callback scam (TOAD)", "No link, only a phone number to call", 20)
    if (
        re.search(r"voicemail|voice message|video call|join the meeting|deepfake", low)
        and "Urgency" in trigs
    ):
        flag(
            11,
            "Possible deepfake follow-up",
            "Voice/video claim backed by urgent request; verify out-of-band",
            10,
        )

    # --- Browser-in-the-Browser (BitB) ---
    for pat in BITB_HINTS:
        if re.search(pat, low):
            flag(
                3,
                "Browser-in-the-Browser (BitB) risk",
                "Mentions of popups / SSO windows that mimic the browser UI",
                20,
            )
            break

    # --- MFA fatigue ---
    for pat in MFA_FATIGUE_HINTS:
        if re.search(pat, low):
            flag(
                8,
                "MFA fatigue / push bombing",
                "Repeated push prompts — attacker waits until you tap Approve",
                20,
            )
            break

    # --- Dangling DNS ---
    for prov in DANGLING_PROVIDERS:
        if prov in low:
            flag(
                12,
                "Dangling DNS / cloud takeover indicator",
                f"Mentions '{prov}' — legacy CNAMEs here are common takeover targets",
                20,
            )
            break

    # --- Vishing (voice phishing) ---
    if re.search(
        r"call\s+(this\s+)?number|call\s+our|call\s+support|call\s+us|vishing|voice\s+call",
        low,
    ) or re.search(r"live\s+call|verify\s+by\s+phone", low):
        flag(
            13,
            "Vishing / voice phishing",
            "Asks you to call a number — caller ID can be spoofed, verify through directory",
            15,
        )

    # --- Search Engine Phishing (SEO poisoning) ---
    if re.search(
        r"search\s+for\s+(us|our|the)|google\s+us|top\s+result|first\s+link\s+on|find\s+us\s+on|"
        r"click\s+the\s+ad|sponsored\s+link",
        low,
    ):
        flag(
            14,
            "Search Engine Phishing (SEO poisoning)",
            "Tells you to search for the brand — malicious lookalikes rank above the real site",
            15,
        )

    if re.search(r"dear (customer|user|member)|valued customer", low):
        flag(0, "Generic greeting", "No personalisation: mass phishing indicator", 5)

    score = min(score, 100)
    verdict = "Safe" if score < 25 else "Suspicious" if score < 55 else "Malicious"
    action = {
        "Safe": "Close: no threat indicators found",
        "Suspicious": "Warn user: Pause, Verify out-of-band, Report",
        "Malicious": "Block domain & escalate to the security team",
    }[verdict]

    if verdict != "Safe":
        if trigs:
            why.append(
                "It uses psychological triggers ("
                + ", ".join(sorted(trigs))
                + ") to rush you past logical checks."
            )
        if any(l["risky"] for l in links):
            why.append(
                "Links do not lead where they claim: the true root domain is not the brand it imitates."
            )
        if any(f["id"] == 1 for f in flags):
            why.append(
                "The sender identity cannot be trusted: display name, domain or Reply-To disagree."
            )
        if any(f["id"] in (5, 6) for f in flags):
            why.append(
                "It asks for secrecy, credentials or money movement: classic credential-theft / BEC behaviour."
            )
        if any(f["id"] in (4, 9, 10, 11, 13, 14) for f in flags):
            why.append(
                "It uses a vector that avoids link scanners (attachment, QR, phone call, voice or search)."
            )
        if any(f["id"] in (3, 8, 12) for f in flags):
            why.append(
                "It relies on advanced tricks (BitB popup, MFA fatigue or abandoned cloud CNAME) that bypass normal user instinct."
            )
        why.append(
            "Do not click or reply. Verify through a known directory number, then report; do not just delete."
        )
    else:
        why.append(
            "No sender mismatch, risky link or pressure tactic detected. Still verify unexpected requests."
        )

    return {
        "verdict": verdict,
        "score": score,
        "action": action,
        "links": links,
        "keywords": kw,
        "flags": flags,
        "why": why,
        "headers": build_header_report(text),
    }


@app.route("/")
def index():
    return send_from_directory(".", "index.html")


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    data = request.get_json(silent=True) or {}
    text = (data.get("text") or "").strip()
    if not text:
        return jsonify({"error": "Paste an email or message to analyze."}), 400
    return jsonify(analyze(text[:20000]))


if __name__ == "__main__":
    app.run(debug=True)
