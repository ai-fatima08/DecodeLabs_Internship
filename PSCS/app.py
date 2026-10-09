"""http://127.0.0.1:5000"""

import os
import re
import math
import string
import secrets
import hashlib
from flask import Flask, request, jsonify, send_from_directory

try:
    import requests
except ImportError:
    requests = None  # the breach check will just report itself as unavailable

app = Flask(__name__, static_folder=None)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

COMMON_PASSWORDS = {
    "123456",
    "password",
    "123456789",
    "12345678",
    "12345",
    "qwerty",
    "abc123",
    "password1",
    "111111",
    "123123",
    "admin",
    "letmein",
    "welcome",
    "monkey",
    "iloveyou",
    "dragon",
    "football",
    "master",
    "login",
    "princess",
}

SYMBOL_POOL = "!@#$%^&*()-_=+"


def estimate_crack_time(password: str) -> dict:
    """
    Rough Entropy-based crack time estimate.

    entropy (bits) = length * log2(character pool size)
    combinations    = 2 ** entropy
    seconds         = combinations / guesses_per_second / 2 (average case)

    10 billion guesses per second is a realistic number for an offline
    attack against a fast, unsalted hash on modern hardware.
    """
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += len(SYMBOL_POOL)

    length = len(password)
    if length == 0 or pool == 0:
        return {"entropy_bits": 0.0, "display": "instantly"}

    entropy_bits = length * math.log2(pool)
    combinations = 2**entropy_bits
    guesses_per_second = 1e10
    seconds = combinations / guesses_per_second / 2

    return {
        "entropy_bits": round(entropy_bits, 1),
        "display": humanize_seconds(seconds),
    }


def humanize_seconds(seconds: float) -> str:
    if seconds < 1:
        return "instantly"
    units = [
        ("century", 60 * 60 * 24 * 365 * 100),
        ("year", 60 * 60 * 24 * 365),
        ("day", 60 * 60 * 24),
        ("hour", 60 * 60),
        ("minute", 60),
        ("second", 1),
    ]
    for name, unit_seconds in units:
        if seconds >= unit_seconds:
            value = seconds / unit_seconds
            if value > 1_000_000:
                return f"{value:.1e} {name}s"
            return f"{value:.1f} {name}s"
    return "instantly"


def analyze_password(password: str) -> dict:
    """
    Input is the raw password string. Process is a single linear scan
    (regex, no nested loops) over the string for each character class,
    plus the entropy math. Output is a score with the evidence behind it.
    """
    length = len(password)

    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"[0-9]", password))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", password))
    is_long = length >= 12
    is_common = password.lower() in COMMON_PASSWORDS
    variety_count = sum([has_lower, has_upper, has_digit, has_symbol])
    crack = estimate_crack_time(password)

    score = 0
    if length >= 8:
        score += 30
        score += variety_count * 15
        if is_long:
            score += 10
    elif length > 0:
        score += round((length / 8) * 20)

    if is_common:
        score = min(score, 15)

    score = max(0, min(100, score))

    if length == 0:
        label = "empty"
    elif score < 40:
        label = "weak"
    elif score < 75:
        label = "medium"
    else:
        label = "strong"

    return {
        "length": length,
        "has_lower": has_lower,
        "has_upper": has_upper,
        "has_digit": has_digit,
        "has_symbol": has_symbol,
        "is_long": is_long,
        "is_common": is_common,
        "score": score,
        "label": label,
        "entropy_bits": crack["entropy_bits"],
        "crack_time": crack["display"],
    }


def generate_password(length: int = 16) -> str:
    length = max(8, min(length, 64))
    pools = [string.ascii_lowercase, string.ascii_uppercase, string.digits, SYMBOL_POOL]

    # guarantee at least one character from every pool
    password_chars = [secrets.choice(pool) for pool in pools]

    all_chars = "".join(pools)
    password_chars += [
        secrets.choice(all_chars) for _ in range(length - len(password_chars))
    ]

    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars)


def check_have_i_been_pwned(password: str):
    """
    Only the first 5 characters of the SHA-1 hash are sent to the API.
    The full password and even the full hash never leave this machine.
    Returns the number of times the password has shown up in known
    breaches or None if the check couldn't be completed.
    """
    if requests is None or not password:
        return None
    try:
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        resp = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=4)
        if resp.status_code != 200:
            return None
        for line in resp.text.splitlines():
            hash_suffix, count = line.split(":")
            if hash_suffix == suffix:
                return int(count)
        return 0
    except Exception:
        return None


@app.route("/")
def home():
    return send_from_directory(BASE_DIR, "index.html")


@app.route("/api/check", methods=["POST"])
def check_password():
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    return jsonify(analyze_password(password))


@app.route("/api/generate")
def generate():
    length = request.args.get("length", default=16, type=int)
    return jsonify({"password": generate_password(length)})


@app.route("/api/breach-check", methods=["POST"])
def breach_check():
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    count = check_have_i_been_pwned(password)
    if count is None:
        return jsonify({"available": False})
    return jsonify({"available": True, "breached": count > 0, "count": count})


if __name__ == "__main__":
    app.run(debug=True)
