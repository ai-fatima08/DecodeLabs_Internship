"""
SCRAMBLE (AES)
DecodeLabs Cyber Security Internship Project 2

Caesar cipher only has 25 possible keys a computer breaks it instantly.
This version replaces it with real, industry-standard encryption, and lets
the user pick how strong a key they want:

    AES-128 / AES-192 / AES-256, all in GCM mode (Galois/Counter Mode)
    Key derived from a user password via PBKDF2-HMAC-SHA256 (200,000 rounds)

Why I have choose this:
- Key size choice -> AES-128, AES-192 and AES-256 differ only in key length
                      (16 / 24 / 32 bytes) and number of internal rounds
                      (10 / 12 / 14). All three are considered secure today;
                      AES-256 just has a larger safety margin for the future.
- GCM mode        -> "authenticated encryption". It doesn't just hide the
                      message, it also detects if the ciphertext was
                      tampered with or the wrong password was used.
- PBKDF2          -> humans pick weak, short, guessable passwords. Running
                      the password through 200,000 rounds of a hash function
                      before using it as an AES key makes brute-forcing the
                      password itself much slower for an attacker.

Output format (all base64-encoded together as one blob):
    [ 1-byte key-size marker ] + [ 16-byte salt ] + [ 12-byte nonce ] + [ ciphertext + 16-byte auth tag ]

The key-size marker means decryption doesn't need the user to remember or
re-select which key size they originally encrypted with.

Setup:
    pip install flask flask-cors cryptography
    python app.py
Server starts on http://127.0.0.1:5000
"""

import os
import base64

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

app = Flask(__name__)
CORS(app)

SALT_SIZE = 16  # bytes, unique per encryption
NONCE_SIZE = 12  # bytes, required for AES-GCM
PBKDF2_ITERATIONS = 200_000
KDF_LABEL = "PBKDF2-HMAC-SHA256"

# key size in bits -> derived key length in bytes
# (AES-128 = 16 bytes, AES-192 = 24 bytes, AES-256 = 32 bytes)
KEY_SIZES = {128: 16, 192: 24, 256: 32}

# One extra byte on the front of the blob records which key size was used,
# so the decrypt panel doesn't need the user to also remember/re-pick it.
SIZE_MARKER = {128: 1, 192: 2, 256: 3}
MARKER_TO_SIZE = {v: k for k, v in SIZE_MARKER.items()}


@app.route("/")
def index():
    return send_from_directory(
        ".", "index.html"
    )

def derive_key(password: str, salt: bytes, key_bits: int) -> bytes:
    """Turn a human password into a proper AES key of the chosen size."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZES[key_bits],
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_text(plaintext: str, password: str, key_bits: int) -> str:
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt, key_bits)

    aesgcm = AESGCM(key)
    # AESGCM.encrypt() returns ciphertext with the 16-byte auth tag appended
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)

    marker = bytes([SIZE_MARKER[key_bits]])
    blob = marker + salt + nonce + ciphertext
    return base64.b64encode(blob).decode("utf-8")


def decrypt_text(blob_b64: str, password: str) -> str:
    blob = base64.b64decode(blob_b64)
    if len(blob) < 1 + SALT_SIZE + NONCE_SIZE + 16:
        raise ValueError("Ciphertext is too short to be valid.")

    marker = blob[0]
    key_bits = MARKER_TO_SIZE.get(marker)
    if key_bits is None:
        raise ValueError("Unrecognized key-size marker in ciphertext.")

    offset = 1
    salt = blob[offset : offset + SALT_SIZE]
    offset += SALT_SIZE
    nonce = blob[offset : offset + NONCE_SIZE]
    offset += NONCE_SIZE
    ciphertext = blob[offset:]

    key = derive_key(password, salt, key_bits)
    aesgcm = AESGCM(key)
    # Raises InvalidTag if the password is wrong OR the data was tampered with
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8"), key_bits


def validate_payload(data, require_key_size=False):
    if not data:
        return "Request body must be JSON."
    text = data.get("text", "")
    password = data.get("password", "")

    if not isinstance(text, str) or text == "":
        return "Field 'text' is required and must be a non-empty string."
    if not isinstance(password, str) or password == "":
        return "Field 'password' is required and must be a non-empty string."

    if require_key_size:
        key_size = data.get("key_size")
        if key_size not in (128, 192, 256):
            return "Field 'key_size' must be 128, 192, or 256."
    return None


@app.route("/api/encrypt", methods=["POST"])
def encrypt():
    data = request.get_json(silent=True)
    error = validate_payload(data, require_key_size=True)
    if error:
        return jsonify({"error": error}), 400

    text = data["text"]
    password = data["password"]
    key_bits = int(data["key_size"])

    try:
        output = encrypt_text(text, password, key_bits)
    except Exception:
        return jsonify({"error": "Encryption failed. Please try again."}), 500

    return jsonify(
        {
            "output": output,
            "algorithm": f"AES-{key_bits}-GCM",
            "key_size": key_bits,
            "key_derivation": KDF_LABEL,
            "iterations": PBKDF2_ITERATIONS,
        }
    )


@app.route("/api/decrypt", methods=["POST"])
def decrypt():
    data = request.get_json(silent=True)
    error = validate_payload(data, require_key_size=False)
    if error:
        return jsonify({"error": error}), 400

    text = data["text"]
    password = data["password"]

    try:
        output, key_bits = decrypt_text(text, password)
    except (InvalidTag, ValueError, base64.binascii.Error, Exception):
        # Wrong password, corrupted ciphertext, and malformed base64 all
        # collapse to the same message on purpose — telling an attacker
        # *which* one failed is itself information leakage.
        return (
            jsonify(
                {"error": "Decryption failed. Wrong password or corrupted ciphertext."}
            ),
            400,
        )

    return jsonify(
        {"output": output, "key_size": key_bits, "algorithm": f"AES-{key_bits}-GCM"}
    )


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "online", "service": "SCRAMBLE API (AES edition)"})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
