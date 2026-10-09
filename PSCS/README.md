# SentinelPass

**Password Strength Checker** | Project 1, Cyber Security Industrial Training Kit (DecodeLabs, Batch 2026)

![Python](https://img.shields.io/badge/Python-3.8%2B-blue) ![Flask](https://img.shields.io/badge/Flask-backend-black) ![License](https://img.shields.io/badge/use-educational-green)

A full-stack password strength checker with a Python (Flask) backend and an HTML/CSS/JavaScript frontend. It goes beyond a simple weak/medium/strong label: it estimates crack time from real entropy, generates cryptographically secure passwords, and checks whether a password has appeared in a known data breach, without ever sending the password anywhere.

![SentinelPass landing screen] ("D:\Internship\Decode-Labs\PSCS\screenshots\home.png")

## Table of contents

1. [Features](#features)
2. [Screenshots](#screenshots)
3. [Tech stack](#tech-stack)
4. [Getting started](#getting-started)
5. [How it works](#how-it-works)
6. [API](#api)
7. [Sample results](#sample-results)
8. [Privacy](#privacy)
9. [Known limitations](#known-limitations)
10. [Future improvements](#future-improvements)

## Features

| Feature | Description |
|---|---|
| Real-time strength scoring | Checks length, lowercase, uppercase, digits and symbols while you type, then classifies the password |
| Crack-time estimate | Calculates entropy from the character pool and length, then converts it to a readable time |
| Password generator | Uses Python's `secrets` module and guarantees at least one character from each class |
| Real breach check | Looks the password up in the HaveIBeenPwned database using k-anonymity |
| Password strength table | Example passwords scored live, with a toggle between password and passphrase examples |
| Educational content | Common bad practices and a short FAQ |

## Screenshots

| Strong password | Weak password |
|---|---|
| ![Strong]("D:\Internship\Decode-Labs\PSCS\screenshots\strong.png") | ![Weak] ("D:\Internship\Decode-Labs\PSCS\screenshots\weak.png") |

![Strength table]("D:\Internship\Decode-Labs\PSCS\screenshots\table.png")

## Tech stack

- **Backend:** Python 3, Flask
- **Frontend:** HTML, CSS, JavaScript (no frameworks)
- **External API:** [HaveIBeenPwned Pwned Passwords](https://haveibeenpwned.com/API/v3#PwnedPasswords) (free, no key required)

## Getting started

```bash
git clone https://github.com/YOUR-USERNAME/sentinelpass.git
cd sentinelpass
pip install flask requests
python app.py
```

Open http://127.0.0.1:5000 in your browser.

`index.html` must stay in the same folder as `app.py`, because Flask serves it from there. If `requests` is not installed, everything works except the breach check, which reports itself as unavailable.

## How it works

The scoring follows an **Input, Process, Output** model.

1. **Input:** the raw password string.
2. **Process:** one regular-expression scan per character class, plus the entropy calculation.
3. **Output:** a 0 to 100 score, a tier label and an estimated crack time.

### Scoring rules

| Condition | Effect |
|---|---|
| Length of 8 or more | +30 |
| Each character class present (lower, upper, digit, symbol) | +15 each |
| Length of 12 or more | +10 |
| Length under 8 | Partial credit: (length / 8) x 20 |
| Password is on the common-password list | Score capped at 15 |

Tiers: under 40 is **weak**, 40 to 74 is **medium**, 75 and above is **strong**.

### Entropy and crack time

```
entropy_bits = length x log2(pool_size)
seconds      = 2^entropy_bits / 10,000,000,000 / 2
```

The pool is 26 for lowercase, 26 for uppercase, 10 for digits and 14 for the symbol set. The estimate assumes an offline attack at about 10 billion guesses per second against a fast unsalted hash, and halves the search space for the average case.

### Breach check (k-anonymity)

1. The password is hashed with SHA-1 on your own machine.
2. Only the **first 5 characters** of the hash are sent to the HaveIBeenPwned API.
3. The API returns every hash suffix that starts with those 5 characters.
4. The match is confirmed locally, so neither the password nor the full hash is exposed.

## API

| Method | Endpoint | Body or query | Returns |
|---|---|---|---|
| GET | `/` | none | The web page |
| POST | `/api/check` | `{"password": "..."}` | length, character classes, score, label, entropy_bits, crack_time |
| GET | `/api/generate` | `?length=16` (8 to 64) | `{"password": "..."}` |
| POST | `/api/breach-check` | `{"password": "..."}` | `{"available": true, "breached": true, "count": 123}` or `{"available": false}` |

## Sample results

Taken from the running `/api/check` endpoint:

| Password | Entropy (bits) | Estimated crack time | Score | Tier |
|---|---|---|---|---|
| `123456` | 19.9 | Instantly | 15 | weak (common) |
| `password` | 37.6 | 10.4 seconds | 15 | weak (common) |
| `Hello123` | 47.6 | 3.0 hours | 75 | strong |
| `Tr0ub4dor&3` | 68.7 | 7.7 centuries | 90 | strong |
| `correct horse battery staple` | 149.0 | 1.1e+25 centuries | 70 | medium |
| `X9$kLm2#pQ7vRt!z` | 100.0 | 2.0e+10 centuries | 100 | strong |

## Privacy

- No password is stored, logged or written to disk.
- The only outbound request is the optional breach check, and it never carries the real password.
- No API keys, tokens or secrets are needed anywhere in the project.

## Known limitations

- The score rewards character variety more than entropy, so a short password such as `Hello123` can score Strong while a long all-lowercase passphrase scores only Medium.
- Only 20 very common passwords are blocked by name.
- The crack-time model uses one fixed attack speed. Against a slow hash such as bcrypt or Argon2 the real time would be much longer.
- The breach check needs internet access.

## Future improvements

- Weight the score by entropy and model multi-word passphrases properly.
- Check against a larger breached-password list and a dictionary.
- Add a Dockerfile and basic rate limiting on the API routes.
- Add more ways to check a password.

## Credits

Built as Project 1 of the DecodeLabs Cyber Security internship, 2026.
Author: S Fatima Manzoor
