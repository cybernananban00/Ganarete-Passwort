#!/usr/bin/env python3
"""
SAFE CLI SECURITY TOOLKIT
-------------------------------------------------
A legal, educational command‑line tool inspired by
ASCII‑banner style utilities. It includes:
  1) Password strength checker
  2) Strong password generator
  3) String hasher (MD5/SHA1/SHA256/SHA512) with optional salt
  4) Mock login simulator (local only) with rate‑limiting demo

No external network activity. Everything runs locally.
Python 3.8+; standard library only.

Author: You + ChatGPT
License: MIT
"""

import os
import sys
import time
import math
import json
import hashlib
import secrets
import string
import getpass
from dataclasses import dataclass

# ------------------------ Styling -------------------------
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
WHITE = "\033[37m"

SPINNER_FRAMES = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]

BANNER = f"""
{RED}{BOLD}  _____       __          _____       __ _ _   _ _   _    {RESET}
{RED}{BOLD} / ____|     / _|        / ____|     / _(_) | (_) | | |   {RESET}
{RED}{BOLD}| (___   ___| |_ ___ _ _| (___  _ __| |_ _| |_ _| |_| |__ {RESET}
{RED}{BOLD} \___ \ / _ \  _/ _ \ '__\___ \| '__|  _| | __| | __| '_ \{RESET}
{RED}{BOLD} ____) |  __/ ||  __/ |  ____) | |  | | | | |_| | |_| | | |{RESET}
{RED}{BOLD}|_____/ \___|_| \___|_| |_____/|_|  |_| |_|\__|_|\__|_| |_|{RESET}
{DIM}          Safe, local, educational CLI toolkit{RESET}
"""

MENU = f"""
{CYAN}{BOLD}Select an option:{RESET}
  [1] Password strength checker
  [2] Strong password generator
  [3] Hash a string (MD5/SHA1/SHA256/SHA512)
  [4] Mock login simulator (rate‑limit demo)
  [0] Exit
"""

# ------------------- Utility Functions --------------------

def clear():
    try:
        os.system('cls' if os.name == 'nt' else 'clear')
    except Exception:
        pass

def pause(msg="Press Enter to continue..."):
    try:
        input(DIM + msg + RESET)
    except KeyboardInterrupt:
        print()


def spin_task(label: str, seconds: float = 1.2):
    """Tiny spinner animation."""
    start = time.time()
    i = 0
    while time.time() - start < seconds:
        sys.stdout.write(f"\r{DIM}{label} {SPINNER_FRAMES[i % len(SPINNER_FRAMES)]}{RESET}")
        sys.stdout.flush()
        time.sleep(0.06)
        i += 1
    sys.stdout.write("\r" + " " * (len(label) + 4) + "\r")

# ---------------- Password Strength Checker ---------------

@dataclass
class StrengthReport:
    score: int  # 0..100
    verdict: str
    notes: list
    entropy_bits: float
    est_crack_time: str


def password_strength(pw: str) -> StrengthReport:
    notes = []
    length = len(pw)
    sets = {
        'lower': any(c.islower() for c in pw),
        'upper': any(c.isupper() for c in pw),
        'digits': any(c.isdigit() for c in pw),
        'symbols': any(c in string.punctuation for c in pw),
        'spaces': any(c.isspace() for c in pw)
    }

    pool = 0
    pool += 26 if sets['lower'] else 0
    pool += 26 if sets['upper'] else 0
    pool += 10 if sets['digits'] else 0
    pool += len(string.punctuation) if sets['symbols'] else 0
    pool += 1 if sets['spaces'] else 0
    pool = max(pool, 1)

    # Shannon-ish estimate of brute-force entropy (bits)
    entropy = length * math.log2(pool)

    # Score (0..100)
    score = 0
    score += min(40, length * 3)  # up to 40 from length
    score += (10 if sets['lower'] else 0)
    score += (10 if sets['upper'] else 0)
    score += (10 if sets['digits'] else 0)
    score += (15 if sets['symbols'] else 0)
    score += (5 if sets['spaces'] else 0)

    # common patterns
    if pw.lower() in {"password","admin","qwerty","letmein","welcome","iloveyou"}:
        notes.append("Looks like a common password; avoid dictionary words.")
        score -= 35

    if pw.isdigit() and length < 10:
        notes.append("All digits and short length – very weak.")
        score -= 20

    # Repetition penalty
    if length > 1 and len(set(pw)) <= max(1, length // 3):
        notes.append("Too much repetition; increase variety.")
        score -= 15

    score = max(0, min(100, score))

    # Rough time to crack (offline aggressive 1e10 guesses/sec)
    guesses = 2 ** entropy
    gps = 1e10
    seconds = guesses / gps

    def human_time(s: float) -> str:
        if s < 1:
            return "<1 second"
        units = [
            (60, "seconds"),
            (60, "minutes"),
            (24, "hours"),
            (365, "days"),
            (1000, "years"),
        ]
        value = s
        names = ["seconds","minutes","hours","days","years","millennia"]
        i = 0
        for k, _ in units:
            if value < k:
                break
            value /= k
            i += 1
        return f"{value:.2f} {names[i]}"

    t = human_time(seconds)

    if score >= 85:
        verdict = "EXCELLENT"
    elif score >= 70:
        verdict = "STRONG"
    elif score >= 50:
        verdict = "FAIR"
    else:
        verdict = "WEAK"

    if length < 12:
        notes.append("Use at least 12–16 characters.")
    if not sets['symbols']:
        notes.append("Add symbols to increase search space.")
    if not sets['upper']:
        notes.append("Add uppercase letters.")
    if not sets['digits']:
        notes.append("Include numbers.")

    return StrengthReport(score=score, verdict=verdict, notes=notes, entropy_bits=entropy, est_crack_time=t)


def handle_strength_checker():
    clear()
    print(BANNER)
    print(f"{YELLOW}{BOLD}Password Strength Checker{RESET}\n")
    pw = getpass.getpass("Enter a password to evaluate (input hidden): ")
    spin_task("Analyzing")
    report = password_strength(pw)

    bar_len = 30
    filled = int(report.score / 100 * bar_len)
    bar = f"[{GREEN}{'█'*filled}{RESET}{DIM}{'░'*(bar_len-filled)}{RESET}]"
    print(f"Score: {report.score}/100 {bar}  → {BOLD}{report.verdict}{RESET}")
    print(f"Entropy estimate: {report.entropy_bits:.2f} bits")
    print(f"Estimated brute‑force time (very rough): {report.est_crack_time}")
    if report.notes:
        print(f"\nTips:")
        for n in report.notes:
            print(f"  • {n}")
    print()
    pause()

# ---------------- Password Generator ----------------------

def generate_password(length=16, use_upper=True, use_lower=True, use_digits=True, use_symbols=True) -> str:
    pools = []
    if use_lower:
        pools.append(string.ascii_lowercase)
    if use_upper:
        pools.append(string.ascii_uppercase)
    if use_digits:
        pools.append(string.digits)
    if use_symbols:
        pools.append("!@#$%^&*()-_=+[]{};:,.?/\\|~")

    if not pools:
        pools = [string.ascii_letters]

    # Ensure at least one char from each selected class
    chars = [secrets.choice(p) for p in pools]
    allpool = ''.join(pools)
    chars += [secrets.choice(allpool) for _ in range(max(0, length - len(chars)))]
    secrets.SystemRandom().shuffle(chars)
    return ''.join(chars)


def handle_password_generator():
    clear()
    print(BANNER)
    print(f"{YELLOW}{BOLD}Strong Password Generator{RESET}\n")
    try:
        length = int(input("Desired length (default 16): ") or 16)
    except ValueError:
        length = 16
    length = max(8, min(128, length))

    def yn(prompt, default=True):
        raw = input(f"{prompt} [{'Y/n' if default else 'y/N'}]: ")
        if not raw.strip():
            return default
        return raw.strip().lower().startswith('y')

    use_upper = yn("Include UPPERCASE?", True)
    use_lower = yn("Include lowercase?", True)
    use_digits = yn("Include digits?", True)
    use_symbols = yn("Include symbols?", True)

    spin_task("Generating")
    pw = generate_password(length, use_upper, use_lower, use_digits, use_symbols)
    print(f"\nGenerated password:\n{BOLD}{GREEN}{pw}{RESET}\n")

    if yn("Save to file?", False):
        path = input("File path (default passwords.txt): ") or "passwords.txt"
        with open(path, 'a', encoding='utf-8') as f:
            f.write(pw + "\n")
        print(f"Saved to {path}")
    print()
    pause()

# ---------------- String Hasher ----------------------------

def handle_hasher():
    clear()
    print(BANNER)
    print(f"{YELLOW}{BOLD}String Hasher{RESET}\n")
    text = getpass.getpass("Enter string to hash (input hidden): ")
    algo = (input("Algorithm [md5|sha1|sha256|sha512] (default sha256): ") or "sha256").lower()
    if algo not in {"md5","sha1","sha256","sha512"}:
        algo = "sha256"
    salt = input("Optional salt (press Enter to skip): ")

    spin_task("Hashing")
    data = (salt + text).encode('utf-8') if salt else text.encode('utf-8')
    h = getattr(hashlib, algo)(data).hexdigest()

    print(f"Algorithm : {algo}")
    if salt:
        print(f"Salt      : {salt}")
    print(f"Hash ({len(h)} hex chars):\n{BOLD}{MAGENTA}{h}{RESET}\n")

    if input("Save to file? [y/N]: ").strip().lower().startswith('y'):
        path = input("File path (default hashes.txt): ") or "hashes.txt"
        with open(path, 'a', encoding='utf-8') as f:
            payload = {"algo": algo, "salt": salt, "hash": h}
            f.write(json.dumps(payload) + "\n")
        print(f"Saved to {path}")
    print()
    pause()

# --------------- Mock Login Simulator ---------------------

def handle_login_sim():
    clear()
    print(BANNER)
    print(f"{YELLOW}{BOLD}Mock Login Simulator (Local){RESET}\n")
    print(DIM + "Demonstrates rate limiting and lockouts WITHOUT contacting any real service." + RESET)

    user = input("Choose a username: ") or "user"
    real_pw = getpass.getpass("Set a secret password (input hidden): ")
    max_attempts = 5
    cooldown = 5  # seconds after lockout

    attempts = 0
    while True:
        print()
        guess = getpass.getpass(f"[{user}] Enter password: ")
        attempts += 1
        if guess == real_pw:
            print(GREEN + BOLD + "✅ Access granted (local demo)." + RESET)
            break
        else:
            left = max_attempts - attempts
            print(RED + "❌ Incorrect password." + RESET)
            if left > 0:
                print(f"Attempts remaining: {left}")
            else:
                print(YELLOW + "Too many attempts. Rate limiting..." + RESET)
                for i in range(cooldown, 0, -1):
                    sys.stdout.write(f"\rRetry enabled in {i} s   ")
                    sys.stdout.flush()
                    time.sleep(1)
                print("\rYou can try again now.     ")
                attempts = 0
    print()
    pause()

# --------------------------- Main -------------------------

def main():
    while True:
        clear()
        print(BANNER)
        print(MENU)
        choice = input(f"{BOLD}> {RESET}").strip()
        if choice == '1':
            handle_strength_checker()
        elif choice == '2':
            handle_password_generator()
        elif choice == '3':
            handle_hasher()
        elif choice == '4':
            handle_login_sim()
        elif choice == '0':
            print("Goodbye! 👋")
            break
        else:
            print("Invalid choice. Try again.")
            time.sleep(1.0)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted. Bye!")
