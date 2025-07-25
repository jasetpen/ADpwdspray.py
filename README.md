# ADpwdspray.py

AD password sprayer relying on crackmapexec with advanced functionality and safety nets.


## Features

- Sprays **a one password per defined number of attempts per interval** across all usernames
- Detects and logs:
  - Valid credentials (green)
  - Locked-out accounts (red)
  - Disabled or expired accounts (purple)
  - Connection issues (red)
- Safety nets:
  - In case of any account getting locked out the script terminates
  - In case of DC timeout it retries the script 5 times with 3 minute wait intervals before quitting
  - Optional **bait user spraying** with wrong password to detect lockout thresholds before affecting real users
- Logs:
  - All CME output to a file
  - Valid credentials to `valid_credentials.txt`

 
## Screenshots

<img width="864" height="246" alt="image" src="https://github.com/user-attachments/assets/88314213-efb0-40e4-b5bd-5f7e3b7eee26" />

Example of exceeding password policy limits, that is where bait user comes in handy.


## Requirements

- Python 3
- [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) installed and in your `$PATH`


## Installation

git clone https://github.com/jasetpen/ADpwdspray.py.git


## Usage

`ADpwdspray.py [-h] --dc-ip DC_IP -u USERS -p PASSWORDS -i INTERVAL [-a ATTEMPTS] [-bu BAIT_USER] -l LOGFILE`

| Argument           | Required | Description                                                                                     |
|--------------------|----------|-------------------------------------------------------------------------------------------------|
| `--dc-ip`          | Yes      | IP address of the Domain Controller (target for CME)                                            |
| `-u`, `--users`    | Yes      | Path to file with one username per line                                                         |
| `-p`, `--passwords`| Yes      | Path to file with one password per line                                                         |
| `-i`, `--interval` | Yes      | Interval in minutes between each password spray                                                |
| `-a`, `--attempts` | No      | Attempts per interval, default 1                                                |
| `-bu`, `--bait-user` | No     | User to use as lockout bait – sprayed once per interval with a wrong password to detect lockout |
| `-l`, `--log file`  | Yes      | File to append all CrackMapExec output                                                          |

--bait-user also has to be in the users list (at the top) for it to get sprayed twice
