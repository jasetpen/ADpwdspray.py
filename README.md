# ADpwdsprayer.py

AD password sprayer relying on crackmapexec with advanced functionality and safety nets.


## Features

- Sprays **one password per interval** across all usernames
- Detects and logs:
  - Valid credentials (green)
  - Locked-out accounts (red)
  - Disabled or expired accounts (purple)
- Safety nets:
  - In case of any account getting locked out the script terminates
  - Optional **bait user spraying** with wrong password to detect lockout thresholds before affecting real users
- Logs:
  - All CME output to a file
  - Valid credentials to `valid_credentials.txt`
 
## Screenshots

![image](https://github.com/user-attachments/assets/910ae135-84b0-493a-ac77-ec00d56552ab)
![image](https://github.com/user-attachments/assets/7eb59417-4723-45a1-a86b-d8d17f45dd9e)


## Requirements

- Python 3
- [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) installed and in your `$PATH`


# Installation

git clone https://github.com/jasetpen/ADpwdsprayer.py.git


# Usage

`python3 ADpwdsprayer.py --dc-ip <DC_IP> -u <users.txt> -p <passwords.txt> -i <interval> -f <logfile> [-bu] <bait user>`

| Argument           | Required | Description                                                                                     |
|--------------------|----------|-------------------------------------------------------------------------------------------------|
| `--dc-ip`          | Yes      | IP address of the Domain Controller (target for CME)                                            |
| `-u`, `--users`    | Yes      | Path to file with one username per line                                                         |
| `-p`, `--passwords`| Yes      | Path to file with one password per line                                                         |
| `-i`, `--interval` | Yes      | Interval in minutes between each password spray                                                |
| `-f`, `--outfile`  | Yes      | File to append all CrackMapExec output                                                          |
| `-bu`, `--bait-user` | No     | User to use as lockout bait – sprayed once per interval with a wrong password to detect lockout |

--bait-user also has to be in the users list (at the top) for it to get sprayed twice
