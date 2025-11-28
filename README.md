# githubpenit

Python utility that automates login attempts against iRZ web pages using Selenium with either Chromium or Internet Explorer drivers.

## Usage

1. Install dependencies: `pip install -r requirements.txt`.
2. Prepare credential sources:
   - Either a credentials file with `username;password` on each line,
   - or separate username and password files (one value per line) to test every combination.
3. Prepare a hosts file with `IP:Port` on each line.
4. Run the script:

```bash
python main.py --credential-file creds.txt --host-file hosts.txt --multiwindow 2 --browser chromium
```

To combine usernames and passwords from separate lists:

```bash
python main.py --user-file user.txt --password-file password.txt --host-file hosts.txt
```

If arguments are omitted, the script will prompt for them interactively. Successful logins are appended to `g.txt` as `ip:port:username:password` and progress is logged to the console with timestamps.
