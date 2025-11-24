# githubpenit

Python utility that automates login attempts against iRZ web pages using Selenium with either Chromium or Internet Explorer drivers.

## Usage

1. Install dependencies: `pip install -r requirements.txt`.
2. Prepare two text files:
   - Credentials file with `username;password` on each line.
   - Hosts file with `IP:Port` on each line.
3. Run the script:

```bash
python main.py --credential-file creds.txt --host-file hosts.txt --multiwindow 2 --browser chromium
```

If arguments are omitted, the script will prompt for them interactively. Successful logins are appended to `g.txt` as `ip:port:username:password` and progress is logged to the console with timestamps.
