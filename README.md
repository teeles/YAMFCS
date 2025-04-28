# YAMFCS - Yet Another macOS Forensic Collection Script

YAMFCS collects a load of  digital forensic artifact from a macOS device to help with cyberseucrity incident response investigtaions. Once the collection is all done you can copy the ZIP to the forensics server and run your analysis. A lot of the data is parsed on the endpoint to save time!

## Features

- Simple Bash script — no dependencies
- Runs standalone or via JAMF policies
- Focused on forensic artifacts.
- Supports Safari, Chrome, Firefox data collection. 
- Designed for compatibility across macOS versions.
- "grab" function allows you to add in a file or directory to collect. 

## Output Structure

All logs and artifacts are saved in `/tmp/logs`, and then zipped to the desktop as:

```
TMFDCT_<HOSTNAME>_<TIMESTAMP>.zip
```

## FULL DISK ACCESS - A WARNING FROM THE PAST

The ONLY way to get this script to work is to grant full disk access to Terminal. This is not a security wise thing to do, and shoudl be reversed staright after. 

1. Get yourself some Admin, you will need this anyways. 
2. Open Settings.
3. Navigate to "Privacy & Security"
4. Nagivate to "Full Disk Access"
5. If you see "Terminal" then go ahead and use the toggle to turn it on, then you are done, move on. 
6. If you dont see "Terminal" in the list then you need to add it manualy
7. Unlock to allow changes, this is the small padlock and + at the bottom of the window.
8. In the popup window go to "Applications/Utilities/" and pick Terminal.app
9. Toglle that on, and close the padlock.
10. NOW YOU ARE ALL READY! 

# Usage

```bash
sudo ./yamfcs.sh 
```
or with grab...
```bash
sudo ./yamfcs.sh -- grab Users/myuser/desktop/supercool.txt
```

Must be run as root for complete access. 

## Collected Artifacts (Function Reference)

| Function           | What it Collects                                                                 |
|--------------------|----------------------------------------------------------------------------------|
| `browser_safari`   | Safari history, bookmarks, downloads, notification permissions                   |
| `browser_chrome`   | Chrome history, downloads, cookies, preferences, installed extensions (zipped)   |
| `browser_firefox`  | Firefox history, downloads, extensions                                           |
| `collect_logs`     | System logs, user logs, `/var/log`, audit logs                                   |
| `shellhistory`     | User `.bash*`, `.zsh*`, `fish` configs, `/etc/z*` and `/etc/profile`             |
| `system_profile`   | Massive data grab — see detailed breakdown below                                |
| `collect_tcc`      | System and user TCC.db copies + parsed CSV outputs                               |
| `sdiagnose`        | Optional macOS diagnostic bundle (if sysdiagnose is enabled)                     |
| `compress_logs`    | Zips everything in `/tmp/logs` to a named file on Desktop                        |

## system_profile Breakdown (the really big function, it needs its own table)

| Subsection                      | Description                                                                 |
|----------------------------------|-----------------------------------------------------------------------------|
| `.ssh` & `sudoers`              | System & user `.ssh`, `sudoers`, `hosts`, `resolv.conf`                     |
| System Summary                  | Hostname, logged-in user, macOS version, XProtect/MRT versions             |
| Installed Applications          | List of `/Applications/*.app` and their MD5 hashes                         |
| Install History                 | Converted plist to JSON, parsed into CSV (Process, Date, Identifiers, etc.)|
| Running Processes               | `ps` output with PID, binary path, and suspicious path notes               |
| Network Interfaces              | Interface name, IP address, MAC address, status                            |
| Environment Variables           | `env` key=value format                                                     |
| Security Settings               | Gatekeeper, SIP, Airdrop, Remote Login, Firewall, Last login, etc.         |
| XProtect Artifacts              | XProtect `.yara` and version `.plist` copied                               |
| Installed Users                 | Users with UID ≥ 500, home directory, and groups                           |


## Credit
Based on the original SHOWMETHLOGS but with added teeth.
