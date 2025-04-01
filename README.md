# LimeSurvey 6.6.4 Authenticated RCE Exploit

A Python-based exploit targeting LimeSurvey version 6.6.4 that achieves **authenticated remote code execution (RCE)** by uploading and activating a malicious plugin.

## 📋 Requirements

- Python 3.x
- Dependencies: `termcolor`, `pyfiglet`, `requests`

Install dependencies:
```bash
pip install -r requirements.txt
```

## ⚙️ Usage

```bash
python3 -t http://example.com -u user -p password123
```

### Arguments:

- `-t`: Target base URL.
- `-u`: Valid LimeSurvey username.
- `-p`: Corresponding password.

## 📁 Required Files:

- `config.xml`: Plugin configuration file.
- `revshell.php`: Reverse shell payload.

## Disclaimer

This script is intended for educational purposes and authorized penetration testing only. Unauthorized use of this script is prohibited and may be illegal.
