# PHISHSENTRY

PHISHSENTRY is a Python-based email phishing scanner with a **PyQt5 GUI**. It pulls recent emails over IMAP, detects suspicious URLs/keywords, checks links against **VirusTotal**, assigns a risk score, and exports results to **JSON/CSV**.

---

## Features
- Fetches the **latest 20 emails** from your inbox (IMAP)
- Detects **suspicious URLs** and **phishing keywords**
- Basic **attachment risk** flagging (by file extension)
- **VirusTotal** URL checks with simple rate-limit handling
- **Export** analysis to JSON or CSV
- Lightweight **GUI** (PyQt5)

---

## Requirements
- **Python 3.11**
- Windows / macOS / Linux (VMs supported)
- Email account with **IMAP** enabled
- **VirusTotal API key**
- Internet access

---

## Quick Start (VM-friendly)

> **Tip:** Use a **virtual environment (venv)** inside your VM to isolate dependencies.

### 1) Clone the repo
```bash
git clone https://github.com/<your-username>/PHISHSENTRY.git
cd PHISHSENTRY/PHISHSENTRY
2) Create & activate a virtual environment
Windows (PowerShell / VS Code Terminal)

powershell
Copy
Edit
python -m venv venv
.\venv\Scripts\Activate.ps1
If activation is blocked, allow scripts once:

powershell
Copy
Edit
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
macOS / Linux

bash
Copy
Edit
python3 -m venv venv
source venv/bin/activate
3) Install dependencies
Create a requirements.txt (in the same folder as mainproject.py) with:

text
Copy
Edit
PyQt5>=5.15.10
requests>=2.31.0
chardet>=5.2.0
Install:

bash
Copy
Edit
pip install -r requirements.txt
4) Run the app
bash
Copy
Edit
python mainproject.py
Configuration
Gmail (example)
Enable IMAP
Gmail → Settings → See all settings → Forwarding and POP/IMAP → Enable IMAP.

Use an App Password
Google Account → Security → enable 2-Step Verification → App passwords → choose Mail → generate the 16-character password.

In the app’s credentials dialog, enter:

Email: your Gmail address

Password: the App Password (not your normal password)

IMAP Server: imap.gmail.com

For other providers, use their IMAP server (e.g., Outlook/Office365: outlook.office365.com).

VirusTotal
Sign up at virustotal.com and copy your API key from your profile.

Paste it into the VirusTotal API Key field when prompted.

Project Structure
bash
Copy
Edit
PHISHSENTRY/
└─ PHISHSENTRY/
   ├─ mainproject.py          # PyQt5 GUI entry point
   ├─ emailret.py             # IMAP connect/fetch + safe decoding
   ├─ phishing_detector.py    # URL detection, score, attachment checks
   ├─ report.py               # JSON/CSV exporters
   └─ visual.py               # VirusTotal integration
Limitations
Latest 20 emails only: The app fetches and analyzes up to 20 recent messages by design.

Plain-text oriented: HTML emails are handled superficially; complex HTML/inline content may be missed.

Basic heuristics: Phishing score and URL/attachment checks are simple (keyword + extension based).

VirusTotal rate limits: Free API plans can throttle; the app retries briefly and then skips the URL.

No OAuth flow: Uses username + (preferably) App Password; enterprise OAuth not implemented.

No file uploads to VT: Attachments are not hashed/uploaded; only extensions are checked.

Recommendations
Use App Passwords (Gmail) or provider-specific secure credentials; never hard-code secrets.

Refine rules over time: maintain allow/deny lists for domains and adjust keyword sets to reduce false positives.

Run in a VM and keep a dedicated project venv per environment.

Retain exports (CSV/JSON) for auditing; consider centralizing logs later.

Extend detection gradually: stronger HTML parsing, reputation feeds, hashing attachments, optional ML scoring.

For educational and defensive security use only. Respect privacy and applicable laws when scanning emails.
