# PHISHSENTRY

PHISHSENTRY is a Python-based email phishing scanner with a PyQt5 GUI.  
It pulls recent emails over IMAP, detects suspicious URLs/keywords, checks links against VirusTotal, assigns a risk score, and exports results to JSON/CSV.

---

## Features

- Fetches the latest **20 emails** from your inbox (IMAP)  
- Detects suspicious **URLs** and **phishing keywords**  
- Basic **attachment risk flagging** (by file extension)  
- **VirusTotal** URL checks with simple rate-limit handling  
- Export analysis to **JSON** or **CSV**  
- **Lightweight GUI** (PyQt5)

---

## Requirements

- Python **3.11**  
- Windows / macOS / Linux (VMs supported)  
- Email account with **IMAP** enabled  
- **VirusTotal** API key  
- Internet access  

---

## Quick Start (VM-friendly)

### 1) Clone the repo
```bash
git clone https://github.com/vivekjhingan/PHISHSENTRY.git
cd PHISHSENTRY/PHISHSENTRY
```
## 2) Create & activate a virtual environment

### Windows (PowerShell)
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```
If activation is blocked, allow scripts once:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```
**macOS / Linux**
```sh
python3 -m venv venv
source venv/bin/activate
```
### 3) Install dependencies

Create a file named `requirements.txt` (in the same folder as `mainproject.py`) with:

PyQt5>=5.15.10
requests>=2.31.0
chardet>=5.2.0

csharp
Copy
Edit

Then install the dependencies with:

```sh
pip install -r requirements.txt
```
### 4) Run the app
```sh
python mainproject.py
```
## Configuration

### Gmail (example)

1. **Enable IMAP**
   - Gmail → Settings → *See all settings* → **Forwarding and POP/IMAP** → Enable IMAP.

2. **Use an App Password**
   - Google Account → **Security** → enable **2-Step Verification** → **App passwords** → choose *Mail* → generate the 16-character password.

3. **Enter credentials in the app dialog:**
   - **Email:** your Gmail address  
   - **Password:** the App Password (not your normal password)  
   - **IMAP Server:** `imap.gmail.com`  

   *(For other providers, use their IMAP server. Example: Outlook/Office365 → `outlook.office365.com`)*

---

### VirusTotal

- Sign up at [VirusTotal](https://www.virustotal.com) and copy your API key from your profile.  
- Paste it into the **VirusTotal API Key** field when prompted.

---

## Project Structure

📁 PHISHSENTRY/  
└── 📁 PHISHSENTRY/  
   ├── 🖥️ mainproject.py        → PyQt5 GUI entry point  
   ├── 📧 emailret.py           → IMAP connect/fetch + safe decoding  
   ├── 🔍 phishing_detector.py  → URL detection, score, attachment checks  
   ├── 📊 report.py             → JSON/CSV exporters  
   └── 🧪 visual.py             → VirusTotal integration  


---

## Limitations

- **Latest 20 emails only** – analyzes up to 20 recent messages by design.  
- **Plain-text oriented** – complex HTML/inline content may be missed.  
- **Basic heuristics** – scoring and URL/attachment checks are simple (keyword/extension based).  
- **VirusTotal rate limits** – free API plans can throttle; the app retries briefly then skips.  
- **No OAuth flow** – uses username + (preferably) App Password; enterprise OAuth not implemented.  
- **No file uploads to VT** – attachments are not hashed/uploaded; only extensions are checked.  

---

## Recommendations

- Use App Passwords (Gmail) or provider-specific secure credentials; never hard-code secrets.  
- Refine rules over time (allow/deny domain lists, keyword sets) to reduce false positives.  
- Run in a VM and keep a dedicated project `venv` per environment.  
- Retain exports (CSV/JSON) for auditing; consider centralizing logs later.  
- Extend detection gradually: stronger HTML parsing, reputation feeds, hashing attachments, optional ML scoring.  

---

⚠️ **Note:** For educational and defensive security use only. Respect privacy and applicable laws when scanning emails.
