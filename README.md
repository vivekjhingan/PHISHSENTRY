# PHISHSENTRY

A lightweight, PyQt5-based email phishing scanner. Pulls recent emails over IMAP, detects suspicious URLs/keywords, checks links against VirusTotal, assigns a risk score, and exports results to JSON/CSV.

<p align="left">
  <a href="https://www.python.org/downloads/release/python-3110/"><img alt="Python 3.11" src="https://img.shields.io/badge/python-3.11+-blue.svg"></a>
  <img alt="Platforms" src="https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-informational">
  <a href="https://vscode.dev/github/vivekjhingan/PHISHSENTRY"><img alt="Open in VS Code" src="https://img.shields.io/badge/Open%20in-VS%20Code-007acc"></a>
</p>

---

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
  - [Gmail (example)](#gmail-example)
  - [VirusTotal](#virustotal)
- [Run & Debug with VS Code](#run--debug-with-vs-code)
  - [Recommended Extensions](#recommended-extensions)
  - [.vscode snippets](#vscode-snippets)
- [Project Structure](#project-structure)
- [Limitations](#limitations)
- [Recommendations](#recommendations)
- [Troubleshooting](#troubleshooting)
- [Security & Privacy](#security--privacy)

---

## Features

- Fetches the latest **20** emails from your inbox (IMAP)  
- Detects suspicious **URLs** and **phishing keywords**  
- Basic **attachment** risk flagging (by file extension)  
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

## Quick Start

> **Repo layout note**: the app’s entry point is `PHISHSENTRY/PHISHSENTRY/mainproject.py`.

### 1) Clone

```bash
git clone https://github.com/vivekjhingan/PHISHSENTRY.git
cd PHISHSENTRY/PHISHSENTRY
