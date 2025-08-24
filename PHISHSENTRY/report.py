# report.py

import json
import csv

def generate_report_json(emails, filepath):
    try:
        with open(filepath, 'w') as f:
            json.dump(emails, f, indent=4)
    except Exception as e:
        print(f"❌ Failed to save JSON report: {e}")

def generate_report_csv(emails, filepath):
    try:
        with open(filepath, mode='w', newline='') as file:
            writer = csv.writer(file)
            
            # Header
            writer.writerow(["From", "Subject", "Phishing Score", "URLs", "Attachments"])
            
            # Rows
            for email in emails:
                urls = ", ".join(email.get('urls', []))
                attachments = ", ".join(email.get('attachments', []))
                phishing_score = email.get('phishing_score', "N/A")
                writer.writerow([email.get('from', ''), email.get('subject', ''), phishing_score, urls, attachments])
    except Exception as e:
        print(f"❌ Failed to save CSV report: {e}")
