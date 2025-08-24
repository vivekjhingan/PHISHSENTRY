# phishing_detector.py

import re

def detect_suspicious_urls(email_body):
    # Example simple URL detector
    urls = re.findall(r'https?://\S+', email_body)
    suspicious = [url for url in urls if any(domain in url.lower() for domain in ['paypal', 'bank', 'secure', 'login'])]
    return suspicious

def calculate_phishing_score(email_body):
    # Very basic scoring
    score = 0
    phishing_keywords = ['verify', 'account', 'password', 'login', 'urgent', 'immediately', 'click here']
    for word in phishing_keywords:
        if word in email_body.lower():
            score += 10
    return min(score, 100)  # cap at 100

def analyze_attachments(attachments):
    # Analyze file types/extensions in attachments
    suspicious_attachments = []
    risky_extensions = ['.exe', '.bat', '.scr', '.js', '.vbs', '.zip', '.rar', '.pdf']

    for attachment in attachments:
        for ext in risky_extensions:
            if attachment.lower().endswith(ext):
                suspicious_attachments.append(f"{attachment} (⚠ Suspicious file extension)")

    return suspicious_attachments
