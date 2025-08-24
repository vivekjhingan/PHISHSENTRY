import requests
import re
import time

VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/urls"

def get_virustotal_api_key():
    """Prompt user to enter their VirusTotal API key."""
    return input("Enter your VirusTotal API Key: ")

def scan_url(url, api_key):
    """Scan a given URL using the VirusTotal API while handling rate limits properly."""
    headers = {"x-apikey": api_key}
    data = {"url": url}

    retry_attempts = 3  # Only retry 3 times to avoid infinite loops

    for attempt in range(retry_attempts):
        try:
            response = requests.post(VIRUSTOTAL_URL, headers=headers, data=data)

            if response.status_code == 429:  # VirusTotal rate limit
                if attempt < retry_attempts - 1:
                    print(f"⚠️ Rate limit hit. Retrying in 15s... (Attempt {attempt+1}/{retry_attempts})")
                    time.sleep(15)
                    continue  # Retry request
                else:
                    print("❌ Too many rate limit errors. Skipping this URL.")
                    return {"error": "Rate limit exceeded"}

            if response.status_code == 200:
                result = response.json()
                analysis_id = result.get("data", {}).get("id", "N/A")
                return {"status": "Scanned", "VirusTotal Report": f"https://www.virustotal.com/gui/url/{analysis_id}/detection"}

            return {"error": f"VirusTotal API error: {response.status_code}"}
        
        except requests.exceptions.RequestException as e:
            return {"error": f"Request failed: {str(e)}"}

    return {"error": "Failed after retries"}

def extract_urls(text):
    """Extract all URLs from the given text using regex pattern matching."""
    return re.findall(r"https?://[^\s]+", text)

def scan_urls_from_emails(emails, api_key):
    """Scan URLs found in the latest 20 emails using VirusTotal while ensuring it moves to the next email."""
    
    email_count = 0  # Track processed emails
    
    for email_data in emails[:20]:  # Process only the latest 20 emails
        urls = extract_urls(email_data["body"])
        if not urls:
            continue  # Skip emails without URLs

        email_count += 1
        print(f"\n📧 [{email_count}] Email: {email_data['subject']} - {len(urls)} URL(s) found")

        for url in urls:
            vt_result = scan_url(url, api_key)
            if "VirusTotal Report" in vt_result:  # Success case
                print(f"🛡 {url} → {vt_result['VirusTotal Report']}")
            else:
                print(f"❌ {url} → {vt_result['error']}")

        print("✅ Email scan completed.")

    print("\n🔍 All emails scanned.")
