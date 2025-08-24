import imaplib
import email
from email.header import decode_header
import getpass
import chardet

def get_email_credentials():
    """Prompt user for email credentials"""
    email_user = input("Enter your email: ")
    email_pass = getpass.getpass("Enter your password: ")
    imap_server = input("Enter your IMAP server (e.g., imap.gmail.com): ")
    return email_user, email_pass, imap_server


def connect_imap(email_user, email_pass, imap_server):
    """Establish a secure IMAP connection"""
    try:
        print("🔌 Connecting to IMAP server...")
        mail = imaplib.IMAP4_SSL(imap_server)
        mail.login(email_user, email_pass)
        print("✅ IMAP connection successful!")
        return mail
    except imaplib.IMAP4.error:
        print("❌ Authentication failed: Invalid username or password.")
        return None
    except Exception as e:
        print(f"❌ Error connecting to IMAP: {e}")
        return None


def safe_decode(payload):
    """Try different encoding methods to decode email body safely."""
    if not payload:
        return ""

    try:
        return payload.decode("utf-8")  # First, try UTF-8
    except UnicodeDecodeError:
        detected_encoding = chardet.detect(payload)['encoding']  # Detect encoding
        if detected_encoding:
            try:
                return payload.decode(detected_encoding, errors="ignore")  # Try detected encoding
            except UnicodeDecodeError:
                return payload.decode("latin-1", errors="ignore")  # Fallback
    return payload.decode("latin-1", errors="ignore")  # Final fallback


def fetch_emails(email_user, email_pass, imap_server):
    """Retrieve and parse only the latest 20 emails from the inbox (latest first)"""
    mail = connect_imap(email_user, email_pass, imap_server)
    if not mail:
        print("❌ Failed to connect to IMAP. Exiting...")
        return []

    print("📩 Selecting Inbox...")
    status, messages = mail.select("inbox")
    if status != "OK":
        print("❌ ERROR: Unable to access the inbox.")
        return []

    print("🔍 Searching for emails...")
    status, messages = mail.search(None, "ALL")
    if status != "OK" or not messages[0]:
        print("❌ ERROR: No emails found or unable to retrieve.")
        return []

    email_nums = messages[0].split()
    latest_emails = email_nums[-20:]  # Get only the latest 20 emails
    print(f"📨 Found {len(email_nums)} emails, fetching the latest {len(latest_emails)}.")

    email_list = []

    for count, num in enumerate(reversed(latest_emails), 1):  # Fetch latest emails first
        print(f"📥 Fetching email {num.decode()}...")
        status, msg_data = mail.fetch(num, "(RFC822)")
        if status != "OK":
            print(f"❌ ERROR: Failed to fetch email {num.decode()}.")
            continue

        for response_part in msg_data:
            if isinstance(response_part, tuple):
                msg = email.message_from_bytes(response_part[1])

                # Decode subject safely
                subject, encoding = decode_header(msg["Subject"])[0]
                try:
                    subject = subject.decode(encoding) if encoding else str(subject)
                except (LookupError, AttributeError):
                    subject = str(subject)
                
                sender = msg.get("From")

                # Extract body safely
                body = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        if part.get_content_type() == "text/plain":
                            body = safe_decode(part.get_payload(decode=True))
                            break
                else:
                    body = safe_decode(msg.get_payload(decode=True))

                print(f"✅ Email Retrieved: {subject} from {sender}")

                email_list.append({
                    "subject": subject,
                    "from": sender,
                    "body": body
                })
        
        if count >= 20:  # Stop after processing 20 emails
            print("\n✅ Stopping after retrieving 20 emails.")
            break

    mail.logout()
    return email_list
