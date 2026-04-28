# ============================================================
# PHISHING EMAIL FETCHER & DETECTOR
# Connects to inbox + scans emails for phishing
# ============================================================

import imaplib
import email
import sys
import os
import pickle
import glob
from email.header import decode_header
from datetime import datetime
from colorama import Fore, Style, init
from rules import check_keywords, check_links_in_body
from config import MY_EMAIL, MY_PASSWORD

sys.stdout.reconfigure(encoding="utf-8")
init(autoreset=True)

# ============================================================
# SECTION 1: CONFIGURATION
# ============================================================

MODEL_FILE      = "model.pkl"
VECTORIZER_FILE = "vectorizer.pkl"
LOG_FILE        = "scan_log.txt"

PROVIDERS = {
    "gmail": {
        "host"       : "imap.gmail.com",
        "port"       : 993,
        "description": "Gmail"
    },
    "outlook": {
        "host"       : "outlook.office365.com",
        "port"       : 993,
        "description": "Outlook / Hotmail"
    },
    "yahoo": {
        "host"       : "imap.mail.yahoo.com",
        "port"       : 993,
        "description": "Yahoo Mail"
    },
    "custom": {
        "host"       : "",
        "port"       : 993,
        "description": "Custom IMAP"
    }
}

# ============================================================
# SECTION 2: LOAD ML MODEL
# ============================================================

def load_ml_model():
    if os.path.exists(MODEL_FILE) and os.path.exists(VECTORIZER_FILE):
        with open(MODEL_FILE, "rb") as f:
            model = pickle.load(f)
        with open(VECTORIZER_FILE, "rb") as f:
            vectorizer = pickle.load(f)
        print(f"{Fore.GREEN}ML model loaded successfully.")
        return model, vectorizer
    else:
        print(f"{Fore.YELLOW}No ML model found. Rule-based detection only.")
        print(f"{Fore.YELLOW}Run ml_model.py to enable ML detection.")
        return None, None

model, vectorizer = load_ml_model()

# ============================================================
# SECTION 3: ML PREDICTION
# ============================================================

def ml_predict(text):
    if model and vectorizer:
        vec        = vectorizer.transform([text])
        pred       = model.predict(vec)[0]
        proba      = model.predict_proba(vec)[0]
        phish_prob = round(proba[1] * 100, 2)
        return pred, phish_prob
    return None, None

# ============================================================
# SECTION 4: ANALYZE EMAIL (from detector.py)
# ============================================================

def get_verdict(score):
    if score == 0:
        return "SAFE", Fore.GREEN
    elif score <= 5:
        return "WARNING", Fore.YELLOW
    else:
        return "DANGER - LIKELY PHISHING", Fore.RED

def analyze_email(subject, body, sender=""):
    total_score = 0
    all_flags   = []

    # Rule-based checks on subject
    s_score, s_flags = check_keywords(subject)
    total_score += s_score
    all_flags.extend([f"[SUBJECT] {f}" for f in s_flags])

    # Rule-based checks on body
    b_score, b_flags = check_keywords(body)
    total_score += b_score
    all_flags.extend([f"[BODY] {f}" for f in b_flags])

    # URL checks
    u_score, u_flags, urls = check_links_in_body(body)
    total_score += u_score
    all_flags.extend([f"[URL] {f}" for f in u_flags])

    # ML prediction
    ml_label, ml_prob = ml_predict(subject + " " + body)
    if ml_label is not None:
        if ml_label == 1:
            total_score += 3
            all_flags.append(
                f"[ML] Model flagged as phishing ({ml_prob}% confidence)"
            )
        else:
            all_flags.append(
                f"[ML] Model says safe ({100 - ml_prob:.1f}% confidence)"
            )

    return total_score, all_flags, urls

# ============================================================
# SECTION 5: SAVE LOG (from detector.py)
# ============================================================

def save_log(sender, subject, score, verdict):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(
            f"[{timestamp}] Score:{score:2} | {verdict:25} | "
            f"From:{sender} | Subject:{subject}\n"
        )

# ============================================================
# SECTION 6: DISPLAY RESULT (from detector.py)
# ============================================================

def display_result(subject, sender, score, flags, urls):
    verdict, color = get_verdict(score)

    print("\n" + "="*52)
    print("      PHISHING DETECTOR REPORT")
    print("="*52)
    print(f"From       : {sender}")
    print(f"Subject    : {subject}")
    print(f"Risk Score : {score}")
    print(f"Verdict    : {color}{verdict}{Style.RESET_ALL}")
    print("-"*52)

    if flags:
        print("Red flags:")
        for flag in flags:
            if flag.startswith("[ML] Model says safe"):
                print(f"  {Fore.GREEN}✓{Style.RESET_ALL} {flag}")
            else:
                print(f"  {Fore.RED}✗{Style.RESET_ALL} {flag}")
    else:
        print(f"{Fore.GREEN}No red flags detected.")

    if urls:
        print(f"\nURLs found ({len(urls)}):")
        for url in urls:
            print(f"  - {url}")

    print("="*52 + "\n")

# ============================================================
# SECTION 7: CONNECT TO MAILBOX
# ============================================================

def connect_to_mailbox(provider, email_address, password):
    config = PROVIDERS[provider]

    if provider == "custom":
        config["host"] = input("Enter your IMAP server address: ").strip()

    print(f"\nConnecting to {config['description']}...")

    try:
        mail = imaplib.IMAP4_SSL(config["host"], config["port"])
        mail.login(email_address, password)
        print(f"{Fore.GREEN}Connected successfully!")
        return mail
    except imaplib.IMAP4.error as e:
        print(f"{Fore.RED}Connection failed: {e}")
        print("Check your email/password and make sure IMAP is enabled.")
        return None

# ============================================================
# SECTION 8: DECODE EMAIL PARTS
# ============================================================

def decode_str(value):
    if value is None:
        return ""
    decoded_parts = decode_header(value)
    result = ""
    for part, encoding in decoded_parts:
        if isinstance(part, bytes):
            result += part.decode(encoding or "utf-8", errors="ignore")
        else:
            result += part
    return result

def extract_body(msg):
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    body += payload.decode("utf-8", errors="ignore")
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body = payload.decode("utf-8", errors="ignore")
    return body

# ============================================================
# SECTION 9: FETCH AND SCAN EMAILS
# ============================================================

def fetch_and_scan(mail, folder="INBOX", limit=10, only_unread=True):
    mail.select(folder)

    criteria = "UNSEEN" if only_unread else "ALL"
    status, messages = mail.search(None, criteria)

    if status != "OK":
        print("Could not fetch emails.")
        return

    email_ids = messages[0].split()

    if not email_ids:
        print(f"{Fore.GREEN}No {'unread' if only_unread else ''} emails found.")
        return

    email_ids = email_ids[-limit:]

    print(f"\nScanning {len(email_ids)} emails...\n")
    print(f"{'#':<4} {'VERDICT':<10} {'SCORE':<7} {'FROM':<30} {'SUBJECT'}")
    print("="*80)

    danger_count  = 0
    warning_count = 0
    safe_count    = 0
    count         = 1

    for email_id in reversed(email_ids):
        status, msg_data = mail.fetch(email_id, "(RFC822)")

        if status != "OK":
            continue

        raw_email = msg_data[0][1]
        msg       = email.message_from_bytes(raw_email)

        sender  = decode_str(msg.get("From", ""))
        subject = decode_str(msg.get("Subject", ""))
        body    = extract_body(msg)

        score, flags, urls = analyze_email(subject, body, sender)
        verdict, color     = get_verdict(score)

        if score == 0:
            safe_count    += 1
        elif score <= 5:
            warning_count += 1
        else:
            danger_count  += 1

        sender_clean  = sender.split("<")[0].strip()
        if not sender_clean:
            sender_clean  = sender.split("@")[0] if "@" in sender else sender
        sender_clean  = sender_clean[:28] + ".." if len(sender_clean) > 30 else sender_clean
        subject_clean = subject[:38] + ".." if len(subject) > 40 else subject

        print(f"{str(count)+'.':<4} {color}{verdict:<10}{Style.RESET_ALL} "
              f"Score:{score:<3} {sender_clean:<30} {subject_clean}")

        if score > 0:
            rule_flags = [f for f in flags if not f.startswith("[ML] Model says safe")]
            if rule_flags:
                for flag in rule_flags[:3]:
                    print(f"      {Fore.RED}↳ {flag}{Style.RESET_ALL}")

        save_log(sender, subject, score, verdict)
        count += 1

    print("\n" + "="*80)
    print("  SCAN SUMMARY")
    print("="*80)
    print(f"  {Fore.GREEN}✓ Safe    : {safe_count}{Style.RESET_ALL}")
    print(f"  {Fore.YELLOW}! Warning : {warning_count}{Style.RESET_ALL}")
    print(f"  {Fore.RED}✗ Danger  : {danger_count}{Style.RESET_ALL}")
    print(f"    Total   : {safe_count + warning_count + danger_count}")
    print(f"\n  Log saved : {LOG_FILE}")
    print("="*80 + "\n")

# ============================================================
# SECTION 10: AUTO SCAN
# ============================================================

def auto_scan(mail, interval_minutes=5):
    import time
    print(f"\nAuto-scan enabled. Checking every {interval_minutes} minutes.")
    print("Press Ctrl+C to stop.\n")

    try:
        while True:
            now = datetime.now().strftime("%H:%M:%S")
            print(f"\n[{now}] Checking for new emails...")
            fetch_and_scan(mail, only_unread=True, limit=20)
            print(f"Next scan in {interval_minutes} minutes...")
            time.sleep(interval_minutes * 60)
    except KeyboardInterrupt:
        print("\nAuto-scan stopped.")

# ============================================================
# SECTION 11: MANUAL SCAN
# ============================================================

def manual_scan():
    print("\n--- Manual Email Scan ---")
    sender  = input("Sender email address : ").strip()
    subject = input("Email subject        : ").strip()
    print("Email body (type END on new line when done):")
    lines = []
    while True:
        line = input()
        if line.strip().upper() == "END":
            break
        lines.append(line)
    body = "\n".join(lines)

    print("\nAnalyzing...")
    score, flags, urls = analyze_email(subject, body, sender)
    display_result(subject, sender, score, flags, urls)
    verdict, _         = get_verdict(score)
    save_log(sender, subject, score, verdict)
    print(f"Log saved to: {LOG_FILE}")

# ============================================================
# MAIN MENU
# ============================================================

if __name__ == "__main__":
    print("\n" + "="*52)
    print("      PHISHING EMAIL DETECTOR")
    print("="*52)
    print("1. Scan inbox (Gmail / Outlook / Yahoo)")
    print("2. Scan manually (paste email content)")
    print("="*52)

    main_choice = input("Choose option (1/2): ").strip()

    if main_choice == "2":
        manual_scan()

    elif main_choice == "1":
        print("\nSelect your email provider:")
        print("  1. Gmail")
        print("  2. Outlook / Hotmail")
        print("  3. Yahoo Mail")
        print("  4. Custom IMAP")

        choice = input("Choose provider (1/2/3/4): ").strip()

        provider_map = {
            "1": "gmail",
            "2": "outlook",
            "3": "yahoo",
            "4": "custom"
        }

        if choice not in provider_map:
            print("Invalid choice.")
            exit()

        provider = provider_map[choice]
        print(f"Using saved credentials for: {MY_EMAIL}")

        mail = connect_to_mailbox(provider, MY_EMAIL, MY_PASSWORD)

        if not mail:
            exit()

        print("\nScan options:")
        print("  1. Scan latest 10 unread emails")
        print("  2. Scan latest 50 emails (read + unread)")
        print("  3. Auto-scan every 5 minutes")

        scan_choice = input("Choose scan option (1/2/3): ").strip()

        if scan_choice == "1":
            fetch_and_scan(mail, only_unread=True,  limit=10)
        elif scan_choice == "2":
            fetch_and_scan(mail, only_unread=False, limit=50)
        elif scan_choice == "3":
            auto_scan(mail, interval_minutes=5)
        else:
            print("Invalid option.")

        mail.logout()
        print("\nDisconnected from mailbox.")

    else:
        print("Invalid option.")