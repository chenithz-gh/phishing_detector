from rules import check_keywords, check_links_in_body
from colorama import Fore, Style, init
init(autoreset=True)

def analyze_email(subject, body, sender=""):
    total_score = 0
    all_flags   = []

    # Check subject line
    s_score, s_flags = check_keywords(subject)
    total_score += s_score
    all_flags.extend([f"[SUBJECT] {f}" for f in s_flags])

    # Check body keywords
    b_score, b_flags = check_keywords(body)
    total_score += b_score
    all_flags.extend([f"[BODY] {f}" for f in b_flags])

    # Check URLs in body
    u_score, u_flags, urls = check_links_in_body(body)
    total_score += u_score
    all_flags.extend([f"[URL] {f}" for f in u_flags])

    return total_score, all_flags, urls

def display_result(score, flags, urls):
    print("\n" + "="*50)
    print("     PHISHING DETECTOR REPORT")
    print("="*50)

    if score == 0:
        verdict = f"{Fore.GREEN}SAFE"
    elif score <= 5:
        verdict = f"{Fore.YELLOW}WARNING"
    else:
        verdict = f"{Fore.RED}DANGER - LIKELY PHISHING"

    print(f"Risk Score : {score}")
    print(f"Verdict    : {verdict}")
    print("-"*50)

    if flags:
        print("Red flags detected:")
        for flag in flags:
            print(f"  {Fore.RED}x{Style.RESET_ALL} {flag}")
    else:
        print(f"{Fore.GREEN}No red flags detected.")

    if urls:
        print(f"\nURLs found ({len(urls)}):")
        for url in urls:
            print(f"  - {url}")

    print("="*50 + "\n")

if __name__ == "__main__":
    print("\n===== PHISHING EMAIL DETECTOR =====")
    print("Paste email details below.\n")

    sender  = input("Sender email address: ").strip()
    subject = input("Email subject       : ").strip()

    print("Email body (paste text, type END on new line when done):")
    lines = []
    while True:
        line = input()
        if line.strip().upper() == "END":
            break
        lines.append(line)
    body = "\n".join(lines)

    print("\nAnalyzing...")
    score, flags, urls = analyze_email(subject, body, sender)
    display_result(score, flags, urls)


