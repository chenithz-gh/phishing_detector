SUSPICIOUS_KEYWORDS = [
    "verify your account",
    "click here immediately",
    "your account will be suspended",
    "confirm your password",
    "urgent action required",
    "you have won",
    "free gift",
    "limited time offer",
    "act now",
    "your account has been compromised",
    "update your payment",
    "unusual activity",
    "login attempt",
    "reset your password immediately",
    "dear customer",
    "dear user",
    "congratulations you have been selected",
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co",
    "goo.gl", "ow.ly", "short.link",
    "rebrand.ly", "tiny.cc"
]

import re
from urllib.parse import urlparse

def is_ip_based_url(url):
    # Checks if URL uses IP address instead of domain
    pattern = r"https?://(\d{1,3}\.){3}\d{1,3}"
    return bool(re.match(pattern, url))

def has_too_many_subdomains(url):
    # More than 3 dots in domain = suspicious
    domain = urlparse(url).netloc
    return domain.count(".") > 3

def is_url_shortener(url):
    domain = urlparse(url).netloc
    return any(s in domain for s in URL_SHORTENERS)

def is_http_only(url):
    return url.startswith("http://")

def has_suspicious_tld(url):
    # Suspicious top-level domains
    suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz"]
    domain = urlparse(url).netloc
    return any(domain.endswith(tld) for tld in suspicious_tlds)

def check_url(url):
    score = 0
    flags = []

    if is_ip_based_url(url):
        score += 3
        flags.append("IP-based URL detected")

    if has_too_many_subdomains(url):
        score += 2
        flags.append("Too many subdomains")

    if is_url_shortener(url):
        score += 2
        flags.append("URL shortener detected")

    if is_http_only(url):
        score += 1
        flags.append("No HTTPS")

    if has_suspicious_tld(url):
        score += 2
        flags.append("Suspicious domain extension")

    return score, flags

def check_keywords(text):
    score = 0
    flags = []
    text_lower = text.lower()

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in text_lower:
            score += 1
            flags.append(f'Suspicious phrase: "{keyword}"')

    return score, flags

def check_links_in_body(text):
    # Extract all URLs from the email body
    url_pattern = r"https?://[^\s]+"
    urls = re.findall(url_pattern, text)

    score = 0
    flags = []

    for url in urls:
        url_score, url_flags = check_url(url)
        score += url_score
        flags.extend(url_flags)

    return score, flags, urls

