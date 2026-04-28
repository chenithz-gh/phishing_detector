# phishing_detector# 🛡️ Phishing Email Detector

> **Disclaimer:** This project is built strictly for educational purposes to understand how phishing detection works. Use responsibly and only on your own email accounts.

---

## 📋 Overview

A fully functional phishing email detector built in Python that combines **rule-based heuristics** and **machine learning** to detect phishing emails. It connects directly to your Gmail, Outlook, or Yahoo inbox and scans incoming emails automatically.

---

## ✨ Features

- **Rule-based detection** — checks for suspicious keywords, URL patterns, IP-based links, URL shorteners, and dangerous domain extensions
- **ML-powered detection** — Naive Bayes classifier trained on 39,000+ real emails
- **Inbox scanning** — connects directly to Gmail, Outlook, Yahoo via IMAP
- **Manual scanning** — paste any email content for instant analysis
- **Auto-scan mode** — automatically checks for new emails every 5 minutes
- **Risk scoring system** — Safe / Warning / Danger verdict with score breakdown
- **Red flag reporting** — shows exactly why an email was flagged
- **Scan log** — saves every scan result with timestamp to `scan_log.txt`
- **Color-coded terminal output** — green/yellow/red results at a glance

---

## 📁 Project Structure

```
phishing_detector/
│
├── email_fetcher.py     ← main script (detection + inbox connector)
├── rules.py             ← keyword + URL heuristic rules
├── ml_model.py          ← train the ML model
├── requirements.txt     ← Python dependencies
├── .gitignore           ← excluded files
└── README.md            ← this file
```

---

## 🛠️ Requirements

- Python 3.7+
- Gmail / Outlook / Yahoo account with IMAP enabled

### Dependencies

```bash
pip install -r requirements.txt
```

Or install manually:

```bash
pip install pandas scikit-learn colorama
```

---

## ⚙️ Configuration

Before running, open `email_fetcher.py` and update the credentials at the top:

```python
MY_EMAIL    = "your_email@gmail.com"
MY_PASSWORD = "your_app_password_here"
```

### Setting up Gmail App Password

1. Go to your Google Account → Security
2. Enable 2-Step Verification
3. Go to App Passwords → Generate new password
4. Select "Mail" and your device
5. Copy the 16-character password into `MY_PASSWORD`

### Enable IMAP in Gmail

```
Gmail → Settings → See all settings
→ Forwarding and POP/IMAP
→ Enable IMAP → Save
```

---

## 🚀 How to Run

**Step 1 — Clone the repo**
```bash
git clone https://github.com/chenithz-gh/phishing-detector.git
cd phishing-detector
```

**Step 2 — Create virtual environment**
```bash
python -m venv venv

# Windows:
venv\Scripts\activate

# macOS/Linux:
source venv/bin/activate
```

**Step 3 — Install dependencies**
```bash
pip install -r requirements.txt
```

**Step 4 — Get the dataset**

Download the CEAS 2008 phishing dataset from Kaggle:
```
https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset
```
Rename the downloaded file to `emails.csv` and place it in the project folder.

**Step 5 — Train the ML model**
```bash
python ml_model.py
```

Expected output:
```
Loading dataset: emails.csv
  Total rows  : 39154
  Safe (0)    : 17312
  Phishing (1): 21842

Training set : 31323 emails
Testing set  : 7831 emails

Training model...

========== MODEL PERFORMANCE ==========
              precision    recall  f1-score
        Safe       0.97      0.96      0.97
    Phishing       0.97      0.98      0.97
    accuracy                           0.97
```

**Step 6 — Run the detector**
```bash
python email_fetcher.py
```

---

## 📊 How It Works

### Risk Scoring System

| Score | Verdict | Meaning |
|---|---|---|
| 0 | SAFE | No red flags detected |
| 1–5 | WARNING | Some suspicious signals |
| 6+ | DANGER | Very likely phishing |

### What Gets Checked

| Check | Points Added |
|---|---|
| Suspicious keyword found | +1 per keyword |
| IP-based URL detected | +3 |
| URL shortener detected | +2 |
| No HTTPS | +1 |
| Suspicious domain extension (.tk, .ml) | +2 |
| Too many subdomains | +2 |
| ML model flags as phishing | +3 |

---

## 📄 Output Example

```
Scanning 5 emails...

#    VERDICT    SCORE   FROM                           SUBJECT
================================================================================
1.   SAFE       0       Google                         Security alert for your..
2.   SAFE       0       GitHub                         Your weekly digest
3.   WARNING    4       PayPal Support                 Please verify your accou..
      ↳ [SUBJECT] Suspicious phrase: "verify your account"
      ↳ [URL] No HTTPS
4.   DANGER     9       noreply@amaz0n.tk              Urgent: Account suspended
      ↳ [SUBJECT] Suspicious phrase: "urgent action required"
      ↳ [URL] IP-based URL detected
      ↳ [ML] Model flagged as phishing (94.2% confidence)
5.   SAFE       0       Slack                          New message in #general

================================================================================
  SCAN SUMMARY
================================================================================
  ✓ Safe    : 3
  ! Warning : 1
  ✗ Danger  : 1
    Total   : 5

  Log saved : scan_log.txt
================================================================================
```

---

## 🔌 Supported Email Providers

| Provider | IMAP Server | Notes |
|---|---|---|
| Gmail | imap.gmail.com | Requires App Password |
| Outlook / Hotmail | outlook.office365.com | Requires App Password |
| Yahoo Mail | imap.mail.yahoo.com | Requires App Password |
| Custom | Your IMAP server | Enter manually |

---

## 🤖 ML Model Details

| Detail | Value |
|---|---|
| Algorithm | Naive Bayes (MultinomialNB) |
| Feature extraction | TF-IDF (top 5000 features) |
| N-gram range | (1, 2) — captures word pairs |
| Training dataset | CEAS 2008 (39,154 emails) |
| Train/test split | 80% / 20% |
| Expected accuracy | 95–97% |

---

## 🛡️ How to Defend Against Phishing

Understanding how phishing works helps you stay safe:

- Use a **password manager** — auto-fill bypasses fake login pages
- Always check the **sender domain** — not just the display name
- Hover over links **before clicking** — check the real URL
- Enable **2FA** on all important accounts
- Never enter credentials on **HTTP** (non-HTTPS) pages
- Be suspicious of **urgent language** — real companies don't threaten you

---

## 📚 What I Learned

- How TF-IDF converts text into numerical features for ML
- Why Naive Bayes works well for text classification
- How IMAP protocol works for email retrieval
- Combining rule-based and ML detection for better accuracy
- How to handle Unicode encoding issues in email parsing
- Real-world phishing patterns from 39,000+ email dataset

---

## ⚖️ Legal & Ethical Notice

This project is intended **only** for:
- Learning about cybersecurity and phishing detection
- Scanning your **own** email accounts
- Educational demonstration purposes

**Never use this to access email accounts you do not own.**

---

## 👤 Author

**Chenitha Gurusinghe**
- GitHub: [@chenithz-gh](https://github.com/chenithz-gh)

---

## 📜 License

This project is licensed under the MIT License — for educational use only.