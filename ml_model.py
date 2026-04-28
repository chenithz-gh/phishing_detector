# ============================================================
# ML MODEL - Phishing Email Detector
# Dataset: CEAS_08 (emails.csv)
# ============================================================

import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import pickle
import os

# ============================================================
# SECTION 1: CONFIGURATION
# ============================================================

DATASET_FILE     = "emails.csv"
MODEL_FILE       = "model.pkl"
VECTORIZER_FILE  = "vectorizer.pkl"

# ============================================================
# SECTION 2: LOAD AND PREPARE DATASET
# ============================================================

def load_data():
    print(f"Loading dataset: {DATASET_FILE}")

    df = pd.read_csv(DATASET_FILE, usecols=["subject", "body", "label"])

    # Combine subject + body for richer features
    df["text"]  = df["subject"].fillna("") + " " + df["body"].fillna("")
    df["label"] = df["label"].astype(int)   # already 0=safe, 1=phishing

    df = df[["text", "label"]].dropna()

    print(f"  Total rows  : {len(df)}")
    print(f"  Safe (0)    : {(df['label']==0).sum()}")
    print(f"  Phishing (1): {(df['label']==1).sum()}")

    return df

# ============================================================
# SECTION 3: TRAIN THE MODEL
# ============================================================

def train_model():
    df = load_data()

    # Split into train and test (80/20)
    X_train, X_test, y_train, y_test = train_test_split(
        df["text"],
        df["label"],
        test_size=0.2,
        random_state=42,
        stratify=df["label"]    # keeps same ratio in both splits
    )

    print(f"\nTraining set : {len(X_train)} emails")
    print(f"Testing set  : {len(X_test)} emails")
    print("\nTraining model...")

    # Convert text to numbers using TF-IDF
    vectorizer = TfidfVectorizer(
        stop_words="english",
        max_features=5000,      # top 5000 most important words
        ngram_range=(1, 2)      # captures word pairs like "click here"
    )
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec  = vectorizer.transform(X_test)

    # Train Naive Bayes classifier
    model = MultinomialNB()
    model.fit(X_train_vec, y_train)

    # Evaluate
    y_pred = model.predict(X_test_vec)

    print("\n========== MODEL PERFORMANCE ==========")
    print(classification_report(
        y_test, y_pred,
        target_names=["Safe", "Phishing"]
    ))

    # Confusion matrix breakdown
    cm = confusion_matrix(y_test, y_pred)
    print("Confusion Matrix:")
    print(f"  True Safe     (correct): {cm[0][0]}")
    print(f"  False Alarm   (wrong)  : {cm[0][1]}")
    print(f"  Missed Phish  (wrong)  : {cm[1][0]}")
    print(f"  True Phishing (correct): {cm[1][1]}")
    print("========================================\n")

    # Save model and vectorizer
    with open(MODEL_FILE, "wb") as f:
        pickle.dump(model, f)
    with open(VECTORIZER_FILE, "wb") as f:
        pickle.dump(vectorizer, f)

    print(f"Model saved     : {MODEL_FILE}")
    print(f"Vectorizer saved: {VECTORIZER_FILE}")

# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    if not os.path.exists(DATASET_FILE):
        print(f"ERROR: {DATASET_FILE} not found!")
        print("Rename your CEAS_08.csv to emails.csv")
        exit()

    train_model()