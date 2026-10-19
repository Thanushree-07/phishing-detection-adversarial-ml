import joblib

model = joblib.load("saved_model/tfidf_phishing_model.joblib")

test_urls = [
    ("https://www.google.com", "SAFE"),
    ("https://www.microsoft.com", "SAFE"),
    ("https://www.github.com", "SAFE"),
    ("http://paypa1-secure-login.com/verify?acc=4471829", "PHISH"),
    ("http://192.168.4.12/account/signin/update", "PHISH"),
    ("http://secure-verify-account1829.xyz/confirm", "PHISH"),
    ("http://amazon-customer-support.tk/billing-update", "PHISH"),
    ("http://bank-login-urgent-verify2847.com/signin", "PHISH"),
    ("http://apple-id-locked-confirm.xyz/restore", "PHISH"),
]

print(f"{'expected':10} {'phish_prob':12} url")
print("-" * 70)
for url, expected in test_urls:
    prob = model.predict_proba([url])[0][1]
    print(f"{expected:10} {prob:.4f}       {url}")