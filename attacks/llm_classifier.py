import os
from dotenv import load_dotenv
from google import genai

load_dotenv()
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

SYSTEM_PROMPT = """You are a phishing detection assistant.
You will be given a URL or a piece of email/message text.
Classify it as either PHISH or SAFE.
Respond with only one word: PHISH or SAFE. No explanation, no punctuation."""


def classify(text):
    response = client.models.generate_content(
        model="gemini-flash-latest",
        contents=f"{SYSTEM_PROMPT}\n\nClassify this: {text}"
    )
    return response.text.strip().upper()


if __name__ == "__main__":
    test_cases = [
        ("http://www.google.com", "SAFE"),
        ("http://paypa1-secure-login.com/verify?acc=4471829", "PHISH"),
        ("https://amazon.com/orders", "SAFE"),
        ("http://192.168.4.12/account/signin/update", "PHISH"),
        ("http://secure-update-bank1929.xyz/confirm", "PHISH"),
    ]

    correct = 0
    for url, expected in test_cases:
        result = classify(url)
        is_correct = result == expected
        correct += is_correct
        print(f"URL: {url}")
        print(f"  Expected: {expected} | Got: {result} | {'✓' if is_correct else '✗'}")
        print()

    print(f"Accuracy on test cases: {correct}/{len(test_cases)}")