"""
Defended version of the LLM classifier.

Combines three defense layers:
1. Sanitization - strips hidden/invisible content (HTML comments, white-on-white
   CSS, zero-width characters) and flags base64-looking content as visible data
2. Delimiter-based prompting - wraps the input clearly and instructs the model
   to never treat its contents as commands
3. Constrained output parsing - only ever returns PHISH or SAFE, regardless
   of what the model actually said, by checking for those exact words
"""

import os
from dotenv import load_dotenv
from google import genai
from defenses import sanitize, build_hardened_prompt

load_dotenv()
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))


def classify_defended(text):
    # Layer 1: strip hidden/invisible tricks before the model ever sees them
    cleaned_text = sanitize(text)

    # Layer 2: wrap in delimiters + explicit "treat as data" instruction
    prompt = build_hardened_prompt(cleaned_text)

    response = client.models.generate_content(
        model="gemini-flash-latest",
        contents=prompt,
    )
    raw_output = response.text.strip().upper()

    # Layer 3: constrained output parsing - force the result into exactly
    # one of the two valid labels, defaulting to PHISH if the model's
    # output is unclear (safer default for a security tool: when uncertain,
    # flag it rather than silently let it through)
    if "SAFE" in raw_output and "PHISH" not in raw_output:
        return "SAFE"
    elif "PHISH" in raw_output:
        return "PHISH"
    else:
        return "PHISH"  # unclear output defaults to the safer assumption


if __name__ == "__main__":
    # Quick sanity check on normal (non-attack) cases first
    test_cases = [
        ("http://www.google.com", "SAFE"),
        ("http://paypa1-secure-login.com/verify?acc=4471829", "PHISH"),
    ]
    for text, expected in test_cases:
        result = classify_defended(text)
        print(f"{text[:50]:50} -> {result} (expected {expected})")