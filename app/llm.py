"""
LLM classifier used by the app.

Designed so the whole app works even if no API key is set up yet:
- If GROQ_API_KEY is present, real calls are made to Groq (fast, free tier,
  OpenAI-compatible chat API).
- If not, a clearly-labeled offline fallback is used instead, so the rest
  of the app (baseline models, TF-IDF model, evasion demo) is still fully
  usable while the LLM piece is being wired up.

This keeps the "we'll figure out the API key later" plan from blocking
the rest of the app.
"""

import os
from dotenv import load_dotenv

load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY")

SYSTEM_PROMPT = """You are a phishing detection assistant.
You will be given a URL or a piece of email/message text.
Classify it as either PHISH or SAFE.
Respond with only one word: PHISH or SAFE. No explanation, no punctuation."""

_client = None
_llm_available = False

if GROQ_API_KEY:
    try:
        from groq import Groq
        _client = Groq(api_key=GROQ_API_KEY)
        _llm_available = True
    except Exception:
        _llm_available = False


def llm_configured():
    """Whether a real LLM backend is wired up and ready to use."""
    return _llm_available


def _offline_fallback(text):
    """
    A simple keyword-based stand-in used only when no API key is configured,
    so the app's LLM tab still demonstrates the idea (just without a real
    model behind it). Clearly NOT a replacement for the real LLM classifier,
    and the UI always labels this mode explicitly.
    """
    suspicious_words = ["login", "verify", "secure", "account", "update",
                         "confirm", "banking", "signin", "password", "suspend",
                         "urgent", "click", "immediately"]
    text_lower = text.lower()
    hits = sum(word in text_lower for word in suspicious_words)
    return "PHISH" if hits >= 2 else "SAFE"


def classify(text, model_name="llama-3.3-70b-versatile"):
    """Classify raw text (URL or message) as PHISH or SAFE."""
    if not _llm_available:
        return _offline_fallback(text)

    try:
        response = _client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f"Classify this: {text}"},
            ],
            max_tokens=10,
        )
        answer = response.choices[0].message.content.strip().upper()
        if "PHISH" in answer:
            return "PHISH"
        elif "SAFE" in answer:
            return "SAFE"
        return "PHISH"  # unclear output -> safer default
    except Exception as e:
        return f"ERROR: {e}"
