"""
Character-level evasion attacks against a phishing URL,
mirroring the logic used in text_model/adversarial_evaluation.py.
"""

import random
from urllib.parse import urlsplit, urlunsplit


def digit_substitution(url):
    replacements = {"o": "0", "i": "1", "e": "3", "a": "4", "s": "5"}
    chars = list(url.lower())
    positions = [i for i, c in enumerate(chars) if c in replacements]
    if not positions:
        return url
    pos = random.choice(positions)
    chars[pos] = replacements[chars[pos]]
    return "".join(chars)


def typo_attack(url):
    parts = urlsplit(url if "://" in url else "http://" + url)
    domain = parts.hostname or ""
    if len(domain) < 5:
        return url
    pos = random.randint(1, len(domain) - 2)
    changed_domain = domain[:pos] + domain[pos + 1:]
    netloc = parts.netloc
    if domain in netloc:
        netloc = netloc.replace(domain, changed_domain, 1)
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


# Latin letters -> visually identical Cyrillic letters (what real homograph phishing uses)
HOMOGLYPHS = {
    "a": "\u0430",  # Cyrillic а
    "c": "\u0441",  # Cyrillic с
    "e": "\u0435",  # Cyrillic е
    "i": "\u0456",  # Cyrillic і
    "o": "\u043e",  # Cyrillic о
    "p": "\u0440",  # Cyrillic р
    "s": "\u0455",  # Cyrillic ѕ
    "x": "\u0445",  # Cyrillic х
    "y": "\u0443",  # Cyrillic у
}


def homoglyph_attack(url):
    """Replace every confusable Latin letter after the scheme with a look-alike Cyrillic letter.

    The scheme (http://, https://) is left alone so the URL still looks and behaves like a URL.
    Replacing ALL confusable letters (not just one) is what actually changes the character
    n-grams the TF-IDF model sees and removes keywords like 'login' / 'verify' from the
    GBT model's keyword features, while the text still looks the same to a human.
    """
    if "://" in url:
        scheme, rest = url.split("://", 1)
        prefix = scheme + "://"
    else:
        prefix, rest = "", url
    return prefix + "".join(HOMOGLYPHS.get(c, c) for c in rest)


def describe_changes(original, attacked):
    """Character-level diff: segments for highlighting plus a table of every changed character."""
    import difflib
    import unicodedata

    sm = difflib.SequenceMatcher(a=original, b=attacked, autojunk=False)
    orig_segments, att_segments, changes = [], [], []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            orig_segments.append({"text": original[i1:i2], "changed": False})
            att_segments.append({"text": attacked[j1:j2], "changed": False})
            continue
        if i2 > i1:
            orig_segments.append({"text": original[i1:i2], "changed": True})
        if j2 > j1:
            att_segments.append({"text": attacked[j1:j2], "changed": True})
        if tag == "replace" and (i2 - i1) == (j2 - j1):
            pairs = zip(range(i1, i2), original[i1:i2], attacked[j1:j2])
            for idx, o, a in pairs:
                changes.append({
                    "index": idx, "original": o, "replacement": a,
                    "codepoint": f"U+{ord(a):04X}",
                    "unicode_name": unicodedata.name(a, "UNKNOWN"),
                })
        elif tag == "delete":
            for idx in range(i1, i2):
                changes.append({"index": idx, "original": original[idx], "replacement": "",
                                "codepoint": "-", "unicode_name": "DELETED"})
        else:
            changes.append({"index": i1, "original": original[i1:i2], "replacement": attacked[j1:j2],
                            "codepoint": " ".join(f"U+{ord(c):04X}" for c in attacked[j1:j2]),
                            "unicode_name": "REPLACED"})
    return {"original_segments": orig_segments, "attacked_segments": att_segments, "changes": changes}


def to_punycode_host(url):
    """What the browser / DNS actually sees for a non-ASCII hostname (xn--...)."""
    from urllib.parse import urlsplit
    try:
        host = urlsplit(url if "://" in url else "http://" + url).hostname or ""
        if host.isascii():
            return None          # plain ASCII hostname: no punycode involved
        return host.encode("idna").decode("ascii")
    except Exception:
        return None


def keyword_stuffing_attack(url):
    """FALSE-ALARM attack: make a LEGITIMATE url look phishy by adding phishing keywords.

    Unlike the other attacks (which try PHISH -> SAFE), this tries SAFE -> PHISH. It adds a
    'secure-login' subdomain and a '/verify-account?update=1' path, the words the models learned
    to associate with phishing. Used to flood a filter with false alarms or get a real site blocked.
    """
    parts = urlsplit(url if "://" in url else "http://" + url)
    host = (parts.hostname or "")
    if host.startswith("www."):
        host = host[4:]
    path = parts.path.rstrip("/") + "/verify-account"
    return urlunsplit((parts.scheme, "secure-login." + host, path, "update=1", parts.fragment))


EVASION_ATTACKS = {
    "digit_substitution": digit_substitution,
    "typo": typo_attack,
    "homoglyph": homoglyph_attack,
    "keyword_stuffing": keyword_stuffing_attack,
}

ATTACK_LABELS = {
    "digit_substitution": "Digit substitution",
    "typo": "Typo (character deletion)",
    "homoglyph": "Homoglyph substitution",
    "keyword_stuffing": "Keyword stuffing (false-alarm attack on legit URLs)",
}
