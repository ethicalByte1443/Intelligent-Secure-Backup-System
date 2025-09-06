# app/utils/dlp.py
import re
from pathlib import Path
from typing import Dict, List, Tuple
import json
import os
import math

# optional ML pieces
try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    import joblib
    HAS_SKLEARN = True
except Exception:
    HAS_SKLEARN = False

MODEL_PATH = "data/context_model.joblib"

# Regex patterns
AADHAAR_RE = re.compile(r"\b\d{12}\b")
PAN_RE = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")
CC_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
# Indian phone numbers (10 digits), with optional +91 or country code
PHONE_RE = re.compile(r"(?:\+91[\-\s]?|0)?[6-9]\d{9}\b")
# Passport (India: 8 chars, one letter then 7 digits, often): e.g., A1234567
PASSPORT_RE = re.compile(r"\b[A-Z][0-9]{7}\b")
# password-like tokens (very heuristic)
PASSWORD_TOKEN_RE = re.compile(r"(password|passwd|pwd|passcode|pass:)\s*[:#\-]?\s*([^\s,;]{4,40})", re.IGNORECASE)

# keywords that boost context/confidence
SENSITIVE_KEYWORDS = [
    "aadhaar", "pan", "credit card", "card number", "cvv", "upi",
    "password", "pwd", "passport", "passport no", "bank account",
    "account number", "ifsc", "salary", "payroll", "ssn", "social security",
    "secret", "confidential"
]

# helper: Luhn check for cc
def _luhn_check(number_str: str) -> bool:
    digits = [int(ch) for ch in re.sub(r"\D", "", number_str)]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0

def _read_text_safe(path: Path, max_bytes: int = 200_000) -> str:
    try:
        raw = path.read_bytes()
        if len(raw) > max_bytes:
            raw = raw[:max_bytes]
        return raw.decode(errors="ignore")
    except Exception:
        return ""

def _find_snippets(text: str, match_spans: List[Tuple[int,int]], context: int = 40) -> List[str]:
    snippets = []
    for (s,e) in match_spans:
        start = max(0, s - context)
        end = min(len(text), e + context)
        snippet = text[start:end].replace("\n", " ").replace("\r", " ")
        snippets.append(snippet.strip())
    return snippets

# Simple keyword heuristic context scorer (0..1)
def context_score_heuristic(text: str) -> float:
    lower = text.lower()
    hits = sum(1 for kw in SENSITIVE_KEYWORDS if kw in lower)
    if hits == 0:
        return 0.0
    # score saturates at 1 with several hits
    return min(1.0, hits / 6.0)



def load_context_model():
    if not HAS_SKLEARN:
        return None
    if os.path.exists(MODEL_PATH):
        return joblib.load(MODEL_PATH)
    return None

def predict_context_ml(text: str) -> float:
    model = load_context_model()
    if not model:
        return 0.0
    vec, clf = model
    X = vec.transform([text])
    proba = clf.predict_proba(X)[0,1]  # probability sensitive
    return float(proba)

# Combine heuristic + ML (if available)
def compute_context_score(text: str) -> float:
    h = context_score_heuristic(text)
    ml = 0.0
    if HAS_SKLEARN and os.path.exists(MODEL_PATH):
        try:
            ml = predict_context_ml(text)
        except Exception:
            ml = 0.0
    # weighted combination (favor ML slightly if available)
    if ml > 0:
        return min(1.0, 0.4*h + 0.6*ml)
    return h

def compute_risk_score(hits: Dict, confidence: str, context_score: float) -> int:
    """
    Return risk score 0-100.
    Basic formula:
      base = 20 * number_of_hit_types
      confidence boost: low=0, medium=10, high=20
      context multiplier: multiplies base importance
    """
    n_types = len(hits)
    base = 20 * n_types
    conf_map = {"low": 0, "medium": 10, "high": 20}
    conf_boost = conf_map.get(confidence, 0)
    # clamp
    raw = (base + conf_boost) * (1.0 + context_score)
    score = max(0, min(100, int(round(raw))))
    return score

def score_label_from_score(score: int) -> str:
    if score >= 70:
        return "High"
    if score >= 35:
        return "Medium"
    return "Low"

def scan_file(path: Path) -> Dict:
    """
    Scan a single file for PII. Returns a dict containing:
    {
      "hits": {...},
      "snippets": {...},
      "confidence": "low|medium|high",
      "context_score": 0.0..1.0,
      "risk_score": 0..100,
      "risk_label": "Low|Medium|High"
    }
    """
    text = _read_text_safe(path)
    if not text:
        return {}

    hits = {}
    snippets = {}

    # Aadhaar
    aad_matches = [m.group(0) for m in AADHAAR_RE.finditer(text)]
    if aad_matches:
        hits["aadhaar"] = aad_matches
        spans = [(m.start(), m.end()) for m in AADHAAR_RE.finditer(text)]
        snippets["aadhaar"] = _find_snippets(text, spans)

    # PAN
    pan_matches = [m.group(0) for m in PAN_RE.finditer(text)]
    if pan_matches:
        hits["pan"] = pan_matches
        spans = [(m.start(), m.end()) for m in PAN_RE.finditer(text)]
        snippets["pan"] = _find_snippets(text, spans)

    # Email
    email_matches = [m.group(0) for m in EMAIL_RE.finditer(text)]
    if email_matches:
        hits["email"] = email_matches
        spans = [(m.start(), m.end()) for m in EMAIL_RE.finditer(text)]
        snippets["email"] = _find_snippets(text, spans)

    # Phone
    phone_matches = [m.group(0) for m in PHONE_RE.finditer(text)]
    if phone_matches:
        hits["phone"] = phone_matches
        spans = [(m.start(), m.end()) for m in PHONE_RE.finditer(text)]
        snippets["phone"] = _find_snippets(text, spans)

    # Passport
    passport_matches = [m.group(0) for m in PASSPORT_RE.finditer(text)]
    if passport_matches:
        hits["passport"] = passport_matches
        spans = [(m.start(), m.end()) for m in PASSPORT_RE.finditer(text)]
        snippets["passport"] = _find_snippets(text, spans)

    # Password-like tokens
    pwd_matches = [m.group(2) for m in PASSWORD_TOKEN_RE.finditer(text)]
    if pwd_matches:
        hits["password_token"] = pwd_matches
        spans = [(m.start(), m.end()) for m in PASSWORD_TOKEN_RE.finditer(text)]
        snippets["password_token"] = _find_snippets(text, spans)

    # Credit card with Luhn
    cc_candidates = [m.group(0) for m in CC_RE.finditer(text)]
    cc_valid = []
    cc_spans = []
    for m in CC_RE.finditer(text):
        candidate = m.group(0)
        if _luhn_check(candidate):
            cc_valid.append(re.sub(r"[ -]", "", candidate))
            cc_spans.append((m.start(), m.end()))
    if cc_valid:
        hits["credit_card"] = cc_valid
        snippets["credit_card"] = _find_snippets(text, cc_spans)

    # Confidence (simple)
    confidence = "low"
    if hits:
        # if any explicit keyword present near matches, boost
        lower = text.lower()
        keyword_hits = sum(1 for kw in SENSITIVE_KEYWORDS if kw in lower)
        if keyword_hits >= 2:
            confidence = "high"
        else:
            confidence = "medium"

    context = compute_context_score(text)
    risk_score = compute_risk_score(hits, confidence, context)
    risk_label = score_label_from_score(risk_score)

    return {
        "hits": hits,
        "snippets": snippets,
        "confidence": confidence,
        "context_score": round(context, 3),
        "risk_score": risk_score,
        "risk_label": risk_label,
    }

def scan_directory(root_path: str) -> Dict[str, Dict]:
    root = Path(root_path)
    results = {}
    if not root.exists():
        return results
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        try:
            res = scan_file(p)
            if res:
                results[str(p)] = res
        except Exception:
            continue
    return results



MODEL_PATH = os.path.join("data", "context_model.joblib")

def train_context_model(samples, labels):
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    import joblib

    vec = TfidfVectorizer()
    X = vec.fit_transform(samples)
    clf = LogisticRegression(max_iter=200)
    clf.fit(X, labels)

    # Ensure directory exists
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)

    joblib.dump((vec, clf), MODEL_PATH)
    print(f"✅ Model saved at {MODEL_PATH}")