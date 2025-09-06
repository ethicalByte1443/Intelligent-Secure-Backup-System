# app/utils/dlp.py
import os
import re
from pathlib import Path
from typing import List, Dict, Tuple
import joblib

# ---------------------------- ML imports ----------------------------
try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

MODEL_PATH = os.path.join("data", "context_model.joblib")
_CONTEXT_MODEL = None

# ---------------------------- Regex Patterns ----------------------------
AADHAAR_RE = re.compile(r"\b\d{12}\b")
PAN_RE = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")
CC_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"(?:\+91[\-\s]?|0)?[6-9]\d{9}\b")
PASSPORT_RE = re.compile(r"\b[A-Z][0-9]{7}\b")
PASSWORD_RE = re.compile(r"(password|passwd|pwd|passcode)\s*[:#\-]?\s*([^\s,;]{4,40})", re.IGNORECASE)

SENSITIVE_KEYWORDS = [
    "aadhaar","pan","credit card","card number","cvv","upi",
    "password","pwd","passport","passport no","bank account",
    "account number","ifsc","salary","payroll","ssn","social security",
    "secret","confidential"
]

# ---------------------------- Helpers ----------------------------
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

def _read_file_safe(path: Path, max_bytes: int = 200_000) -> str:
    try:
        raw = path.read_bytes()
        if len(raw) > max_bytes:
            raw = raw[:max_bytes]
        return raw.decode(errors="ignore")
    except Exception:
        return ""

def _find_snippets(text: str, spans: List[Tuple[int,int]], context: int = 40) -> List[str]:
    snippets = []
    for (s,e) in spans:
        start = max(0, s-context)
        end = min(len(text), e+context)
        snippet = text[start:end].replace("\n"," ").replace("\r"," ")
        snippets.append(snippet.strip())
    return snippets

# ---------------------------- ML ----------------------------
def train_context_model(samples: List[str], labels: List[int]):
    if not HAS_SKLEARN:
        raise RuntimeError("scikit-learn required")
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    vec = TfidfVectorizer(ngram_range=(1,2), max_features=5000)
    X = vec.fit_transform(samples)
    clf = LogisticRegression(max_iter=1000)
    clf.fit(X, labels)
    joblib.dump((vec, clf), MODEL_PATH)
    print(f"✅ Context model saved at {MODEL_PATH}")

def load_context_model():
    global _CONTEXT_MODEL
    if _CONTEXT_MODEL:
        return _CONTEXT_MODEL
    if HAS_SKLEARN and os.path.exists(MODEL_PATH):
        _CONTEXT_MODEL = joblib.load(MODEL_PATH)
        return _CONTEXT_MODEL
    return None

def predict_context_ml(text: str) -> float:
    model = load_context_model()
    if not model:
        return 0.0
    vec, clf = model
    X = vec.transform([text])
    return float(clf.predict_proba(X)[0,1])

def context_score(text: str) -> float:
    hscore = sum(1 for kw in SENSITIVE_KEYWORDS if kw in text.lower())
    hscore = min(hscore / 6.0, 1.0)
    mlscore = 0.0
    if HAS_SKLEARN and os.path.exists(MODEL_PATH):
        try:
            mlscore = predict_context_ml(text)
        except Exception:
            mlscore = 0.0
    if mlscore > 0:
        return min(1.0, 0.4*hscore + 0.6*mlscore)
    return hscore

# ---------------------------- Risk scoring ----------------------------
def compute_risk_score(hits: Dict, confidence: str, context_score: float) -> int:
    n = len(hits)
    base = 20 * n
    conf_map = {"low":0, "medium":10, "high":20}
    conf_boost = conf_map.get(confidence, 0)
    raw = (base + conf_boost) * (1.0 + context_score)
    return max(0, min(100, int(round(raw))))

def risk_label(score: int) -> str:
    if score >= 70: return "High"
    if score >= 35: return "Medium"
    return "Low"

# ---------------------------- Scan file ----------------------------
def scan_file(path: Path) -> Dict:
    text = _read_file_safe(path)
    if not text: return {}

    hits = {}
    snippets = {}

    # Aadhaar
    m = [m.group(0) for m in AADHAAR_RE.finditer(text)]
    if m:
        hits["aadhaar"] = m
        spans = [(m.start(), m.end()) for m in AADHAAR_RE.finditer(text)]
        snippets["aadhaar"] = _find_snippets(text, spans)
    # PAN
    m = [m.group(0) for m in PAN_RE.finditer(text)]
    if m:
        hits["pan"] = m
        spans = [(m.start(), m.end()) for m in PAN_RE.finditer(text)]
        snippets["pan"] = _find_snippets(text, spans)
    # CC
    cc_candidates = [m.group(0) for m in CC_RE.finditer(text)]
    cc_valid = []
    cc_spans = []
    for m in CC_RE.finditer(text):
        if _luhn_check(m.group(0)):
            cc_valid.append(re.sub(r"[ -]","", m.group(0)))
            cc_spans.append((m.start(), m.end()))
    if cc_valid:
        hits["credit_card"] = cc_valid
        snippets["credit_card"] = _find_snippets(text, cc_spans)
    # Email
    m = [m.group(0) for m in EMAIL_RE.finditer(text)]
    if m:
        hits["email"] = m
        spans = [(m.start(), m.end()) for m in EMAIL_RE.finditer(text)]
        snippets["email"] = _find_snippets(text, spans)
    # Phone
    m = [m.group(0) for m in PHONE_RE.finditer(text)]
    if m:
        hits["phone"] = m
        spans = [(m.start(), m.end()) for m in PHONE_RE.finditer(text)]
        snippets["phone"] = _find_snippets(text, spans)
    # Passport
    m = [m.group(0) for m in PASSPORT_RE.finditer(text)]
    if m:
        hits["passport"] = m
        spans = [(m.start(), m.end()) for m in PASSPORT_RE.finditer(text)]
        snippets["passport"] = _find_snippets(text, spans)
    # Password
    m = [m.group(2) for m in PASSWORD_RE.finditer(text)]
    if m:
        hits["password"] = m
        spans = [(m.start(), m.end()) for m in PASSWORD_RE.finditer(text)]
        snippets["password"] = _find_snippets(text, spans)

    # Confidence
    conf = "low"
    if hits:
        kw_hits = sum(1 for kw in SENSITIVE_KEYWORDS if kw in text.lower())
        conf = "high" if kw_hits >= 2 else "medium"

    ctx = context_score(text)
    risk = compute_risk_score(hits, conf, ctx)
    label = risk_label(risk)

    return {
        "hits": hits,
        "snippets": snippets,
        "confidence": conf,
        "context_score": round(ctx,3),
        "risk_score": risk,
        "risk_label": label
    }

# ---------------------------- Scan directory ----------------------------
def scan_directory(root_path: str) -> Dict[str, Dict]:
    root = Path(root_path)
    results = {}
    if not root.exists(): return results
    for p in root.rglob("*"):
        if not p.is_file(): continue
        try:
            res = scan_file(p)
            if res:
                results[str(p)] = res
        except Exception:
            continue
    return results
