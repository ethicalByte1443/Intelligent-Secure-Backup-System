# app/utils/dlp.py
import os
import re
import numpy as np
from pathlib import Path
from typing import Dict, List, Tuple
import joblib

# -----------------------------
# Optional ML / AI libraries
# -----------------------------
try:
    from sentence_transformers import SentenceTransformer
    HAS_AI = True
    HAS_ML = True
    AI_MODEL = SentenceTransformer('all-MiniLM-L6-v2')
    print("ai monitoring...")
    _ML_MODEL_PATH = Path(r"C:\Users\Aseem\Desktop\GIT\Intelligent-Secure-Backup-System\data\context_model.joblib")
    print(_ML_MODEL_PATH)
    _ML_MODEL_CACHE = None
except ImportError:
    HAS_AI = False
    HAS_ML = False
    AI_MODEL = None
    _ML_MODEL_PATH = None
    _ML_MODEL_CACHE = None

# -----------------------------
# Regex patterns for sensitive info
# -----------------------------
AADHAAR_RE = re.compile(r"\b\d{12}\b")
PAN_RE = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")
CC_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"(?:\+91[\-\s]?|0)?[6-9]\d{9}\b")
PASSPORT_RE = re.compile(r"\b[A-Z][0-9]{7}\b")
PASSWORD_RE = re.compile(
    r"(password|passwd|pwd|passcode|pass:)\s*[:#\-]?\s*([^\s,;]{4,40})",
    re.IGNORECASE
)

# ✅ NEW regex
BANK_AC_RE = re.compile(r"\b\d{9,18}\b")   # Bank account numbers
IFSC_RE = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")  # IFSC code format
CVV_RE = re.compile(r"\b\d{3,4}\b")  # 3 or 4 digit CVV


SENSITIVE_KEYWORDS = [
    "aadhaar", "pan", "credit card", "card number", "cvv", "upi",
    "password", "pwd", "passport", "passport no", "bank account",
    "account number", "ifsc", "salary", "payroll", "ssn", "social security",
    "secret", "confidential"
]

# -----------------------------
# Helper functions
# -----------------------------
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

def _find_snippets(text: str, match_spans: List[Tuple[int,int]], context: int = 40) -> List[str]:
    snippets = []
    for (s,e) in match_spans:
        start = max(0, s - context)
        end = min(len(text), e + context)
        snippet = text[start:end].replace("\n", " ").replace("\r", " ")
        snippets.append(snippet.strip())
    return snippets

# -----------------------------
# AI-based semantic context score
# -----------------------------
def compute_context_score_ai(text: str) -> float:
    if not HAS_AI:
        return 0.0
    text_emb = AI_MODEL.encode([text]) # type: ignore
    keyword_emb = AI_MODEL.encode(SENSITIVE_KEYWORDS) # pyright: ignore[reportOptionalMemberAccess]
    sim = np.dot(text_emb, keyword_emb.T) / (
        np.linalg.norm(text_emb, axis=1)[:, None] * np.linalg.norm(keyword_emb, axis=1)
    )
    return float(sim.max())

# -----------------------------
# Optional ML model for context
# -----------------------------
def load_ml_model():
    global _ML_MODEL_CACHE
    if _ML_MODEL_CACHE is not None:
        # print("load_ml_model ----- 1")
        return _ML_MODEL_CACHE
    if _ML_MODEL_PATH and _ML_MODEL_PATH.exists() and HAS_ML:
        _ML_MODEL_CACHE = joblib.load(_ML_MODEL_PATH)
        # print("load_ml_model ----- 1")
        return _ML_MODEL_CACHE
    # print("load_ml_model ----- 3")
    
    return None

def predict_context_ml(text: str) -> float:
    if not HAS_ML:
        return 0.0
    model = load_ml_model()
    if not model:
        return 0.0
    vec, clf = model
    X = vec.transform([text])
    return float(clf.predict_proba(X)[0][1])

# -----------------------------
# Combined context score
# -----------------------------
def context_score(text: str) -> float:
    # Regex / keyword heuristic
    # print("context_score : Started")
    h = sum(1 for kw in SENSITIVE_KEYWORDS if kw in text.lower())
    h_score = min(1.0, h / 6.0)
    # AI semantic
    ai_score = compute_context_score_ai(text)
    # ML model score
    ml_score = predict_context_ml(text)
    # Weighted hybrid
    # print("h_score : ",h_score, " + ai_score : ",ai_score, " + ml_score : ", ml_score)
    final = 0.3*h_score + 0.4*ai_score + 0.3*ml_score
    # print(final)
    return min(final, 1.0)

# -----------------------------
# Risk scoring
# -----------------------------
def compute_risk_score(hits: Dict, confidence: str, context_score: float) -> int:
    n_types = len(hits)
    # print("Compute_risk_score :", n_types)
    # print("confidence :",confidence)
    # print("context_score :",context_score)
    base = 20 * n_types
    conf_map = {"low": 0, "medium": 10, "high": 20}
    conf_boost = conf_map.get(confidence, 0)
    # print("base :",base)
    # print("conf_boost :",conf_boost)
    # print("context_score :",context_score)
    raw = (base + conf_boost) * (1.0 + context_score)
    # print("raw ", raw)
    # print("return ",max(0, min(100, int(round(raw)))))
    # print("-------------------------------")
    return max(0, min(100, int(round(raw))))

def risk_label(score: int) -> str:
    if score >= 70:
        return "High"
    elif score >= 35:
        return "Medium"
    return "Low"

# -----------------------------
# Scan single file (Hybrid)
# -----------------------------
def scan_file(path: Path) -> Dict:
    text = _read_file_safe(path)
    if not text:
        return {}

    hits = {}
    snippets = {}

    # Regex detections
    for name, regex in [
        ("aadhaar", AADHAAR_RE),
        ("pan", PAN_RE),
        ("email", EMAIL_RE),
        ("phone", PHONE_RE),
        ("passport", PASSPORT_RE),
    ]:
        m = [x.group(0) for x in regex.finditer(text)]
        if m:
            hits[name] = m
            spans = [(x.start(), x.end()) for x in regex.finditer(text)]
            snippets[name] = _find_snippets(text, spans)

    # Password
    m = [x.group(2) for x in PASSWORD_RE.finditer(text)]
    if m:
        hits["password"] = m
        spans = [(x.start(), x.end()) for x in PASSWORD_RE.finditer(text)]
        snippets["password"] = _find_snippets(text, spans)

# Bank Account
    m = [x.group(0) for x in BANK_AC_RE.finditer(text)]
    if m:
        hits["bank_account"] = m
        spans = [(x.start(), x.end()) for x in BANK_AC_RE.finditer(text)]
        snippets["bank_account"] = _find_snippets(text, spans)

    # IFSC Code
    m = [x.group(0) for x in IFSC_RE.finditer(text)]
    if m:
        hits["ifsc"] = m
        spans = [(x.start(), x.end()) for x in IFSC_RE.finditer(text)]
        snippets["ifsc"] = _find_snippets(text, spans)

    # CVV (special handling: must appear near "credit card" or "CVV")
    m = [x.group(0) for x in CVV_RE.finditer(text)]
    cvv_hits = []
    cvv_spans = []
    for x in CVV_RE.finditer(text):
        snippet = text[max(0, x.start() - 10): x.end() + 10].lower()
        if "cvv" in snippet or "card" in snippet:   # ✅ avoid false positives
            cvv_hits.append(x.group(0))
            cvv_spans.append((x.start(), x.end()))
    if cvv_hits:
        hits["cvv"] = cvv_hits
        snippets["cvv"] = _find_snippets(text, cvv_spans)


    # Credit Card
    cc_candidates = [m.group(0) for m in CC_RE.finditer(text)]
    cc_valid = []
    cc_spans = []
    for m in CC_RE.finditer(text):
        candidate = re.sub(r"[ -]", "", m.group(0))
        if _luhn_check(candidate):
            cc_valid.append(candidate)
            cc_spans.append((m.start(), m.end()))
    if cc_valid:
        hits["credit_card"] = cc_valid
        snippets["credit_card"] = _find_snippets(text, cc_spans)

    # Confidence heuristic
    conf = "low"
    if hits:
        kw_hits = sum(1 for kw in SENSITIVE_KEYWORDS if kw in text.lower())
        conf = "high" if kw_hits >= 2 else "medium"

    # Hybrid context score
    ctx = context_score(text)

    # Risk
    if not hits:
        # ✅ No actual sensitive info → force safe result
        risk = 0
        label = "Low"
    else:
        risk = compute_risk_score(hits, conf, ctx)
        label = risk_label(risk)

    return {
        "hits": hits,
        "snippets": snippets,
        "confidence": conf,
        "context_score": round(ctx, 3),
        "risk_score": risk,
        "risk_label": label
    }


# -----------------------------
# Scan directory
# -----------------------------
def scan_directory(root_path: str) -> Dict[str, Dict]:
    print("scan directory called : -> ")
    root = Path(root_path)
    results = {}
    if not root.exists():
        return results
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        try:
            print(p)
            res = scan_file(p)
            if res:
                results[str(p)] = res
        except Exception:
            continue
    print(results)
    return results
