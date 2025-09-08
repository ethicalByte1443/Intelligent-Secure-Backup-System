# import os
# import json
# import shutil
# from datetime import datetime
# from pathlib import Path
# from fastapi import APIRouter, HTTPException
# from utils.dlp import scan_directory

# router = APIRouter()

# BACKUP_DIR = Path("data/backups")
# METADATA_FILE = BACKUP_DIR / "metadata.json"

# # ensure folders exist
# BACKUP_DIR.mkdir(parents=True, exist_ok=True)
# if not METADATA_FILE.exists():
#     with open(METADATA_FILE, "w") as f:
#         json.dump([], f)


# def load_metadata():
#     with open(METADATA_FILE, "r") as f:
#         return json.load(f)


# def save_metadata(data):
#     with open(METADATA_FILE, "w") as f:
#         json.dump(data, f, indent=2)


# @router.post("/backup")
# def create_backup(payload: dict):
#     source = payload.get("sourcePath")
#     name = payload.get("backupName")

#     if not source or not name:
#         raise HTTPException(status_code=400, detail="sourcePath and backupName required")
#     if not os.path.exists(source):
#         raise HTTPException(status_code=400, detail="Source path does not exist")

#     backup_path = BACKUP_DIR / name
#     if backup_path.exists():
#         raise HTTPException(status_code=400, detail="Backup name already exists")

#     # Run DLP scan before backup
#     findings = scan_directory(source)

#     # Perform copy
#     shutil.copytree(source, backup_path)

#     # Prepare metadata entry
#     total_files = sum(len(files) for _, _, files in os.walk(source))
#     sensitive_files = len(findings)
#     risk_label = "Low"
#     if sensitive_files > 0:
#         risk_scores = [info.get("risk_score", 0) for info in findings.values()]
#         avg_score = sum(risk_scores) / len(risk_scores)
#         if avg_score >= 70:
#             risk_label = "High"
#         elif avg_score >= 35:
#             risk_label = "Medium"

#     entry = {
#         "backupName": name,
#         "sourcePath": os.path.abspath(source),
#         "backupPath": str(backup_path),
#         "createdAt": datetime.now().isoformat(),
#         "totalFiles": total_files,
#         "sensitiveFiles": sensitive_files,
#         "riskLabel": risk_label,
#     }

#     # Save metadata
#     data = load_metadata()
#     data.append(entry)
#     save_metadata(data)

#     return {"message": "Backup created successfully", "metadata": entry}


# @router.get("/backups")
# def list_backups():
#     return load_metadata()


# @router.get("/backup/{name}")
# def get_backup(name: str):
#     data = load_metadata()
#     for entry in data:
#         if entry["backupName"] == name:
#             return entry
#     raise HTTPException(status_code=404, detail="Backup not found")


# @router.delete("/backup/{name}")
# def delete_backup(name: str):
#     data = load_metadata()
#     entry = None
#     for e in data:
#         if e["backupName"] == name:
#             entry = e
#             break
#     if not entry:
#         raise HTTPException(status_code=404, detail="Backup not found")

#     # Remove backup folder
#     backup_path = Path(entry["backupPath"])
#     if backup_path.exists():
#         shutil.rmtree(backup_path)

#     # Update metadata
#     data = [e for e in data if e["backupName"] != name]
#     save_metadata(data)

#     return {"message": f"Backup '{name}' deleted successfully"}


# app/routes/backup_routes.py
import os
import re
import json
import shutil
from datetime import datetime
from pathlib import Path
from fastapi import APIRouter, HTTPException

from utils.dlp import scan_directory  # <-- use your existing scan
from utils.crypto_utils import encrypt_str, get_or_create_key

router = APIRouter()

BACKUP_DIR = Path("data/backups")
METADATA_FILE = BACKUP_DIR / "metadata.json"

# ensure folders exist
BACKUP_DIR.mkdir(parents=True, exist_ok=True)
if not METADATA_FILE.exists():
    with open(METADATA_FILE, "w", encoding="utf-8") as f:
        json.dump([], f)


# -------------------------
# Helpers
# -------------------------
def load_metadata():
    with open(METADATA_FILE, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except Exception:
            return []


def save_metadata(data):
    with open(METADATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def _is_text_file(path: Path) -> bool:
    """Heuristic check for text file."""
    try:
        with open(path, "rb") as f:
            chunk = f.read(2048)
            if b"\0" in chunk:
                return False
            chunk.decode("utf-8")
            return True
    except Exception:
        return False


def _encrypt_sensitive_in_text(content: str, hits: dict) -> str:
    """Replace detected sensitive tokens with encrypted placeholders."""
    if not hits:
        return content

    tokens = []
    for _, vals in hits.items():
        for v in vals:
            if v:
                tokens.append(v)

    # sort by longest first to avoid partial overlaps
    sorted_tokens = sorted(set(tokens), key=lambda s: -len(s))
    out = content
    for tok in sorted_tokens:
        try:
            enc = encrypt_str(tok)
            out = out.replace(tok, enc)
        except Exception:
            continue
    return out


def _process_and_copy_file(src: Path, dst: Path, findings_for_file: dict):
    """Copy one file, encrypt sensitive content if needed."""
    dst.parent.mkdir(parents=True, exist_ok=True)

    risk_label = findings_for_file.get("risk_label") if findings_for_file else None
    if not findings_for_file or (risk_label not in ("Medium", "High")):
        shutil.copy2(src, dst)
        return False  # no encryption

    if not _is_text_file(src):
        shutil.copy2(src, dst)
        return False

    try:
        text = src.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        shutil.copy2(src, dst)
        return False

    hits = findings_for_file.get("hits", {})

    # fallback if no hits but risk is medium/high → guess credentials
    if not hits:
        extra_hits = {}
        pwd_pattern = re.compile(r"(password|passwd|pwd)\s*[:=]\s*([^\s,;]{4,40})", re.IGNORECASE)
        found = [m.group(2) for m in pwd_pattern.finditer(text)]
        if found:
            extra_hits["password"] = found
        email_pattern = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
        found = [m.group(0) for m in email_pattern.finditer(text)]
        if found:
            extra_hits["email"] = list(set(found))
        hits = extra_hits

    new_text = _encrypt_sensitive_in_text(text, hits)

    try:
        dst.write_text(new_text, encoding="utf-8")
        return True
    except Exception:
        shutil.copy2(src, dst)
        return False


# -------------------------
# Routes
# -------------------------
@router.post("/backup")
def create_backup(payload: dict):
    source = payload.get("sourcePath")
    name = payload.get("backupName")

    if not source or not name:
        raise HTTPException(status_code=400, detail="sourcePath and backupName required")
    if not os.path.exists(source):
        raise HTTPException(status_code=400, detail="Source path does not exist")

    backup_path = BACKUP_DIR / name
    if backup_path.exists():
        raise HTTPException(status_code=400, detail="Backup name already exists")

    # ensure key exists
    get_or_create_key()

    findings = scan_directory(source)

    encrypted_files_count = 0
    total_copied = 0
    for root, _, files in os.walk(source):
        rel_root = Path(root).relative_to(Path(source))
        for fn in files:
            src_file = Path(root) / fn
            rel_dest = backup_path / rel_root / fn
            findings_for_file = findings.get(str(src_file))
            try:
                encrypted = _process_and_copy_file(src_file, rel_dest, findings_for_file)
            except Exception:
                rel_dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src_file, rel_dest)
                encrypted = False
            if encrypted:
                encrypted_files_count += 1
            total_copied += 1

    # metadata
    total_files = total_copied
    sensitive_files = len(findings)
    avg_score = 0
    if sensitive_files > 0:
        risk_scores = [info.get("risk_score", 0) for info in findings.values()]
        avg_score = sum(risk_scores) / len(risk_scores)
    risk_label = "Low"
    if avg_score >= 70:
        risk_label = "High"
    elif avg_score >= 35:
        risk_label = "Medium"

    entry = {
        "backupName": name,
        "sourcePath": os.path.abspath(source),
        "backupPath": str(backup_path),
        "createdAt": datetime.now().isoformat(),
        "totalFiles": total_files,
        "sensitiveFiles": sensitive_files,
        "encryptedFiles": encrypted_files_count,
        "avgRiskScore": round(avg_score, 2),
        "riskLabel": risk_label,
    }

    data = load_metadata()
    data.append(entry)
    save_metadata(data)

    return {"message": "Backup created successfully", "metadata": entry}


@router.get("/backups")
def list_backups():
    return load_metadata()


@router.get("/backup/{name}")
def get_backup(name: str):
    data = load_metadata()
    for entry in data:
        if entry["backupName"] == name:
            return entry
    raise HTTPException(status_code=404, detail="Backup not found")


@router.delete("/backup/{name}")
def delete_backup(name: str):
    data = load_metadata()
    entry = next((e for e in data if e["backupName"] == name), None)
    if not entry:
        raise HTTPException(status_code=404, detail="Backup not found")

    backup_path = Path(entry["backupPath"])
    if backup_path.exists():
        shutil.rmtree(backup_path)

    data = [e for e in data if e["backupName"] != name]
    save_metadata(data)

    return {"message": f"Backup '{name}' deleted successfully"}
