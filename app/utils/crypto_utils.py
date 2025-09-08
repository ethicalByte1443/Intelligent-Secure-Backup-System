# app/utils/crypto_utils.py
from pathlib import Path
from cryptography.fernet import Fernet

KEY_PATH = Path("data/backup_key.key")

def get_or_create_key() -> bytes:
    """
    Ensure a symmetric key exists for backups. Returns key bytes.
    """
    if not KEY_PATH.parent.exists():
        KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    if KEY_PATH.exists():
        return KEY_PATH.read_bytes()
    key = Fernet.generate_key()
    KEY_PATH.write_bytes(key)
    return key

def get_fernet() -> Fernet:
    key = get_or_create_key()
    return Fernet(key)

def encrypt_str(value: str) -> str:
    """
    Encrypt a UTF-8 string and return a printable placeholder.
    We wrap encrypted base64 in a marker so you can detect encrypted tokens later.
    Format: <ENC>{base64-token}
    """
    f = get_fernet()
    tok = f.encrypt(value.encode("utf-8"))  # bytes (base64)
    return f"<ENC>{tok.decode('utf-8')}"

def decrypt_str(enc_placeholder: str) -> str:
    """
    Decrypt a placeholder produced by encrypt_str.
    If input is not in the expected format, raises ValueError.
    """
    if not enc_placeholder.startswith("<ENC>"):
        raise ValueError("Not an encrypted placeholder")
    b64 = enc_placeholder[len("<ENC>"):]
    f = get_fernet()
    return f.decrypt(b64.encode("utf-8")).decode("utf-8")
