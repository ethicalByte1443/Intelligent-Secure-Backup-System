# SecureAI Backup — Intelligent Backup & Recovery System

[See Architecture diagram](https://drive.google.com/file/d/190P-AZAjZDAZOysfTAjr6varqcfhyqxR/view?usp=sharing)

---

## 🔹 Feature Overview

### 1. **AI-Powered Data Leak Prevention (DLP) for Backups**

**Goal:** Detect sensitive data before backing it up and ensure it is never stored without encryption.

**Techniques:**

* Regex + NLP models to detect Aadhaar, PAN, credit card numbers, email IDs, etc.
* Example: Aadhaar regex `\d{4}\s\d{4}\s\d{4}`.
* Use an ML/NLP model (spaCy NER or a small HuggingFace model) for robust sensitive-entity detection.

**Workflow:**

1. User selects folder.
2. The system scans files for sensitive information.
3. If sensitive data is found, the file is encrypted (AES-256) before backup.
4. User is notified: “Sensitive data found — encryption applied.”

---

### 2. **Ransomware Detection in Backups**

**Goal:** If files being backed up are already infected or encrypted by ransomware, raise an alert and prevent compromised data from polluting the backup set.

**Techniques:**

* File entropy calculation (high entropy can indicate encrypted/malicious files).
* Detection of mass-renaming patterns (e.g., many `.docx` → `.locked`).
* A machine learning classifier trained on samples of normal files vs. ransomware-encrypted files.

**Workflow:**

1. The backup engine analyzes files.
2. If suspicious patterns are detected, the backup batch is flagged as “Quarantine Backup.”
3. User is notified: “Potential ransomware detected in backup batch XYZ.”

---

## 🔹 AI Monitoring & Internal Logs

When the system computes **context scores** and **risk scores**, detailed monitoring/logging runs for debugging and auditing. Logs are important for traceability while preserving confidentiality (paths redacted).

**Sample log trace (paths hidden):**

```
INFO:     Started server process [5812]
INFO:     Waiting for application startup.
INFO:     Application startup complete.

scan_directory : Started

test1.txt
context_score : Started
load_ml_model : Started
h_score : 0.16666666666666666  + ai_score : 0.6886560320854187  + ml_score : 0.5652289159334941
0.4950310876142157
compute_risk_score : Started
confidence : medium
context_score : 0.4950310876142157
-------------------------------
base : 20
conf_boost : 10
raw  44.85093262842647
return  45
-------------------------------

test2.txt
context_score : Started
load_ml_model : Started
h_score : 0.3333333333333333  + ai_score : 0.6598167419433594  + ml_score : 0.5660652443068904
0.5337462700694109
compute_risk_score : Started
confidence : high
context_score : 0.5337462700694109
-------------------------------
base : 20
conf_boost : 20
raw  61.34985080277644
return  61
-------------------------------

test4.txt
context_score : Started
load_ml_model : Started
h_score : 0.6666666666666666  + ai_score : 0.6758469343185425  + ml_score : 0.5911254159459445
0.6476763985112003
compute_risk_score : Started
confidence : high
context_score : 0.6476763985112003
-------------------------------
base : 40
conf_boost : 20
raw  98.860583910672
return  99
-------------------------------

text3.txt
context_score : Started
load_ml_model : Started
h_score : 0.16666666666666666  + ai_score : 0.6647664904594421  + ml_score : 0.5424601270550792
0.4786446343003006
compute_risk_score : Started
confidence : medium
context_score : 0.4786446343003006
-------------------------------
base : 20
conf_boost : 10
raw  44.359339029009014
return  44
-------------------------------

text5.txt
context_score : Started
load_ml_model : Started
h_score : 0.6666666666666666  + ai_score : 0.520253598690033  + ml_score : 0.5328629812888575
0.5679603338626704
compute_risk_score : Started
confidence : low
context_score : 0.5679603338626704
-------------------------------
base : 0
conf_boost : 0
raw  0.0
return  0
-------------------------------
```

---

### 3. **Honey Backup System** 🐝

**Goal:** Lure attackers into interacting with decoy backups so you can detect malicious access and gather forensic information.

**Techniques & Workflow:**

* Create a duplicate “decoy backup” set with dummy files and honeytokens.
* The honey backup mirrors the real backup’s structure but contains markers (for example, a hidden `DO_NOT_OPEN.txt` file).
* If the decoy is accessed, an immediate alert is triggered and attacker access is logged.

---

## 🔹 Technology Stack

* **Frontend:** React + Tailwind (UI for backup configuration, scan results, and alerts)
* **Backend:** FastAPI or Flask (backup service and AI modules)
* **Database:** MongoDB or SQLite (stores backup metadata, alerts, honeytrap logs)
* **ML / NLP:** Regex + spaCy / HuggingFace for DLP; scikit-learn or PyTorch for ransomware detection
* **Security:** AES-256 encryption for sensitive files
* **Monitoring & Alerts:** Application logging + notifications (email/SMS via SendGrid/Twilio or similar)
* **Integration:** Optional SIEM integration (Splunk, Elastic)

---

## 🔹 Demo Flow

1. **Backup Start** → System scans selected data → displays “Sensitive data detected — encrypting”. ✅
2. **Backup Analysis** → System detects suspicious files flagged as possibly ransomware-encrypted → displays alert. 🚨
3. **Restore Attempt by Attacker** → Decoy (honey) backup is accessed → alert triggered and attacker activity logged. 🔔

---

## 🔹 Bonus Features 

* Dashboard with an overall **Backup Security Score** (e.g., “Backup Security Score: 85/100”)
* Time-series graphs showing ransomware detection trends and backup health
* Easy integration options with SIEM tools (Splunk, Elastic) for enterprise deployments

---
