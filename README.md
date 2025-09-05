## SecureAI Backup: Intelligent Backup & Recovery System

[See Architecture](https://drive.google.com/file/d/190P-AZAjZDAZOysfTAjr6varqcfhyqxR/view?usp=sharing)


---

## 🔹 Features Breakdown

### 1. **AI-Powered Data Leak Prevention (DLP) in Backup**

👉 **Goal**: backup hone se pehle sensitive data detect ho aur bina encryption ke save na ho.

* **Tech**:

  * Regex + NLP models to detect Aadhar, PAN, credit card numbers, email IDs.
  * Example: regex for `\d{4}\s\d{4}\s\d{4}` → Aadhaar pattern.
  * ML model (like spaCy NER / HuggingFace small model) for sensitive entity detection.
* **Workflow**:

  * User selects folder → system scans files → sensitive data detect → encrypt before backup (AES-256).
  * Alert user: *“Sensitive data found, encryption applied.”*

---

### 2. **Ransomware Detection in Backups**

👉 **Goal**: agar koi ransomware se infected/encrypted files backup ho rahi hain to system alert kare.

* **Tech**:

  * File entropy calculation (high entropy = suspicious).
  * Sudden mass file renaming (e.g., all `.docx` → `.locked`).
  * ML classifier trained on normal vs ransomware encrypted file samples.
* **Workflow**:

  * Backup module analyze kare → agar suspicious pattern mile to “Quarantine Backup” flag.
  * User ko alert: *“Potential ransomware detected in backup batch XYZ.”*

---

### 3. **Honey Backup System** 🐝

👉 **Goal**: hacker ko phasane ke liye ek fake backup ready rahe.

* **Tech**:

  * Create duplicate “decoy backup” with dummy files.
  * Honeytoken mechanism: agar koi access kare toh trigger alert + log attacker details.
* **Workflow**:

  * Real backup securely stored.
  * Honey backup looks same but contains markers (e.g., hidden “DO NOT OPEN.txt” file).
  * If accessed → system instantly sends alert email/notification.

---

## 🔹 Tech Stack

* **Frontend**: React + Tailwind (backup UI, scan results, alerts)
* **Backend**: FastAPI / Flask (backup service + AI modules)
* **Database**: MongoDB / SQLite (store backup metadata, alerts, honeytrap logs)
* **ML/NLP**:

  * Regex + spaCy/HuggingFace (for DLP)
  * Custom classifier (scikit-learn / PyTorch) for ransomware detection
* **Security**: AES-256 encryption for sensitive files
* **Monitoring**: Logging + alerts (maybe email/SMS using Twilio/SendGrid API)

---

## 🔹 Demo Flow (Commvault ko impress karne ke liye 💯)

1. **Backup Start** → System scans → shows “Sensitive data detected → encrypting” ✅
2. **Backup Analysis** → Detects few files as ransomware-encrypted → shows alert 🚨
3. **Restore Attempt by Attacker** → Honey Backup accessed → Alert triggered 🔔 (logs attacker info)

---

## 🔹 Extra (Bonus Impress Points)

* Dashboard with **threat score** (like: “Backup Security Score: 85/100”)
* Graphs showing ransomware detection trends
* Option to integrate with **SIEM tools** (like Splunk, Elastic)




