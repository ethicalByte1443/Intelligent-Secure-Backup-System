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

## 🔹 AI Monitoring & Internal Logs

System ke andar **context score + risk score calculation** ke waqt detailed monitoring hoti hai. Ye logs debugging aur auditing ke liye important hote hain.

Below is a **sample log trace** (paths hidden 🔒 for confidentiality):

```
INFO:     Started server process [5812]
INFO:     Waiting for application startup.
INFO:     Application startup complete.

scan_directory : Started

test1.txt
context_score : Started
load_ml_model : Started
h_score :  0.16666666666666666  + ai_score :  0.6886560320854187  + ml_score :  0.5652289159334941
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
h_score :  0.3333333333333333  + ai_score :  0.6598167419433594  + ml_score :  0.5660652443068904
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
h_score :  0.6666666666666666  + ai_score :  0.6758469343185425  + ml_score :  0.5911254159459445
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
h_score :  0.16666666666666666  + ai_score :  0.6647664904594421  + ml_score :  0.5424601270550792
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
h_score :  0.6666666666666666  + ai_score :  0.520253598690033  + ml_score :  0.5328629812888575
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







