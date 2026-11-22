# ShareSafe 🛡️
> **"Pause before you share."** / **"शेयर करने से पहले, एक पल रुकिए।"**

ShareSafe is an **on-device, intelligent privacy guardian** that sits between users and the "Send" button on WhatsApp, email, or any file-sharing app. It automatically:

- Detects **sensitive Indian identity fields** (Aadhaar, PAN, Payment Cards, Phone, DOB, IFSC, Account Numbers, QR Codes)
- Runs a **Rule-Based Privacy Intelligence Engine** (RBI & UIDAI guideline–aligned) to explain risks and recommend masking
- **Masks or blurs** private fields with one click
- Applies **non-reusable purpose watermarks** so a document can't be misused for a different purpose
- Generates **self-expiring, server-enforced secure sharing links** that auto-delete the file on expiry
- Logs all access events in a **tamper-evident audit trail** (zero document content ever stored)
- Runs **100% on-device** — nothing is uploaded, stored externally, or sent to any cloud

---

## 🔒 Security & Privacy Guarantees

| Guarantee | How it's enforced |
|---|---|
| **On-device processing** | All OCR, detection, masking in-memory via Python |
| **No cloud leakage** | Zero network calls; SQLite only on localhost |
| **Verhoeff validation** | Eliminates false Aadhaar positives from random 12-digit strings |
| **Luhn validation** | Eliminates false card number positives |
| **Expiry enforced server-side** | `expires_at` checked in SQLite on every document access, not just the frontend |
| **Originals never shared** | Only the masked+watermarked image is saved to `.secure_shares/` |
| **Audit log privacy** | Only token preview (first 8 chars) and event type logged — zero document content |
| **Screenshots** | Cannot be prevented in a browser-based app — always disclosed to users |

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10 or higher
- (Optional) [Tesseract-OCR](https://github.com/UB-Mannheim/tesseract/wiki) installed at `C:\Program Files\Tesseract-OCR\tesseract.exe`
  — if absent, ShareSafe **auto-falls back to EasyOCR** (downloads ~140 MB models on first run, then cached)

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Run all test suites
```bash
# Stage 1 — Validators + OCR detection engine
python test_stage1.py

# Secure Links — Expiry, revocation, invalid token rejection
python test_secure_links.py

# Platform Upgrade — Privacy Intelligence + Audit Log
python test_platform_upgrade.py
```

Expected output for all three:
```
[PASSED] ...
ALL ... TESTS PASSED SUCCESSFULLY!
```

### 3. Launch the web app
```bash
streamlit run app.py
```

Then open **http://localhost:8501** in your browser.

---

## 🏗️ Architecture

```
ShareSafe/
├── app.py                  ← Streamlit UI: 4-step flow + Recipient view (?share=<token>)
├── detector.py             ← Dual-engine OCR (Tesseract→EasyOCR), spatial token merger, QR detection
├── validators.py           ← Verhoeff (Aadhaar), Luhn (Cards), PAN, Phone, IFSC, DOB
├── masker.py               ← Full blackout / partial (last 4) / Gaussian blur + purpose watermark
├── samples.py              ← Synthetic Aadhaar, PAN, Cheque/Card demo generators (no real data)
├── intelligence.py         ← Rule-Based Privacy Intelligence Engine (RBI & UIDAI guidelines)
├── secure_links.py         ← Self-expiring secure links, server-side TTL, audit log (SQLite)
├── i18n.py                 ← Bilingual strings: English + हिन्दी
├── test_stage1.py          ← Unit tests: validators + OCR detection
├── test_secure_links.py    ← Unit tests: expiry, revocation, invalid tokens
├── test_platform_upgrade.py← Unit tests: intelligence engine + audit log
├── requirements.txt
└── README.md
```

### How the modules connect

```
app.py
  ├── detector.py        (OCR + entity extraction)
  ├── intelligence.py    (purpose classification → masking recommendations)
  ├── masker.py          (apply masks + watermark)
  ├── secure_links.py    (create/validate/revoke links + audit log)
  ├── samples.py         (generate demo cards for hackathon)
  └── i18n.py            (English ↔ Hindi)
```

---

## 🔍 Feature Details

### 1. AI-Style Privacy Intelligence (`intelligence.py`)
- Classifies the **sharing purpose** from the watermark text (Bank KYC, Hotel, SIM, Job, Rental, General)
- Maps each detected field against **RBI Master Directions** and **UIDAI KYC regulations**
- Flags **Excessive Data Exposure** (e.g. sharing PAN or card number with a hotel)
- One-click **"Apply Recommended Masking"** button applies the policy instantly
- Generates a **Privacy Protection Report** (Markdown, downloadable)
- Transparently labeled: **"Rule-Based Privacy Intelligence Engine — not an AI model"**

### 2. Secure Backend (`secure_links.py`)
- **Cryptographic tokens**: 256-bit URL-safe tokens via `secrets.token_urlsafe(32)`
- **TTL presets**: 1 hour, 6 hours, 24 hours (default), 7 days, or custom minutes
- **Server-side expiry**: checked in SQLite on every `get_shared_document()` call
- **File cleanup**: expired file is deleted from `.secure_shares/documents/` on first access after expiry
- **Manual revocation**: immediate — file deleted and token blacklisted in one transaction
- **Invalid/tampered tokens**: return a clear error, never expose any document

### 3. Access Audit Log (`secure_links.py → audit_logs table`)
Events recorded (zero document content ever stored):
| Event | When |
|---|---|
| `LINK_CREATED` | Link generated by sender |
| `ACCESS_SUCCESSFUL` | Valid recipient opens the document |
| `ACCESS_BLOCKED_EXPIRED` | Access attempt on expired link |
| `ACCESS_BLOCKED_REVOKED` | Access attempt on revoked link |
| `MANUALLY_REVOKED` | Sender manually revokes before expiry |
| `FILE_PURGED` | Server file deleted (expiry or revocation) |

Viewable in the **sidebar → 📋 Access Audit Log** expander in the app.

### 4. Demo Experience
- **Sample documents**: "Try Sample Aadhaar / PAN / Cheque" buttons generate realistic synthetic cards with fake-but-valid numbers (Verhoeff + Luhn)
- **Step indicator**: `1 Upload → 2 Review → 3 Protect → 4 Share`
- **Side-by-side preview**: Original vs Protected
- **Privacy Risk Score gauge**: 0–100, drops in real time as fields are masked
- **Success card**: "🎉 You Shared Safely! Risk reduced from X → Y"
- **Bilingual**: toggle English ↔ हिन्दी in the sidebar

---

## 🌊 User Flow (Step-by-Step)

```
1. UPLOAD     → drag-drop a photo, or click "Try Sample Aadhaar/PAN/Card"
2. REVIEW     → OCR runs → "✋ Wait! Sensitive info detected" alert
                Intelligence panel shows purpose profile + policy guidance
                Privacy Risk Score badge (0–100, colour-coded)
                Per-field checkboxes with risk level + reason
                "⚡ Apply Recommended Masking" one-click button
3. PROTECT    → Choose masking mode: Partial (last 4) / Full blackout / Blur / Original
                Enter sharing purpose (watermark text)
                Side-by-side Original vs Protected preview
4. SHARE      → Consent checkbox → Download PNG  OR  Generate Expiring Link
                Link tab: choose TTL → copy URL → share
                Recipient opens ?share=<token> → sees countdown timer
                Revoke button: immediate invalidation + file deletion
```

---

## 🗺️ Future Roadmap (not built)

1. **Android Share-Sheet Integration** — register as `ACTION_SEND` Intent filter so ShareSafe intercepts before WhatsApp/Gmail transmit the image
2. **On-Device Face & Signature Redaction** — MediaPipe / ONNX lightweight ML to auto-blur passport photos and handwritten signatures
3. **Browser Extension** — intercept `<input type="file">` on job boards and unsecured portals before upload

---

## ⚠️ Disclaimer

- ShareSafe uses **entirely synthetic** test documents. No real Aadhaar or PAN numbers are used anywhere.
- Self-expiring links delete the **server copy** of the file. They cannot delete screenshots or offline copies already downloaded by recipients.
- The Privacy Intelligence Engine is **rule-based** (deterministic, explainable). It is not an AI/ML model and does not connect to any external API.
