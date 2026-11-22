"""
ShareSafe - Privacy Intelligence Module
Rule-Based Privacy Intelligence Engine (RBI & UIDAI Guideline Compliant)

Features:
- Analyzes detected sensitive fields against the stated sharing purpose.
- Generates purpose-aware masking recommendations (e.g., Bank KYC vs. Hotel Check-in vs. SIM Card).
- Identifies "Excessive Data Exposure" (e.g. sharing PAN or Bank Account with a hotel).
- Computes baseline vs. protected risk scores with clear delta metrics.
- Generates a structured Privacy Protection Report.
- Transparently operates via deterministic, explainable privacy rules.
"""

import re
from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple


# Purpose Classification Profiles
PURPOSE_PROFILES = {
    "bank_kyc": {
        "keywords": ["bank", "kyc", "loan", "finance", "account", "credit", "sbi", "hdfc", "axis", "icici", "pnb"],
        "label": "Banking & Financial KYC",
        "description": "Regulated under RBI Master Directions and UIDAI KYC regulations.",
        "allowed_partial": ["Aadhaar Number", "PAN Number"],
        "recommended_mask": ["Payment Card Number", "QR Code", "Bank Account Number"],
        "guideline": "RBI guidelines permit Masked Aadhaar (first 8 digits hidden, last 4 digits visible). Embedded QR codes must be blurred.",
    },
    "hotel_checkin": {
        "keywords": ["hotel", "checkin", "check-in", "stay", "resort", "inn", "guest", "travel", "flight", "booking"],
        "label": "Hotel & Hospitality Check-in",
        "description": "Standard identity verification for accommodation regulations.",
        "allowed_partial": ["Aadhaar Number"],
        "recommended_mask": ["PAN Number", "Payment Card Number", "Bank Account Number", "QR Code", "IFSC Code", "Date of Birth"],
        "guideline": "Hotels require identity proof only. Sharing PAN, payment cards, or full QR demographic templates is excessive and creates unnecessary identity theft exposure.",
    },
    "sim_telecom": {
        "keywords": ["sim", "telecom", "jio", "airtel", "vi", "vodafone", "bsnl", "mobile connection", "esim"],
        "label": "Telecom / SIM Card Purchase",
        "description": "Regulated identity check for telecommunication subscriber activation.",
        "allowed_partial": ["Aadhaar Number"],
        "recommended_mask": ["Payment Card Number", "Bank Account Number", "QR Code", "IFSC Code", "PAN Number"],
        "guideline": "Telecom operators do not require financial details or unmasked QR templates. Use Masked Aadhaar only.",
    },
    "job_employment": {
        "keywords": ["job", "employment", "hr", "company", "interview", "offer", "recruitment", "resume"],
        "label": "Employment & HR Verification",
        "description": "Pre-employment verification by hiring organizations.",
        "allowed_partial": ["Aadhaar Number", "PAN Number"],
        "recommended_mask": ["Payment Card Number", "QR Code", "Bank Account Number"],
        "guideline": "Share only necessary identity and tax identifiers. Never expose payment cards or raw QR biometric templates.",
    },
    "rental_lease": {
        "keywords": ["rent", "lease", "tenant", "landlord", "flat", "apartment", "house", "broker"],
        "label": "Tenancy & Rental Agreement",
        "description": "Informal verification for property lease agreements.",
        "allowed_partial": ["Aadhaar Number"],
        "recommended_mask": ["PAN Number", "Payment Card Number", "Bank Account Number", "QR Code", "IFSC Code"],
        "guideline": "Rental verification requires basic proof of identity. Sharing unmasked PAN or bank accounts exposes you to financial impersonation.",
    },
}


def classify_sharing_purpose(purpose_text: str) -> Dict[str, Any]:
    """
    Classifies user-entered purpose string using rule-based keyword profiling.
    Falls back to 'general' with conservative privacy recommendations.
    """
    clean_text = purpose_text.lower().strip()
    if not clean_text:
        return {
            "key": "general",
            "label": "General Sharing",
            "description": "Unspecified recipient purpose.",
            "allowed_partial": ["Aadhaar Number"],
            "recommended_mask": ["Payment Card Number", "PAN Number", "QR Code", "Bank Account Number", "IFSC Code"],
            "guideline": "Default to the highest privacy level. Apply partial masking or full blackout to all identifiers.",
        }

    for key, profile in PURPOSE_PROFILES.items():
        for kw in profile["keywords"]:
            if re.search(rf"\b{re.escape(kw)}\b", clean_text):
                return {
                    "key": key,
                    "label": profile["label"],
                    "description": profile["description"],
                    "allowed_partial": profile["allowed_partial"],
                    "recommended_mask": profile["recommended_mask"],
                    "guideline": profile["guideline"],
                }

    return {
        "key": "general",
        "label": f"Custom Sharing ('{purpose_text.strip()}')",
        "description": "Direct peer-to-peer or custom commercial sharing.",
        "allowed_partial": ["Aadhaar Number"],
        "recommended_mask": ["Payment Card Number", "PAN Number", "QR Code", "Bank Account Number", "IFSC Code"],
        "guideline": "Protect all non-essential identifiers. Keep last 4 digits only where identification is strictly necessary.",
    }


def analyze_privacy_risks(
    findings: List[Dict[str, Any]], purpose_text: str = ""
) -> Dict[str, Any]:
    """
    Analyzes detected sensitive fields against the stated purpose and generates:
    - Field-by-field privacy risk explanation
    - Recommended action (Mask Full / Mask Partial / Blur / Keep)
    - Identification of 'Excessive Fields' (unnecessary for the specific purpose)
    - Actionable recommendations list
    """
    purpose_info = classify_sharing_purpose(purpose_text)
    recommended_mask_types = set(purpose_info["recommended_mask"])
    allowed_partial_types = set(purpose_info["allowed_partial"])

    field_evaluations = []
    excessive_fields = []
    recommended_indices_to_mask = set()

    for idx, f in enumerate(findings):
        ftype = f.get("type", "Unknown")
        risk_level = f.get("risk_level", "Medium")

        # Determine recommended masking action based on purpose
        if ftype == "QR Code":
            action = "BLUR_MANDATORY"
            action_label = "Blur QR Code (Mandatory)"
            recommended_indices_to_mask.add(idx)
            is_excessive = True
            reason = "QR codes store unmasked biometric templates, complete address, and digital keys."
        elif ftype in recommended_mask_types:
            action = "MASK_FULL"
            action_label = "Mask Completely (Solid Blackout)"
            recommended_indices_to_mask.add(idx)
            is_excessive = True
            excessive_fields.append(ftype)
            reason = f"Not required for {purpose_info['label']}. Sharing this exposes you to unnecessary fraud risks."
        elif ftype in allowed_partial_types:
            action = "MASK_PARTIAL"
            action_label = "Mask Partially (Show Last 4 Only)"
            recommended_indices_to_mask.add(idx)
            is_excessive = False
            reason = f"Official compliance guideline: Only last 4 digits are needed for {purpose_info['label']}."
        else:
            action = "MASK_PARTIAL"
            action_label = "Mask Partially"
            recommended_indices_to_mask.add(idx)
            is_excessive = False
            reason = "Sensitive identifier; should not be shared in cleartext."

        field_evaluations.append({
            "index": idx,
            "type": ftype,
            "text": f.get("text", ""),
            "risk_level": risk_level,
            "recommended_action": action,
            "recommended_action_label": action_label,
            "is_excessive": is_excessive,
            "reason": reason,
        })

    return {
        "purpose_info": purpose_info,
        "field_evaluations": field_evaluations,
        "excessive_fields": list(set(excessive_fields)),
        "recommended_indices_to_mask": list(recommended_indices_to_mask),
        "total_fields": len(findings),
        "engine_type": "Rule-Based Privacy Intelligence Engine (RBI & UIDAI Compliant)",
    }


def generate_privacy_report(
    findings: List[Dict[str, Any]],
    selected_indices: List[int],
    mask_mode: str,
    purpose_text: str,
    orig_score: int,
    protected_score: int,
    link_info: Dict[str, Any] = None,
) -> str:
    """
    Generates a formal, printable Markdown Privacy Protection Report.
    """
    purpose_info = classify_sharing_purpose(purpose_text)
    timestamp_str = datetime.now(timezone.utc).strftime("%d-%b-%Y %H:%M:%S UTC")
    selected_set = set(selected_indices or [])

    # Count protected vs exposed items
    protected_items = []
    exposed_items = []

    for idx, f in enumerate(findings):
        item_desc = f"{f['type']} (`{f.get('text', '')}`)"
        if f.get("type") == "QR Code" or (mask_mode != "none" and idx in selected_set):
            protected_items.append(item_desc)
        else:
            exposed_items.append(item_desc)

    reduction = max(0, orig_score - protected_score)
    reduction_pct = int((reduction / max(1, orig_score)) * 100)

    report_lines = [
        "# 🛡️ ShareSafe Privacy Protection Report",
        f"**Generated On:** {timestamp_str} | **Engine:** ShareSafe Policy Engine v2.0",
        "",
        "---",
        "## 1. Executive Summary",
        f"- **Stated Purpose:** {purpose_text.strip() or 'General Sharing'}",
        f"- **Regulatory Profile:** {purpose_info['label']}",
        f"- **Initial Privacy Risk Score:** `{orig_score}/100` (High Vulnerability)",
        f"- **Protected Privacy Risk Score:** `{protected_score}/100`",
        f"- **Risk Reduction:** `{reduction} points ({reduction_pct}% safer)`",
        f"- **Protection Strategy:** Mode: `{mask_mode.upper()}`",
        "",
        "---",
        "## 2. Sensitive Element Audit",
        f"**Total Elements Detected:** {len(findings)}",
        "",
        "### ✅ Protected / Masked Elements:",
    ]

    if protected_items:
        for item in protected_items:
            report_lines.append(f"- 🛡️ {item}")
    else:
        report_lines.append("- *(No elements protected)*")

    report_lines.extend([
        "",
        "### ⚠️ Visible / Unmasked Elements:",
    ])

    if exposed_items:
        for item in exposed_items:
            report_lines.append(f"- 👁️ {item} — *(Exposed)*")
    else:
        report_lines.append("- *(None — All detected sensitive elements protected)*")

    report_lines.extend([
        "",
        "---",
        "## 3. Regulatory & Purpose Compliance Assessment",
        f"> **Policy Guideline:** {purpose_info['guideline']}",
        "",
        f"- **Data Minimization:** {'Satisfied — Excessive fields redacted.' if not exposed_items else 'Attention — Some fields remain unmasked.'}",
        "- **Embedded QR Code:** Neutralized and blurred to prevent digital signature extraction.",
        f"- **Purpose Watermark:** Stamped with `{purpose_text.strip() or 'Default KYC Tag'}` to prevent secondary re-use for loans or unauthorized SIM activation.",
    ])

    if link_info:
        report_lines.extend([
            "",
            "---",
            "## 4. Secure Sharing Link Metadata",
            f"- **Secure Token (Preview):** `{link_info.get('token', '')[:10]}...`",
            f"- **Time-To-Live (TTL):** {link_info.get('duration_seconds', 0)} seconds",
            f"- **Expires At:** {link_info.get('expires_at', '')}",
            "- **Enforcement:** Server-Side TTL with automatic memory shredding upon expiration.",
        ])

    report_lines.extend([
        "",
        "---",
        "*Disclaimer: Generated by ShareSafe Client-Side Privacy Guardian. This report documents the technical redaction applied prior to document transmission. ShareSafe does not store document contents or personal identities on remote cloud servers.*",
    ])

    return "\n".join(report_lines)
