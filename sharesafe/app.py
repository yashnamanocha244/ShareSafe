"""
ShareSafe - Streamlit Web Application
"Pause before you share."

Intelligent, Secure Document-Sharing Platform:
- On-device OCR & sensitive Indian entity detection (Aadhaar, PAN, Cards, Phone, DOB, IFSC, QR)
- Checksum validation (Verhoeff for Aadhaar, Luhn for Cards)
- Rule-Based Privacy Intelligence Engine:
    * Purpose classification (Banking KYC, Hotel Check-in, SIM Card, HR/Job, Rental, General)
    * Policy-aligned masking recommendations & excessive data exposure warnings
    * Downloadable Privacy Protection Report
- Multiple privacy masking modes (Full blackout, Partial last-4, Gaussian blur)
- Non-reusable purpose watermarking
- Self-Expiring Secure Document Links with server-side TTL and manual revocation
- Tamper-Evident Access Audit Log Dashboard (Zero document data logged)
- Recipient view with live countdown timer and screenshot disclosures
- Bilingual support: English and Hindi (हिन्दी)
"""

import os
import io
import time
from datetime import datetime, timezone
import streamlit as st
from PIL import Image

# Core ShareSafe modules
from validators import is_valid_aadhaar, is_valid_pan, validate_luhn
from detector import detect_sensitive, calculate_risk_score
from masker import apply_masks, add_watermark
from samples import (
    generate_sample_aadhaar,
    generate_sample_pan,
    generate_sample_cheque_or_card,
)
from secure_links import default_link_manager
from intelligence import (
    classify_sharing_purpose,
    analyze_privacy_risks,
    generate_privacy_report,
)
from i18n import t

# ─────────────────────────────────────────────────────────────
# Page Configuration
# ─────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="ShareSafe — Pause before you share",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────────────────────
# Custom Styling  (teal / indigo light theme, rounded cards)
# ─────────────────────────────────────────────────────────────
st.markdown(
    """
    <style>
    :root {
        --teal:   #0d9488;
        --indigo: #4f46e5;
        --bg:     #f8fafc;
        --border: #e2e8f0;
    }
    .stApp { background-color: #ffffff; }

    /* ── Hero header ── */
    .hero-header {
        background: linear-gradient(135deg, #0d9488 0%, #4338ca 100%);
        padding: 24px 30px; border-radius: 16px; color: #fff;
        margin-bottom: 24px;
        box-shadow: 0 4px 15px rgba(13,148,136,.15);
    }
    .hero-title  { font-size:2.3rem; font-weight:800; letter-spacing:-.5px; margin:0; }
    .hero-tagline{ font-size:1.15rem; font-weight:400; opacity:.92; margin-top:6px; }

    /* ── Step indicator ── */
    .step-container{ display:flex; justify-content:space-between; gap:10px; margin-bottom:24px; }
    .step-pill{
        flex:1; padding:10px 14px; background:#f1f5f9; border-radius:10px;
        text-align:center; font-weight:600; font-size:.95rem;
        color:#475569; border:1px solid #cbd5e1;
    }
    .step-pill.active{
        background:#0d9488; color:#fff; border-color:#0d9488;
        box-shadow:0 2px 8px rgba(13,148,136,.25);
    }

    /* ── Alert / status cards ── */
    .warning-card{
        background:#fff7ed; border:2px solid #ea580c;
        border-radius:12px; padding:18px 22px; margin-bottom:20px;
    }
    .danger-card{
        background:#fef2f2; border:2px solid #ef4444;
        border-radius:12px; padding:18px 22px; margin:16px 0;
    }
    .expired-card{
        background:#fef2f2; border:2px solid #ef4444;
        border-radius:14px; padding:26px; text-align:center;
        margin:40px auto; max-width:700px;
    }
    .success-card{
        background:#f0fdf4; border:2px solid #16a34a;
        border-radius:12px; padding:18px 22px; margin:20px 0;
    }
    .intelligence-box{
        background:#f0fdfa; border:2px solid #0d9488;
        border-radius:12px; padding:18px 22px; margin:18px 0;
    }

    /* ── Privacy score badge ── */
    .score-badge{
        font-size:2.2rem; font-weight:800; border-radius:12px;
        padding:10px 18px; display:inline-block; text-align:center;
    }
    .score-high{ background:#fee2e2; color:#b91c1c; border:2px solid #ef4444; }
    .score-med { background:#ffedd5; color:#c2410c; border:2px solid #f97316; }
    .score-safe{ background:#dcfce7; color:#15803d; border:2px solid #22c55e; }

    /* ── Link display box ── */
    .link-box{
        background:#f8fafc; border:2px dashed #0d9488;
        border-radius:12px; padding:18px; margin:15px 0;
    }
    .link-url{
        width:100%; padding:10px; font-size:1rem;
        border-radius:8px; border:1px solid #cbd5e1; background:#fff;
        font-family: monospace;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ─────────────────────────────────────────────────────────────
# Session State
# ─────────────────────────────────────────────────────────────
_DEFAULTS = {
    "lang": "en",
    "image": None,
    "findings": None,
    "selected_findings": set(),
    "mask_mode": "partial",
    "purpose_text": "Axis Bank KYC",
    "created_links": [],
    "consent_given": False,
    "last_link": None,
    "orig_risk_score": None,          # score before any masking (for success card)
    "confirm_send_original": False,   # strong confirmation gate for "send original"
    "download_done": False,           # triggers success card
}
for k, v in _DEFAULTS.items():
    if k not in st.session_state:
        st.session_state[k] = v


# ─────────────────────────────────────────────────────────────
# Routing: Recipient View  (?share=<token>)
# ─────────────────────────────────────────────────────────────
query_params = st.query_params
shared_token = query_params.get("share")

if shared_token:
    lang = st.session_state.lang
    st.markdown(
        f"""
        <div class="hero-header">
            <h1 class="hero-title">🛡️ {t("recipient_header", lang)}</h1>
            <div class="hero-tagline">{t("tagline", lang)}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    status, shared_img, meta = default_link_manager.get_shared_document(shared_token)

    if status == "ACTIVE" and shared_img:
        rem = default_link_manager.get_remaining_seconds(meta["expires_at"])
        h, m, s = rem // 3600, (rem % 3600) // 60, rem % 60

        col_left, col_right = st.columns([2, 1])
        with col_left:
            st.subheader(f"📄 {meta.get('document_type', 'Protected Document')}")
            if meta.get("purpose"):
                st.info(f"🎯 **Authorized Purpose:** {meta['purpose']}")
            st.image(shared_img, caption="Protected & Watermarked Document", use_container_width=True)

        with col_right:
            st.markdown(
                f"""
                <div style="background:#f0fdf4;border:2px solid #22c55e;border-radius:12px;padding:20px;margin-bottom:20px;">
                    <h3 style="color:#15803d;margin:0 0 10px 0;">⏳ {t("countdown_remaining", lang)}</h3>
                    <div style="font-size:2rem;font-weight:800;color:#166534;">
                        {h:02d}h {m:02d}m {s:02d}s
                    </div>
                    <p style="font-size:.85rem;color:#475569;margin-top:8px;">
                        Expires at: {meta['expires_at'][:19].replace('T',' ')} UTC
                    </p>
                </div>
                """,
                unsafe_allow_html=True,
            )
            st.warning(t("screenshot_warning", lang))
            st.caption(f"👀 Access Count: {meta.get('access_count', 1)} times")
            st.divider()
            if st.button("← Back to ShareSafe Home", use_container_width=True):
                st.query_params.clear()
                st.rerun()

    elif status == "EXPIRED":
        st.markdown(
            f"""
            <div class="expired-card">
                <h2 style="color:#b91c1c;margin:0 0 12px 0;">{t("expired_title", lang)}</h2>
                <p style="font-size:1.1rem;color:#4b5563;">{t("expired_desc", lang)}</p>
                <p style="font-size:.9rem;color:#9ca3af;margin-top:12px;">
                    Security Protocol: Document file deleted from server storage.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if st.button("Open ShareSafe", use_container_width=True):
            st.query_params.clear()
            st.rerun()

    elif status == "REVOKED":
        st.markdown(
            f"""
            <div class="expired-card">
                <h2 style="color:#b91c1c;margin:0 0 12px 0;">{t("revoked_title", lang)}</h2>
                <p style="font-size:1.1rem;color:#4b5563;">{t("revoked_desc", lang)}</p>
                <p style="font-size:.9rem;color:#9ca3af;margin-top:12px;">
                    Security Protocol: Document file deleted upon sender revocation.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if st.button("Open ShareSafe", use_container_width=True):
            st.query_params.clear()
            st.rerun()

    else:
        st.error("❌ Document link not found or permanently purged.")
        if st.button("Open ShareSafe"):
            st.query_params.clear()
            st.rerun()

    st.stop()


# ─────────────────────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────────────────────
with st.sidebar:
    st.subheader("⚙️ Settings / सेटिंग्स")

    lang_choice = st.radio(
        "Language / भाषा:",
        options=["English", "हिन्दी"],
        index=0 if st.session_state.lang == "en" else 1,
    )
    st.session_state.lang = "en" if lang_choice == "English" else "hi"
    lang = st.session_state.lang

    st.markdown(
        f"""
        <div style="background:#f1f5f9;border-radius:10px;padding:12px 14px;
                    margin:15px 0;border-left:4px solid #0d9488;">
            <div style="font-weight:700;font-size:.9rem;color:#0f172a;">
                {t("privacy_badge", lang)}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # ── Active links manager ──
    if st.session_state.created_links:
        st.divider()
        st.subheader("🔗 Active Generated Links")
        for item in list(st.session_state.created_links):
            tok = item["token"]
            rem = default_link_manager.get_remaining_seconds(item["expires_at"])
            if rem > 0:
                h, m = rem // 3600, (rem % 3600) // 60
                st.markdown(f"**Token:** `{tok[:10]}...` ({h}h {m}m left)")
                if st.button(f"🛑 Revoke {tok[:8]}", key=f"rev_{tok}"):
                    default_link_manager.revoke_link(tok)
                    st.session_state.created_links.remove(item)
                    st.success("Link revoked.")
                    st.rerun()
            else:
                st.caption(f"⏰ Expired: `{tok[:10]}...`")

    # ── Audit Log ──
    st.divider()
    with st.expander(f"📋 {t('audit_log_title', lang)}", expanded=False):
        st.caption(t("audit_log_sub", lang))
        audit_records = default_link_manager.get_audit_logs(limit=20)
        if not audit_records:
            st.write("*(No access events recorded yet)*")
        else:
            for rec in audit_records:
                ts = rec["timestamp"][:19].replace("T", " ")
                ev = rec["event_type"]
                color = "green" if "SUCCESS" in ev else ("orange" if "CREATED" in ev else "red")
                st.markdown(f"**{ts} UTC** — :{color}[`{ev}`]")
                st.caption(f"Token: `{rec['token_preview']}` | {rec['details']}")
                st.markdown("---")

    # ── How it works ──
    with st.expander(t("how_it_works_title", lang), expanded=False):
        st.markdown(t("how_it_works_content", lang))

    # ── Hackathon judge info ──
    with st.expander("🏆 For Hackathon Judges", expanded=False):
        st.markdown("""
**What makes ShareSafe unique:**

| Feature | Description |
|---------|-------------|
| 🔍 **Dual-Engine OCR** | Tesseract → EasyOCR auto-fallback |
| ✅ **Checksum Validation** | Verhoeff (Aadhaar) + Luhn (Cards) — zero false positives |
| 🤖 **Privacy Intelligence** | Rule-based, RBI & UIDAI guideline–aligned recommendations |
| 🔗 **Expiring Links** | Server-side TTL + file deletion, not just frontend timers |
| 📋 **Audit Log** | Zero document content logged — only access events |
| 🌐 **Bilingual** | Full English + Hindi UI |
| 🔒 **On-device** | Nothing leaves your machine |

**Run:** `streamlit run app.py`  
**Tests:** `python test_stage1.py && python test_secure_links.py && python test_platform_upgrade.py`
        """)


# ─────────────────────────────────────────────────────────────
# MAIN — Hero Banner
# ─────────────────────────────────────────────────────────────
st.markdown(
    f"""
    <div class="hero-header">
        <h1 class="hero-title">🛡️ {t("app_title", lang)}</h1>
        <div class="hero-tagline">{t("tagline", lang)}</div>
    </div>
    """,
    unsafe_allow_html=True,
)

# Step indicator
_step = 1
if st.session_state.image is not None:
    _step = 2
if st.session_state.findings is not None and len(st.session_state.findings) > 0:
    _step = 3
if st.session_state.consent_given:
    _step = 4

st.markdown(
    f"""
    <div class="step-container">
        <div class="step-pill {'active' if _step >= 1 else ''}">{t("step_1", lang)}</div>
        <div class="step-pill {'active' if _step >= 2 else ''}">{t("step_2", lang)}</div>
        <div class="step-pill {'active' if _step >= 3 else ''}">{t("step_3", lang)}</div>
        <div class="step-pill {'active' if _step >= 4 else ''}">{t("step_4", lang)}</div>
    </div>
    """,
    unsafe_allow_html=True,
)


# ─────────────────────────────────────────────────────────────
# STEP 1  —  Upload / Choose Sample
# ─────────────────────────────────────────────────────────────
st.subheader(f"1. {t('upload_header', lang)}")

col_up, col_samples = st.columns([1.5, 1])

with col_up:
    uploaded_file = st.file_uploader(
        t("upload_help", lang),
        type=["png", "jpg", "jpeg", "webp"],
        key="file_uploader_widget",
    )
    if uploaded_file is not None:
        try:
            raw_img = Image.open(uploaded_file).convert("RGB")
            st.session_state.image = raw_img
            st.session_state.findings = None
            st.session_state.selected_findings = set()
            st.session_state.consent_given = False
            st.session_state.download_done = False
            st.session_state.confirm_send_original = False
            st.session_state.last_link = None
        except Exception as e:
            st.error(f"Could not open image: {e}")

with col_samples:
    st.markdown(f"**{t('or_try_sample', lang)}**")
    b1, b2, b3 = st.columns(3)

    def _load_sample(img: Image.Image):
        """Reset state and load a fresh sample image."""
        st.session_state.image = img
        st.session_state.findings = None
        st.session_state.selected_findings = set()
        st.session_state.consent_given = False
        st.session_state.download_done = False
        st.session_state.confirm_send_original = False
        st.session_state.last_link = None

    if b1.button(t("btn_sample_aadhaar", lang), use_container_width=True):
        _load_sample(generate_sample_aadhaar())
        st.rerun()
    if b2.button(t("btn_sample_pan", lang), use_container_width=True):
        _load_sample(generate_sample_pan())
        st.rerun()
    if b3.button(t("btn_sample_cheque", lang), use_container_width=True):
        _load_sample(generate_sample_cheque_or_card())
        st.rerun()


# ─────────────────────────────────────────────────────────────
# STEP 2  —  Review (Detection + Privacy Intelligence)
# ─────────────────────────────────────────────────────────────
if st.session_state.image is None:
    st.info("👆 Upload a document image or choose a sample above to get started.")
    st.stop()

# Auto-run detection once per image
if st.session_state.findings is None:
    with st.spinner(f"🔍 {t('ocr_processing', lang)}"):
        try:
            findings = detect_sensitive(st.session_state.image)
        except Exception as exc:
            st.error(f"⚠️ OCR failed: {exc}")
            st.stop()
        st.session_state.findings = findings
        st.session_state.selected_findings = set(range(len(findings)))
        st.session_state.orig_risk_score = calculate_risk_score(findings)

findings = st.session_state.findings or []

st.divider()
st.subheader(f"2. {t('step_2', lang)} — {t('findings_header', lang)}")

# ── No findings ──────────────────────────────────────────────
if not findings:
    st.success(t("no_sensitive_found", lang))
    st.image(st.session_state.image, caption="Your document", use_container_width=True)
    st.stop()

# ── Scores ───────────────────────────────────────────────────
initial_score = st.session_state.orig_risk_score or calculate_risk_score(findings)

if st.session_state.mask_mode == "none":
    current_unmasked = findings
else:
    current_unmasked = [
        f for idx, f in enumerate(findings)
        if idx not in st.session_state.selected_findings
    ]
current_score = calculate_risk_score(current_unmasked)

# ── Alert card ───────────────────────────────────────────────
st.markdown(
    f"""
    <div class="warning-card">
        <h3 style="color:#c2410c;margin:0 0 6px 0;">{t("alert_headline", lang)}</h3>
        <p style="margin:0;color:#431407;">{t("alert_sub", lang)}</p>
    </div>
    """,
    unsafe_allow_html=True,
)

# ── Privacy Intelligence panel ───────────────────────────────
intel_analysis = analyze_privacy_risks(findings, st.session_state.purpose_text)
purpose_info   = intel_analysis["purpose_info"]
excessive_fields = intel_analysis["excessive_fields"]

st.markdown(
    f"""
    <div class="intelligence-box">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
            <h4 style="margin:0;color:#0f766e;">{t('intelligence_title', lang)}</h4>
            <span style="font-size:.8rem;background:#ccfbf1;color:#115e59;
                         padding:3px 10px;border-radius:999px;font-weight:700;">
                {intel_analysis['engine_type']}
            </span>
        </div>
        <p style="margin:0 0 10px 0;font-size:.95rem;color:#134e4a;">
            🎯 <b>{t('purpose_profile_label', lang)}</b>
            <u>{purpose_info['label']}</u> — <i>{purpose_info['description']}</i>
        </p>
        <div style="background:#fff;padding:10px 14px;border-radius:8px;
                    border-left:4px solid #0d9488;font-size:.9rem;color:#334155;">
            💡 <b>Regulatory Policy:</b> {purpose_info['guideline']}
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

if excessive_fields:
    st.error(
        f"🚨 **{t('excessive_warning', lang)}** This document exposes "
        f"{', '.join(excessive_fields)}, completely non-essential for "
        f"*{purpose_info['label']}*. Sharing them creates unneeded fraud risk."
    )

# ── Apply Recommendations button ─────────────────────────────
if st.button(t("btn_apply_recommendations", lang), use_container_width=True):
    # Update selected set directly — no rerun needed; Streamlit reruns automatically
    st.session_state.selected_findings = set(intel_analysis["recommended_indices_to_mask"])
    st.session_state.mask_mode = "partial"
    st.toast("✅ Recommended masking policy applied!", icon="⚡")

# ── Risk Score + Findings list ───────────────────────────────
score_class = (
    "score-high" if current_score >= 60
    else "score-med" if current_score >= 30
    else "score-safe"
)
col_score, col_details = st.columns([1, 2.5])

with col_score:
    st.markdown(f"**{t('risk_score_title', lang)}**")
    st.markdown(
        f"""
        <div class="score-badge {score_class}">
            {current_score}
            <span style="font-size:1rem;font-weight:500;"> / 100</span>
        </div>
        """,
        unsafe_allow_html=True,
    )
    delta = initial_score - current_score
    if delta > 0:
        st.markdown(f"📉 **Risk Reduced:** `{delta} pts`")
    if current_score == 0:
        st.caption(f"🛡️ {t('risk_safe', lang)}")
    else:
        st.caption(f"⚠️ {t('risk_score_desc', lang)}")

with col_details:
    st.markdown(f"**{t('findings_sub', lang)}**")
    for eval_item in intel_analysis["field_evaluations"]:
        idx     = eval_item["index"]
        finding = findings[idx]
        risk_color = (
            "red" if finding["risk_level"] == "High"
            else "orange" if finding["risk_level"] == "Medium"
            else "blue"
        )
        is_checked = idx in st.session_state.selected_findings

        badge = (
            " :red-background[Excessive for this Purpose]"
            if eval_item["is_excessive"]
            else f" :blue-background[{eval_item['recommended_action_label']}]"
        )

        cb = st.checkbox(
            f"**{finding['type']}**: `{finding['text']}` "
            f"— :{risk_color}[{finding['risk_level']} Risk]{badge}",
            value=is_checked,
            key=f"finding_cb_{idx}",
        )
        if cb:
            st.session_state.selected_findings.add(idx)
        else:
            st.session_state.selected_findings.discard(idx)

        st.caption(f"↳ *{finding['reason']}*")


# ─────────────────────────────────────────────────────────────
# STEP 3  —  Protection Settings
# ─────────────────────────────────────────────────────────────
st.divider()
st.subheader(f"3. {t('protection_controls', lang)}")

col_ctrl1, col_ctrl2 = st.columns(2)

with col_ctrl1:
    mask_mode_label = st.radio(
        t("mask_mode_label", lang),
        options=[
            t("mode_partial", lang),
            t("mode_full", lang),
            t("mode_blur", lang),
            t("mode_original", lang),
        ],
        index=0,
        key="mask_mode_radio",
    )
    if t("mode_partial", lang) in mask_mode_label:
        new_mode = "partial"
    elif t("mode_full", lang) in mask_mode_label:
        new_mode = "full"
    elif t("mode_blur", lang) in mask_mode_label:
        new_mode = "blur"
    else:
        new_mode = "none"

    # Reset confirmation gate if mode changes away from "none"
    if new_mode != st.session_state.mask_mode:
        st.session_state.confirm_send_original = False
    st.session_state.mask_mode = new_mode

with col_ctrl2:
    st.session_state.purpose_text = st.text_input(
        t("watermark_label", lang),
        value=st.session_state.purpose_text,
        placeholder=t("watermark_placeholder", lang),
        help=t("watermark_help", lang),
    )

# ── STRONG WARNING for "Send original" mode ──────────────────
if st.session_state.mask_mode == "none":
    st.markdown(
        f"""
        <div class="danger-card">
            <h3 style="color:#b91c1c;margin:0 0 8px 0;">
                ⚠️ {t("warning_original_title", lang)}
            </h3>
            <p style="margin:0;color:#450a0a;">
                {t("warning_original_desc", lang)}
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    confirm_orig = st.checkbox(
        "✅ I understand the risk and confirm I want to share WITHOUT any masking.",
        value=st.session_state.confirm_send_original,
        key="confirm_orig_cb",
    )
    st.session_state.confirm_send_original = confirm_orig
    if not confirm_orig:
        st.warning("You must confirm above before you can proceed with the unmasked document.")

# ── Build protected image ────────────────────────────────────
masked_img = apply_masks(
    st.session_state.image,
    findings=findings,
    mode=st.session_state.mask_mode,
    selected_indices=list(st.session_state.selected_findings),
)
protected_img = (
    add_watermark(masked_img, st.session_state.purpose_text)
    if st.session_state.purpose_text.strip()
    else masked_img
)

# ── Side-by-side preview ─────────────────────────────────────
st.markdown(f"#### {t('preview_header', lang)}")
p1, p2 = st.columns(2)
with p1:
    st.image(st.session_state.image, caption=t("preview_orig", lang), use_container_width=True)
with p2:
    st.image(protected_img, caption=t("preview_protected", lang), use_container_width=True)


# ─────────────────────────────────────────────────────────────
# STEP 4  —  Consent & Share
# ─────────────────────────────────────────────────────────────
st.divider()
st.subheader(f"4. {t('step_4', lang)}")

# Block step 4 if "send original" but confirmation not given
if st.session_state.mask_mode == "none" and not st.session_state.confirm_send_original:
    st.info("👆 You must confirm the unmasked-share warning above before proceeding.")
    st.stop()

consent = st.checkbox(
    f"**{t('consent_label', lang)}**",
    value=st.session_state.consent_given,
    key="consent_checkbox",
)
st.session_state.consent_given = consent

if not consent:
    st.info(f"👉 {t('consent_required', lang)}")
    st.stop()

# ── Success card after download ───────────────────────────────
if st.session_state.download_done:
    score_after = calculate_risk_score(current_unmasked)
    orig = st.session_state.orig_risk_score or initial_score
    reduction = orig - score_after
    st.markdown(
        f"""
        <div class="success-card">
            <h2 style="color:#166534;margin:0 0 8px 0;">🎉 {t("success_title", lang)}</h2>
            <p style="margin:0;color:#14532d;font-size:1.1rem;">
                {t("success_msg", lang).format(orig_score=orig, new_score=score_after)}
            </p>
            <div style="margin-top:12px;font-size:2rem;font-weight:800;color:#15803d;">
                {'▼ ' + str(reduction) + ' points safer' if reduction > 0 else '🛡️ Already safe!'}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

# ── Shared action cards ───────────────────────────────────────
st.markdown(
    f"""
    <div class="success-card">
        <h3 style="color:#166534;margin:0 0 6px 0;">{t("success_title", lang)}</h3>
        <p style="margin:0;color:#14532d;">
            {t("success_msg", lang).format(orig_score=initial_score, new_score=current_score)}
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)

tab_dl, tab_link, tab_report = st.tabs([
    "📥 Download File",
    "🔗 Self-Expiring Link",
    "📄 Privacy Report",
])

# ── TAB 1: Direct Download ────────────────────────────────────
with tab_dl:
    img_bytes = io.BytesIO()
    protected_img.save(img_bytes, format="PNG")
    img_bytes.seek(0)

    dl = st.download_button(
        label=t("btn_download", lang),
        data=img_bytes,
        file_name="sharesafe_protected_document.png",
        mime="image/png",
        use_container_width=True,
        type="primary",
    )
    if dl:
        st.session_state.download_done = True
        st.rerun()

    # ── Safe Share Summary ────────────────────────────────────
    with st.expander(f"📋 {t('summary_title', lang)}", expanded=True):
        s1, s2 = st.columns(2)
        with s1:
            st.markdown(f"**{t('summary_masked', lang)}**")
            if st.session_state.mask_mode == "none":
                st.write("*(None — Shared unmasked)*")
            else:
                for idx in sorted(st.session_state.selected_findings):
                    if idx < len(findings):
                        f = findings[idx]
                        st.write(f"• **{f['type']}** (`{f['text']}`)")
        with s2:
            st.markdown(f"**{t('summary_visible', lang)}**")
            if st.session_state.mask_mode == "none":
                for f in findings:
                    st.write(f"• **{f['type']}** (`{f['text']}`)")
            else:
                unmasked = [i for i in range(len(findings))
                            if i not in st.session_state.selected_findings]
                if not unmasked:
                    st.write("*(All sensitive elements protected)*")
                else:
                    for idx in unmasked:
                        f = findings[idx]
                        st.write(f"• **{f['type']}** (`{f['text']}`)")

# ── TAB 2: Self-Expiring Link ─────────────────────────────────
with tab_link:
    st.markdown(f"### 🔗 {t('share_link_title', lang)}")
    st.write(t("share_link_desc", lang))

    l1, l2 = st.columns([1.5, 1])
    with l1:
        exp_option = st.selectbox(
            t("expiry_label", lang),
            options=[
                t("opt_24h", lang),
                t("opt_1h", lang),
                t("opt_6h", lang),
                t("opt_7d", lang),
                t("opt_custom", lang),
            ],
            index=0,
        )
        custom_minutes = None
        if exp_option == t("opt_custom", lang):
            custom_minutes = st.number_input(
                t("custom_mins_label", lang),
                min_value=1, max_value=43200, value=30, step=5,
            )

    with l2:
        st.write("")
        st.write("")
        if st.button(t("btn_create_link", lang), use_container_width=True, type="primary"):
            if exp_option == t("opt_1h", lang):
                preset = "1_hour"
            elif exp_option == t("opt_6h", lang):
                preset = "6_hours"
            elif exp_option == t("opt_7d", lang):
                preset = "7_days"
            elif exp_option == t("opt_custom", lang):
                preset = "custom"
            else:
                preset = "24_hours"

            dur = default_link_manager.calculate_expiry_seconds(
                preset, custom_minutes=custom_minutes
            )
            link_info = default_link_manager.create_secure_link(
                masked_image=protected_img,
                duration_seconds=dur,
                purpose=st.session_state.purpose_text,
                document_type="Protected Document",
            )
            st.session_state.created_links.append(link_info)
            st.session_state.last_link = link_info
            st.toast("✅ Secure link generated!", icon="🔗")

    # Show the last generated link
    if st.session_state.last_link:
        last_l  = st.session_state.last_link
        token   = last_l["token"]
        full_url = f"http://localhost:8501/?share={token}"
        rem_secs = default_link_manager.get_remaining_seconds(last_l["expires_at"])
        hh, mm   = rem_secs // 3600, (rem_secs % 3600) // 60

        st.markdown(
            f"""
            <div class="link-box">
                <h4 style="margin:0 0 10px 0;color:#0d9488;">{t("link_created_title", lang)}</h4>
                <input class="link-url" type="text" value="{full_url}" readonly>
                <p style="font-size:.82rem;color:#64748b;margin-top:8px;">
                    ⏳ Expires in {hh}h {mm}m &nbsp;|&nbsp; {t("copy_link_help", lang)}
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # JavaScript copy-to-clipboard helper
        st.markdown(
            f"""
            <button onclick="navigator.clipboard.writeText('{full_url}').then(()=>{{
                this.textContent='✅ Copied!';
                setTimeout(()=>this.textContent='📋 Copy Link',2000);
            }})"
            style="background:#0d9488;color:#fff;border:none;padding:8px 20px;
                   border-radius:8px;cursor:pointer;font-size:1rem;margin-bottom:8px;">
                📋 Copy Link
            </button>
            """,
            unsafe_allow_html=True,
        )

        st.warning(t("screenshot_warning", lang))

        if st.button(t("btn_revoke_link", lang), key="btn_revoke_last"):
            default_link_manager.revoke_link(token)
            st.session_state.last_link = None
            # Remove from sidebar list too
            st.session_state.created_links = [
                x for x in st.session_state.created_links if x["token"] != token
            ]
            st.warning(t("link_revoked_msg", lang))
            st.rerun()

# ── TAB 3: Privacy Report ─────────────────────────────────────
with tab_report:
    report_md = generate_privacy_report(
        findings=findings,
        selected_indices=list(st.session_state.selected_findings),
        mask_mode=st.session_state.mask_mode,
        purpose_text=st.session_state.purpose_text,
        orig_score=initial_score,
        protected_score=current_score,
        link_info=st.session_state.last_link,
    )

    st.download_button(
        label=t("download_report", lang),
        data=report_md,
        file_name="sharesafe_privacy_report.md",
        mime="text/markdown",
        use_container_width=True,
    )

    with st.expander(f"👁️ {t('view_report', lang)}", expanded=True):
        st.markdown(report_md)
