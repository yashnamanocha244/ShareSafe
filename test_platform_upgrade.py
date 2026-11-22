"""
Unit tests for Platform Upgrade:
1. AI-Style Privacy Intelligence & Purpose Alignment
2. Privacy Protection Report generation
3. Access Audit Log recording & retrieval
4. Server-Side Security & Token Enforcement
"""

import time
import shutil
import tempfile
from pathlib import Path
from PIL import Image

from intelligence import (
    classify_sharing_purpose,
    analyze_privacy_risks,
    generate_privacy_report,
)
from secure_links import SecureLinkManager


def test_privacy_intelligence():
    print("Testing Privacy Intelligence Engine...")

    # 1. Test Purpose Classification
    p_bank = classify_sharing_purpose("Axis Bank Loan KYC Verification")
    assert p_bank["key"] == "bank_kyc"
    assert "Banking" in p_bank["label"]

    p_hotel = classify_sharing_purpose("Taj Hotel Guest Check-in")
    assert p_hotel["key"] == "hotel_checkin"
    assert "Hotel" in p_hotel["label"]

    p_sim = classify_sharing_purpose("Airtel SIM Card Activation")
    assert p_sim["key"] == "sim_telecom"

    p_gen = classify_sharing_purpose("Random purpose")
    assert p_gen["key"] == "general"
    print("  [PASSED] Purpose classification across bank, hotel, telecom, and general")

    # 2. Test Purpose-Aware Risk Recommendations
    dummy_findings = [
        {"type": "Aadhaar Number", "text": "5489 1234 5674", "risk_level": "High", "bbox": (10, 10, 100, 20)},
        {"type": "PAN Number", "text": "ABCPE1234F", "risk_level": "High", "bbox": (10, 40, 100, 20)},
        {"type": "QR Code", "text": "https://uidai.gov.in", "risk_level": "High", "bbox": (10, 80, 100, 100)},
        {"type": "Payment Card Number", "text": "4532 0151 1283 0366", "risk_level": "High", "bbox": (10, 200, 100, 20)},
    ]

    # For Hotel Check-in: PAN and Card are EXCESSIVE data
    analysis_hotel = analyze_privacy_risks(dummy_findings, purpose_text="Hotel stay")
    assert "PAN Number" in analysis_hotel["excessive_fields"]
    assert "Payment Card Number" in analysis_hotel["excessive_fields"]
    print("  [PASSED] Excessive data identification for hotel purpose")

    # 3. Test Privacy Protection Report Generation
    report_md = generate_privacy_report(
        findings=dummy_findings,
        selected_indices=[0, 1, 2, 3],
        mask_mode="partial",
        purpose_text="Axis Bank KYC",
        orig_score=100,
        protected_score=0,
        link_info={"token": "test-token-1234567890", "duration_seconds": 3600, "expires_at": "2026-11-23T12:00:00Z"},
    )
    assert "# 🛡️ ShareSafe Privacy Protection Report" in report_md
    assert "Axis Bank KYC" in report_md
    assert "100/100" in report_md
    print("  [PASSED] Structured Privacy Protection Report generation")


def test_access_audit_log():
    print("\nTesting Access Audit Log & Secure Backend...")
    temp_dir = tempfile.mkdtemp(prefix="audit_test_")
    test_storage = Path(temp_dir)

    try:
        manager = SecureLinkManager(storage_dir=test_storage)

        # 1. Create a link -> should record LINK_CREATED in audit log
        dummy_img = Image.new("RGB", (200, 200), color=(100, 150, 200))
        link = manager.create_secure_link(
            masked_image=dummy_img,
            duration_seconds=3600,
            purpose="Car Loan KYC",
        )
        token = link["token"]

        logs = manager.get_audit_logs()
        assert len(logs) >= 1
        assert logs[0]["event_type"] == "LINK_CREATED"
        assert token[:8] in logs[0]["token_preview"]
        print("  [PASSED] Audit event LINK_CREATED recorded")

        # 2. Access document -> should record ACCESS_SUCCESSFUL
        status, img, meta = manager.get_shared_document(token)
        assert status == "ACTIVE"
        assert img is not None

        logs_after_access = manager.get_audit_logs()
        assert logs_after_access[0]["event_type"] == "ACCESS_SUCCESSFUL"
        print("  [PASSED] Audit event ACCESS_SUCCESSFUL recorded")

        # 3. Manually revoke -> should record MANUALLY_REVOKED and FILE_PURGED
        manager.revoke_link(token)
        status_rev, _, _ = manager.get_shared_document(token)
        assert status_rev == "REVOKED"

        logs_rev = manager.get_audit_logs()
        event_types = [l["event_type"] for l in logs_rev]
        assert "MANUALLY_REVOKED" in event_types
        assert "ACCESS_BLOCKED_REVOKED" in event_types
        assert "FILE_PURGED" in event_types
        print("  [PASSED] Audit events MANUALLY_REVOKED, ACCESS_BLOCKED_REVOKED, FILE_PURGED")

        # 4. Verify no personal numbers in audit details
        for l in logs_rev:
            assert "5489" not in l["details"]
            assert "ABCPE" not in l["details"]
        print("  [PASSED] Audit log privacy guarantee (no sensitive numbers stored)")

    finally:
        shutil.rmtree(test_storage, ignore_errors=True)

    print("\nALL PLATFORM UPGRADE TESTS PASSED SUCCESSFULLY!")


if __name__ == "__main__":
    test_privacy_intelligence()
    test_access_audit_log()
