"""
Unit tests for Stage 1: Detection Engine and Validators
"""

import sys
from PIL import Image, ImageDraw, ImageFont
import numpy as np

# Import our modules
from validators import (
    validate_verhoeff,
    generate_verhoeff_check_digit,
    is_valid_aadhaar,
    generate_fake_aadhaar,
    validate_luhn,
    is_valid_pan,
    is_valid_phone,
    is_valid_ifsc,
    is_valid_dob,
)
from detector import (
    detect_sensitive,
    init_ocr_engine,
    calculate_risk_score,
)
from samples import (
    generate_sample_aadhaar,
    generate_sample_pan,
)


def test_validators():
    print("Testing Validators...")

    # Verhoeff test
    fake_aadhaar = generate_fake_aadhaar("54891234567", formatted=False)
    assert len(fake_aadhaar) == 12, f"Length must be 12, got {len(fake_aadhaar)}"
    assert is_valid_aadhaar(fake_aadhaar), f"Expected {fake_aadhaar} to be valid Aadhaar"
    assert not is_valid_aadhaar("123456789012"), "Expected random number to be invalid Aadhaar"
    assert not is_valid_aadhaar("048912345678"), "Aadhaar starting with 0 is invalid"
    print("  [PASSED] Verhoeff and Aadhaar tests")

    # Luhn test
    valid_card = "4532015112830366"  # Standard Visa test number
    assert validate_luhn(valid_card), "Valid Luhn card failed"
    assert not validate_luhn("4532015112830367"), "Invalid Luhn card passed"
    print("  [PASSED] Luhn payment card tests")

    # PAN test
    assert is_valid_pan("ABCDE1234F"), "ABCDE1234F should be valid PAN"
    assert is_valid_pan("BNZPK1234M"), "BNZPK1234M should be valid PAN"
    assert not is_valid_pan("12345ABCDE"), "Invalid PAN pattern should fail"
    assert not is_valid_pan("ABCDE12345"), "Invalid PAN pattern should fail"
    print("  [PASSED] PAN format tests")

    # Phone test
    assert is_valid_phone("9876543210"), "9876543210 should be valid Indian mobile"
    assert is_valid_phone("+91 9876543210"), "+91 format should be valid"
    assert not is_valid_phone("1234567890"), "Phone starting with 1 should be invalid"
    print("  [PASSED] Phone format tests")

    # IFSC test
    assert is_valid_ifsc("SBIN0001234"), "SBIN0001234 should be valid IFSC"
    assert is_valid_ifsc("HDFC0000456"), "HDFC0000456 should be valid IFSC"
    assert not is_valid_ifsc("SBIN1001234"), "5th char must be 0 in IFSC"
    print("  [PASSED] IFSC format tests")

    # DOB test
    assert is_valid_dob("15/08/1990"), "15/08/1990 should be valid DOB"
    assert is_valid_dob("1995-12-25"), "1995-12-25 should be valid DOB"
    print("  [PASSED] DOB format tests")


def test_ocr_and_detector():
    print("\nTesting Detection Engine...")
    engine = init_ocr_engine()
    print(f"  Initialized OCR engine: {engine}")

    # 1. Test Aadhaar sample card
    print("  Testing synthetic Aadhaar Card...")
    aadhaar_img = generate_sample_aadhaar()
    aadhaar_findings = detect_sensitive(aadhaar_img)
    print(f"    Detected {len(aadhaar_findings)} finding(s) on Aadhaar:")
    for f in aadhaar_findings:
        print(f"      - {f['type']}: '{f['text']}' [{f['risk_level']}] at {f['bbox']}")

    types_aadhaar = {f["type"] for f in aadhaar_findings}
    assert "Aadhaar Number" in types_aadhaar, f"Aadhaar Number missing in {types_aadhaar}"
    assert "QR Code" in types_aadhaar, f"QR Code missing in {types_aadhaar}"

    # 2. Test PAN sample card
    print("  Testing synthetic PAN Card...")
    from samples import generate_sample_pan
    pan_img = generate_sample_pan()
    pan_findings = detect_sensitive(pan_img)
    print(f"    Detected {len(pan_findings)} finding(s) on PAN Card:")
    for f in pan_findings:
        print(f"      - {f['type']}: '{f['text']}' [{f['risk_level']}] at {f['bbox']}")

    types_pan = {f["type"] for f in pan_findings}
    assert "PAN Number" in types_pan, f"PAN Number missing in {types_pan}"

    # 3. Test Risk Score calculation
    score_aadhaar = calculate_risk_score(aadhaar_findings)
    print(f"  Aadhaar Document Risk Score: {score_aadhaar}/100")
    assert score_aadhaar >= 50, f"Expected risk score >= 50, got {score_aadhaar}"

    print("\nSTAGE 1 VERIFICATION COMPLETED SUCCESSFULLY!")


if __name__ == "__main__":
    test_validators()
    test_ocr_and_detector()
