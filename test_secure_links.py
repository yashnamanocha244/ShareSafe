"""
Unit tests for Self-Expiring Secure Document Links feature:
1. Valid link creation, token entropy, and document retrieval
2. Server-side expiration enforcement & automatic file shredding
3. Manual link revocation & file shredding
4. Invalid / tampered / non-existent tokens
5. Expiry options preset and custom duration calculations
"""

import time
import shutil
import tempfile
from pathlib import Path
from PIL import Image
from datetime import datetime, timezone, timedelta

from secure_links import SecureLinkManager


def test_secure_links():
    print("Testing Self-Expiring Secure Document Links...")
    temp_dir = tempfile.mkdtemp(prefix="sharesafe_test_")
    test_storage = Path(temp_dir)

    try:
        manager = SecureLinkManager(storage_dir=test_storage)

        # 1. Test Expiry duration calculations
        assert manager.calculate_expiry_seconds("1_hour") == 3600
        assert manager.calculate_expiry_seconds("6_hours") == 21600
        assert manager.calculate_expiry_seconds("24_hours") == 86400
        assert manager.calculate_expiry_seconds("7_days") == 604800
        assert manager.calculate_expiry_seconds("custom", custom_minutes=45) == 2700
        print("  [PASSED] Expiry duration presets and custom math")

        # 2. Test Link Generation
        dummy_img = Image.new("RGB", (300, 200), color=(10, 120, 200))
        link_info = manager.create_secure_link(
            masked_image=dummy_img,
            duration_seconds=3600,
            purpose="Bank Loan KYC",
            document_type="Aadhaar Masked",
        )

        token = link_info["token"]
        assert len(token) >= 40, f"Token length must be >= 40, got {len(token)}"
        assert link_info["duration_seconds"] == 3600
        assert link_info["purpose"] == "Bank Loan KYC"
        print(f"  [PASSED] Secure token generation: {token[:12]}...")

        # 3. Test Active Document Retrieval
        status, retrieved_img, meta = manager.get_shared_document(token)
        assert status == "ACTIVE", f"Expected ACTIVE, got {status}"
        assert retrieved_img is not None
        assert retrieved_img.size == (300, 200)
        assert meta["access_count"] == 1
        print("  [PASSED] Active document retrieval & access counting")

        # 4. Test Manual Revocation
        revocation_img = Image.new("RGB", (200, 200), color=(200, 50, 50))
        revoke_info = manager.create_secure_link(revocation_img, duration_seconds=7200)
        revoke_token = revoke_info["token"]

        revoked_file = test_storage / "documents" / f"{revoke_token}.png"
        assert revoked_file.exists(), "Document file should exist initially"

        # Revoke it
        revoke_success = manager.revoke_link(revoke_token)
        assert revoke_success is True, "Revocation should return True"

        # Verify status is REVOKED and file was shredded
        status_r, img_r, meta_r = manager.get_shared_document(revoke_token)
        assert status_r == "REVOKED", f"Expected REVOKED, got {status_r}"
        assert img_r is None
        assert not revoked_file.exists(), "File must be deleted after revocation"
        print("  [PASSED] Manual link revocation and server-side file deletion")

        # 5. Test Expiration Enforcement & Automatic File Shredding
        # Create link with 1 second TTL
        expiring_img = Image.new("RGB", (150, 150), color=(50, 200, 50))
        expire_info = manager.create_secure_link(expiring_img, duration_seconds=1)
        expire_token = expire_info["token"]
        expire_file = test_storage / "documents" / f"{expire_token}.png"
        assert expire_file.exists(), "Expiring file should exist initially"

        # Sleep 1.5 seconds to cross expiration threshold
        time.sleep(1.5)

        status_e, img_e, meta_e = manager.get_shared_document(expire_token)
        assert status_e == "EXPIRED", f"Expected EXPIRED, got {status_e}"
        assert img_e is None
        assert not expire_file.exists(), "Expired document file must be deleted server-side"
        print("  [PASSED] Server-side TTL expiration enforcement & auto file cleanup")

        # 6. Test Non-existent / Tampered Token
        status_fake, img_fake, _ = manager.get_shared_document("invalid-fake-token-12345")
        assert status_fake == "NOT_FOUND"
        assert img_fake is None
        print("  [PASSED] Non-existent/tampered token rejection")

    finally:
        # Clean up temp dir safely
        try:
            shutil.rmtree(test_storage, ignore_errors=True)
        except Exception:
            pass

    print("\nALL SECURE DOCUMENT LINK TESTS PASSED SUCCESSFULLY!")

    print("\nALL SECURE DOCUMENT LINK TESTS PASSED SUCCESSFULLY!")


if __name__ == "__main__":
    test_secure_links()
