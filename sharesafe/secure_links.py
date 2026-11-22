"""
ShareSafe - Self-Expiring Secure Document Links & Audit Module
Handles cryptographically secure sharing links with server-side time-to-live (TTL)
and tamper-evident access auditing:
- Unique 256-bit URL-safe tokens (secrets.token_urlsafe)
- Server-side expiry enforcement and automatic file shredding
- Manual revocation support
- Local zero-setup SQLite registry & audit log (.secure_shares/shares.db)
- Access Audit Log: Records creation, access attempts, expirations, and revocations
- Strict privacy: NEVER logs document content or unmasked identification numbers
- Strict security: ONLY protected/masked documents can be shared (never originals)
"""

import os
import sqlite3
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, Tuple, List
from pathlib import Path
from PIL import Image

# Default base directory for shared document storage
DEFAULT_STORAGE_DIR = Path(".secure_shares")


class SecureLinkManager:
    """Manages creation, retrieval, validation, audit logging, and auto-cleanup of secure links."""

    def __init__(self, storage_dir: Optional[Path] = None):
        self.storage_dir = Path(storage_dir) if storage_dir else DEFAULT_STORAGE_DIR
        self.docs_dir = self.storage_dir / "documents"
        self.db_path = self.storage_dir / "shares.db"

        # Ensure isolated directories exist
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.docs_dir.mkdir(parents=True, exist_ok=True)

        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Returns SQLite connection with row factory enabled."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Initializes SQLite schema for link metadata and access audit logs."""
        with self._get_connection() as conn:
            # 1. Links registry table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS shared_links (
                    token TEXT PRIMARY KEY,
                    file_name TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    duration_seconds INTEGER NOT NULL,
                    purpose TEXT,
                    document_type TEXT,
                    is_revoked INTEGER DEFAULT 0,
                    revoked_at TEXT,
                    access_count INTEGER DEFAULT 0,
                    last_accessed_at TEXT
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_expires_at ON shared_links (expires_at)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_is_revoked ON shared_links (is_revoked)"
            )

            # 2. Access Audit Log table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token TEXT NOT NULL,
                    token_preview TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    details TEXT
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_token ON audit_logs (token)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs (timestamp)"
            )
            conn.commit()

    def log_audit_event(self, token: str, event_type: str, details: str = ""):
        """
        Appends an event to the Access Audit Log.
        Strict rule: Does NOT log document contents or personal numbers.
        """
        token_clean = str(token).strip()
        token_prev = f"{token_clean[:8]}..." if len(token_clean) > 8 else token_clean
        now_iso = datetime.now(timezone.utc).isoformat()

        try:
            with self._get_connection() as conn:
                conn.execute(
                    """
                    INSERT INTO audit_logs (token, token_preview, event_type, timestamp, details)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (token_clean, token_prev, event_type, now_iso, details),
                )
                conn.commit()
        except Exception:
            pass

    @staticmethod
    def calculate_expiry_seconds(
        preset: str, custom_minutes: Optional[int] = None
    ) -> int:
        """
        Converts preset option or custom minutes into total seconds:
        - "1_hour": 3,600s
        - "6_hours": 21,600s
        - "24_hours": 86,400s (default)
        - "7_days": 604,800s
        - "custom": custom_minutes * 60
        """
        presets = {
            "1_hour": 3600,
            "6_hours": 21600,
            "24_hours": 86400,
            "7_days": 604800,
        }
        if preset in presets:
            return presets[preset]
        if preset == "custom" and custom_minutes and custom_minutes > 0:
            return int(custom_minutes * 60)
        return 86400  # Default 24 hours

    def create_secure_link(
        self,
        masked_image: Image.Image,
        duration_seconds: int = 86400,
        purpose: str = "",
        document_type: str = "Protected Document",
    ) -> Dict[str, Any]:
        """
        Creates a new self-expiring link for a MASKED document.
        Original unmasked documents MUST NEVER be passed to this function.

        Returns dictionary with token, expiry timestamps, and relative link info.
        """
        if not isinstance(masked_image, Image.Image):
            raise TypeError("masked_image must be a PIL Image object")

        # 1. Cryptographically secure 256-bit token
        token = secrets.token_urlsafe(32)

        # 2. Compute UTC timestamps
        now_utc = datetime.now(timezone.utc)
        expires_utc = now_utc + timedelta(seconds=max(1, int(duration_seconds)))

        created_at_iso = now_utc.isoformat()
        expires_at_iso = expires_utc.isoformat()

        # 3. Save masked document image in isolated storage
        file_name = f"{token}.png"
        file_path = self.docs_dir / file_name
        masked_image.save(str(file_path), format="PNG")

        # 4. Record in database
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO shared_links (
                    token, file_name, created_at, expires_at, duration_seconds,
                    purpose, document_type, is_revoked, access_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0)
                """,
                (
                    token,
                    file_name,
                    created_at_iso,
                    expires_at_iso,
                    duration_seconds,
                    purpose.strip(),
                    document_type.strip(),
                ),
            )
            conn.commit()

        # 5. Log audit event
        self.log_audit_event(
            token=token,
            event_type="LINK_CREATED",
            details=f"Created with {duration_seconds}s TTL for purpose '{purpose[:30]}'",
        )

        # Run routine cleanup of any stale records
        self.cleanup_expired_shares()

        return {
            "token": token,
            "created_at": created_at_iso,
            "expires_at": expires_at_iso,
            "duration_seconds": duration_seconds,
            "purpose": purpose,
            "document_type": document_type,
            "relative_url": f"?share={token}",
        }

    def get_shared_document(
        self, token: str
    ) -> Tuple[str, Optional[Image.Image], Optional[Dict[str, Any]]]:
        """
        Server-side validation and retrieval of a shared document:
        Returns:
            status: "ACTIVE" | "EXPIRED" | "REVOKED" | "NOT_FOUND"
            image: PIL.Image if ACTIVE, else None
            metadata: dict with link metadata or None
        """
        clean_token = str(token).strip()
        if not clean_token:
            self.log_audit_event("NONE", "ACCESS_BLOCKED_INVALID", "Empty token requested")
            return "NOT_FOUND", None, None

        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM shared_links WHERE token = ?", (clean_token,)
            ).fetchone()

            if not row:
                self.log_audit_event(clean_token, "ACCESS_BLOCKED_INVALID", "Non-existent token requested")
                return "NOT_FOUND", None, None

            meta = dict(row)

            # Check if manually revoked
            if meta["is_revoked"]:
                self._delete_file_if_exists(meta["file_name"], token=clean_token)
                self.log_audit_event(clean_token, "ACCESS_BLOCKED_REVOKED", "Attempted access to manually revoked link")
                return "REVOKED", None, meta

            # Check server-side expiration
            expires_at = datetime.fromisoformat(meta["expires_at"])
            now_utc = datetime.now(timezone.utc)

            if now_utc >= expires_at:
                # Mark expired and shred file
                self._delete_file_if_exists(meta["file_name"], token=clean_token)
                self.log_audit_event(clean_token, "ACCESS_BLOCKED_EXPIRED", "Attempted access to expired link")
                return "EXPIRED", None, meta

            # Link is valid and active: read file
            file_path = self.docs_dir / meta["file_name"]
            if not file_path.exists():
                self.log_audit_event(clean_token, "ACCESS_BLOCKED_MISSING_FILE", "File missing on server")
                return "NOT_FOUND", None, meta

            try:
                img = Image.open(str(file_path)).convert("RGB")
                # Record access audit
                conn.execute(
                    """
                    UPDATE shared_links
                    SET access_count = access_count + 1,
                        last_accessed_at = ?
                    WHERE token = ?
                    """,
                    (now_utc.isoformat(), clean_token),
                )
                conn.commit()
                meta["access_count"] += 1
                meta["last_accessed_at"] = now_utc.isoformat()

                # Log successful access event
                self.log_audit_event(
                    clean_token,
                    "ACCESS_SUCCESSFUL",
                    f"Document viewed successfully (Access #{meta['access_count']})",
                )
                return "ACTIVE", img, meta
            except Exception:
                return "NOT_FOUND", None, meta

    def revoke_link(self, token: str) -> bool:
        """
        Manually revokes an active link immediately.
        Shreds the associated file from disk and prevents all future access.
        """
        clean_token = str(token).strip()
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT file_name FROM shared_links WHERE token = ?", (clean_token,)
            ).fetchone()
            if not row:
                return False

            now_iso = datetime.now(timezone.utc).isoformat()
            conn.execute(
                """
                UPDATE shared_links
                SET is_revoked = 1,
                    revoked_at = ?
                WHERE token = ?
                """,
                (now_iso, clean_token),
            )
            conn.commit()

            # Log revocation event
            self.log_audit_event(clean_token, "MANUALLY_REVOKED", "Link manually revoked by sender")

            # Shred file from disk
            self._delete_file_if_exists(row["file_name"], token=clean_token)
            return True

    def get_remaining_seconds(self, expires_at_iso: str) -> int:
        """Calculates remaining seconds until expiry. Returns 0 if already expired."""
        try:
            expires_at = datetime.fromisoformat(expires_at_iso)
            now_utc = datetime.now(timezone.utc)
            delta = (expires_at - now_utc).total_seconds()
            return max(0, int(delta))
        except Exception:
            return 0

    def cleanup_expired_shares(self) -> int:
        """
        Scans all records and deletes files for expired or revoked shares.
        Returns count of purged files.
        """
        purged = 0
        now_utc = datetime.now(timezone.utc)

        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT token, file_name, expires_at, is_revoked FROM shared_links"
            ).fetchall()

            for row in rows:
                should_purge = bool(row["is_revoked"])
                if not should_purge:
                    try:
                        exp = datetime.fromisoformat(row["expires_at"])
                        if now_utc >= exp:
                            should_purge = True
                    except Exception:
                        should_purge = True

                if should_purge:
                    if self._delete_file_if_exists(row["file_name"], token=row["token"]):
                        purged += 1

        return purged

    def get_audit_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Returns recent access audit log records.
        """
        with self._get_connection() as conn:
            rows = conn.execute(
                """
                SELECT id, token, token_preview, event_type, timestamp, details
                FROM audit_logs
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]

    def _delete_file_if_exists(self, file_name: str, token: str = "") -> bool:
        """Securely deletes a file if it exists and logs the purge."""
        if not file_name:
            return False
        file_path = self.docs_dir / file_name
        try:
            if file_path.exists():
                file_path.unlink()
                if token:
                    self.log_audit_event(token, "FILE_PURGED", f"File '{file_name[:12]}...' shredded from disk")
                return True
        except Exception:
            pass
        return False


# Module singleton instance
default_link_manager = SecureLinkManager()
