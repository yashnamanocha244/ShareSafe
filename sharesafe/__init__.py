"""
ShareSafe Package
"""
from .validators import is_valid_aadhaar, is_valid_pan, validate_luhn, validate_verhoeff
from .detector import detect_sensitive, calculate_risk_score
from .masker import apply_masks, add_watermark
from .samples import generate_sample_aadhaar, generate_sample_pan, generate_sample_cheque_or_card
from .i18n import t
from .secure_links import SecureLinkManager, default_link_manager
from .intelligence import classify_sharing_purpose, analyze_privacy_risks, generate_privacy_report

__all__ = [
    "is_valid_aadhaar",
    "is_valid_pan",
    "validate_luhn",
    "validate_verhoeff",
    "detect_sensitive",
    "calculate_risk_score",
    "apply_masks",
    "add_watermark",
    "generate_sample_aadhaar",
    "generate_sample_pan",
    "generate_sample_cheque_or_card",
    "SecureLinkManager",
    "default_link_manager",
    "classify_sharing_purpose",
    "analyze_privacy_risks",
    "generate_privacy_report",
    "t",
]
