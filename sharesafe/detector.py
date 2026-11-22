"""
ShareSafe - Detector Engine
Extracts text and sensitive entities from document images using OCR with bounding boxes:
- Aadhaar (12-digit, Verhoeff checksum validated, merges spaced tokens)
- PAN ([A-Z]{5}[0-9]{4}[A-Z], entity status validated)
- Indian Mobile Numbers (+91/91/0 prefix, 10 digits starting with 6-9)
- Dates of Birth (standard date formats + DOB keyword proximity)
- Payment Cards (Credit/Debit 13-19 digits, Luhn validated)
- IFSC Codes (11 chars, 4 letters + 0 + 6 alphanumeric)
- Bank Account Numbers (9-18 digits, account keyword context)
- QR Codes (cv2.QRCodeDetector for Aadhaar/e-PAN QR codes)
"""

import os
import re
import shutil
import logging
from typing import List, Dict, Any, Tuple, Optional, Union
import numpy as np
from PIL import Image
import cv2

# Import project validators
from validators import (
    is_valid_aadhaar,
    is_valid_pan,
    validate_luhn,
    is_valid_phone,
    is_valid_ifsc,
    is_valid_dob,
)

logger = logging.getLogger(__name__)

# OCR State Cache
_EASYOCR_READER = None
_TESSERACT_AVAILABLE: Optional[bool] = None
_OCR_ENGINE_NAME: Optional[str] = None


def get_tesseract_path() -> Optional[str]:
    """Finds Tesseract executable if installed."""
    candidate_paths = [
        r"C:\Program Files\Tesseract-OCR\tesseract.exe",
        r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
        os.environ.get("TESSERACT_PATH", ""),
    ]
    for path in candidate_paths:
        if path and os.path.isfile(path):
            return path

    which_path = shutil.which("tesseract")
    if which_path and os.path.isfile(which_path):
        return which_path

    return None


def init_ocr_engine() -> str:
    """
    Initializes OCR:
    1. Checks for Tesseract at C:\\Program Files\\Tesseract-OCR\\tesseract.exe or PATH
    2. If missing, falls back to EasyOCR
    Returns the engine name ('tesseract' or 'easyocr')
    """
    global _TESSERACT_AVAILABLE, _OCR_ENGINE_NAME, _EASYOCR_READER

    if _OCR_ENGINE_NAME is not None:
        return _OCR_ENGINE_NAME

    tess_path = get_tesseract_path()
    if tess_path:
        try:
            import pytesseract
            pytesseract.pytesseract.tesseract_cmd = tess_path
            # Quick smoke test with dummy image
            dummy = Image.new("RGB", (30, 30), color="white")
            pytesseract.image_to_string(dummy)
            _TESSERACT_AVAILABLE = True
            _OCR_ENGINE_NAME = "tesseract"
            logger.info("Using Tesseract OCR at: %s", tess_path)
            return _OCR_ENGINE_NAME
        except Exception as e:
            logger.warning("Tesseract check failed (%s), falling back to EasyOCR", e)
            _TESSERACT_AVAILABLE = False

    # Fallback to EasyOCR
    try:
        import easyocr
        if _EASYOCR_READER is None:
            # Initialize EasyOCR reader for English
            _EASYOCR_READER = easyocr.Reader(["en"], gpu=False)
        _OCR_ENGINE_NAME = "easyocr"
        logger.info("Using EasyOCR fallback engine")
        return _OCR_ENGINE_NAME
    except Exception as e:
        logger.error("Failed to load EasyOCR: %s", e)
        raise RuntimeError(
            "Neither Tesseract nor EasyOCR is available. Please install Tesseract-OCR or EasyOCR."
        )


def to_pil_and_cv2(image_input: Union[Image.Image, np.ndarray, str]) -> Tuple[Image.Image, np.ndarray]:
    """Converts image input to both PIL Image and OpenCV BGR numpy array."""
    if isinstance(image_input, str):
        pil_img = Image.open(image_input).convert("RGB")
        cv_img = cv2.cvtColor(np.array(pil_img), cv2.COLOR_RGB2BGR)
    elif isinstance(image_input, Image.Image):
        pil_img = image_input.convert("RGB")
        cv_img = cv2.cvtColor(np.array(pil_img), cv2.COLOR_RGB2BGR)
    elif isinstance(image_input, np.ndarray):
        if len(image_input.shape) == 2:
            cv_img = cv2.cvtColor(image_input, cv2.COLOR_GRAY2BGR)
            pil_img = Image.fromarray(image_input).convert("RGB")
        elif image_input.shape[2] == 4:
            cv_img = cv2.cvtColor(image_input, cv2.COLOR_RGBA2BGR)
            pil_img = Image.fromarray(cv2.cvtColor(cv_img, cv2.COLOR_BGR2RGB))
        else:
            # Assume BGR if coming from cv2, or test color
            cv_img = image_input
            pil_img = Image.fromarray(cv2.cvtColor(image_input, cv2.COLOR_BGR2RGB))
    else:
        raise ValueError("Unsupported image type")

    return pil_img, cv_img


def extract_ocr_tokens(pil_img: Image.Image, cv_img: np.ndarray) -> List[Dict[str, Any]]:
    """
    Runs the selected OCR engine and returns normalized word tokens:
    [{"text": str, "x": int, "y": int, "w": int, "h": int, "line": int}, ...]
    """
    engine = init_ocr_engine()
    tokens = []

    if engine == "tesseract":
        import pytesseract
        # Output detailed TSV-style dictionary
        data = pytesseract.image_to_data(pil_img, output_type=pytesseract.Output.DICT)
        n_boxes = len(data["text"])
        for i in range(n_boxes):
            text = data["text"][i].strip()
            conf = float(data["conf"][i])
            if text and conf > 20:  # Ignore low confidence noise
                tokens.append({
                    "text": text,
                    "x": int(data["left"][i]),
                    "y": int(data["top"][i]),
                    "w": int(data["width"][i]),
                    "h": int(data["height"][i]),
                    "line": int(data["line_num"][i]),
                    "block": int(data["block_num"][i]),
                })
    else:
        # EasyOCR
        global _EASYOCR_READER
        if _EASYOCR_READER is None:
            import easyocr
            _EASYOCR_READER = easyocr.Reader(["en"], gpu=False)

        # EasyOCR works directly on numpy array
        results = _EASYOCR_READER.readtext(np.array(pil_img))
        # results: [(bbox, text, prob), ...]
        # bbox: [[x1, y1], [x2, y1], [x2, y2], [x1, y2]]
        for idx, (bbox, text, prob) in enumerate(results):
            text = text.strip()
            if text and prob > 0.2:
                xs = [pt[0] for pt in bbox]
                ys = [pt[1] for pt in bbox]
                x = int(min(xs))
                y = int(min(ys))
                w = int(max(xs) - x)
                h = int(max(ys) - y)
                tokens.append({
                    "text": text,
                    "x": x,
                    "y": y,
                    "w": w,
                    "h": h,
                    "line": y // 30,  # approximate line grouping by vertical position
                    "block": 1,
                })

    return tokens


def detect_qr_codes(cv_img: np.ndarray) -> List[Dict[str, Any]]:
    """
    Detects QR codes using OpenCV's QRCodeDetector.
    Validates decoded payload or square geometry to avoid false positives.
    """
    findings = []
    try:
        img_h, img_w = cv_img.shape[:2]
        detector = cv2.QRCodeDetector()

        # Try detectAndDecodeMulti first
        has_multi, decoded_info, points, _ = detector.detectAndDecodeMulti(cv_img)
        if points is not None and len(points) > 0:
            for i, pts in enumerate(points):
                xs = [pt[0] for pt in pts]
                ys = [pt[1] for pt in pts]
                x = max(0, int(min(xs)))
                y = max(0, int(min(ys)))
                w = int(max(xs) - x)
                h = int(max(ys) - y)
                data = decoded_info[i].strip() if (has_multi and i < len(decoded_info)) else ""

                aspect = w / max(1, h)
                is_reasonable_size = (w < img_w * 0.65) and (h < img_h * 0.65) and (w >= 30 and h >= 30)
                is_square = 0.7 <= aspect <= 1.4

                # Accept if payload is decoded, or if shape is a distinct square
                if (data or is_square) and is_reasonable_size:
                    findings.append({
                        "type": "QR Code",
                        "text": (data[:35] + "...") if len(data) > 35 else (data or "Aadhaar / Secure QR Code"),
                        "bbox": (x, y, w, h),
                        "risk_level": "High",
                        "reason": "QR codes on Aadhaar or e-PAN cards store unmasked demographic data, photos, and digital signatures that can be decoded instantly.",
                    })
        else:
            # Single QR fallback
            data, pts, _ = detector.detectAndDecode(cv_img)
            if pts is not None and len(pts) > 0:
                pts = pts[0]
                xs = [pt[0] for pt in pts]
                ys = [pt[1] for pt in pts]
                x = max(0, int(min(xs)))
                y = max(0, int(min(ys)))
                w = int(max(xs) - x)
                h = int(max(ys) - y)
                data = (data or "").strip()

                aspect = w / max(1, h)
                is_reasonable_size = (w < img_w * 0.65) and (h < img_h * 0.65) and (w >= 30 and h >= 30)
                is_square = 0.7 <= aspect <= 1.4

                if (data or is_square) and is_reasonable_size:
                    findings.append({
                        "type": "QR Code",
                        "text": (data[:35] + "...") if len(data) > 35 else (data or "Aadhaar / Secure QR Code"),
                        "bbox": (x, y, w, h),
                        "risk_level": "High",
                        "reason": "QR codes on Aadhaar or e-PAN cards store unmasked demographic data, photos, and digital signatures that can be decoded instantly.",
                    })
    except Exception as e:
        logger.warning("QR code detection encountered an error: %s", e)

    return findings


def merge_bounding_boxes(tokens: List[Dict[str, Any]]) -> Tuple[int, int, int, int]:
    """Computes enclosing bounding box (x, y, w, h) for a list of tokens."""
    min_x = min(t["x"] for t in tokens)
    min_y = min(t["y"] for t in tokens)
    max_r = max(t["x"] + t["w"] for t in tokens)
    max_b = max(t["y"] + t["h"] for t in tokens)
    return min_x, min_y, max_r - min_x, max_b - min_y


def is_overlapping(bbox1: Tuple[int, int, int, int], bbox2: Tuple[int, int, int, int]) -> bool:
    """Checks if two bounding boxes overlap significantly."""
    x1, y1, w1, h1 = bbox1
    x2, y2, w2, h2 = bbox2
    # Check intersection
    xi1 = max(x1, x2)
    yi1 = max(y1, y2)
    xi2 = min(x1 + w1, x2 + w2)
    yi2 = min(y1 + h1, y2 + h2)

    inter_w = max(0, xi2 - xi1)
    inter_h = max(0, yi2 - yi1)
    inter_area = inter_w * inter_h
    if inter_area == 0:
        return False

    area1 = w1 * h1
    area2 = w2 * h2
    min_area = min(area1, area2)
    return (inter_area / min_area) > 0.5


def group_tokens_into_lines(tokens: List[Dict[str, Any]], y_threshold: int = 15) -> List[List[Dict[str, Any]]]:
    """
    Groups tokens that appear on the same physical line based on y-coordinate proximity.
    Sorts tokens within each line from left to right.
    """
    if not tokens:
        return []

    # Sort primarily by vertical center, then by horizontal x
    sorted_tokens = sorted(tokens, key=lambda t: (t["y"], t["x"]))
    lines: List[List[Dict[str, Any]]] = []

    for token in sorted_tokens:
        token_center_y = token["y"] + token["h"] / 2
        assigned = False
        for line in lines:
            line_avg_y = sum(t["y"] + t["h"] / 2 for t in line) / len(line)
            if abs(token_center_y - line_avg_y) <= y_threshold:
                line.append(token)
                assigned = True
                break
        if not assigned:
            lines.append([token])

    # Sort each line horizontally by x
    for line in lines:
        line.sort(key=lambda t: t["x"])

    return lines


def detect_sensitive(image_input: Union[Image.Image, np.ndarray, str]) -> List[Dict[str, Any]]:
    """
    Scans a document image and detects sensitive personal data:
    - Aadhaar (12 digits, Verhoeff checksum validated, merges spaced tokens)
    - PAN ([A-Z]{5}[0-9]{4}[A-Z], entity status validated)
    - Mobile phone numbers (+91 / 10 digits starting with 6-9)
    - Dates of birth (DD/MM/YYYY, etc. or near DOB keywords)
    - Payment cards (Luhn checksum validated)
    - Bank Account numbers
    - IFSC Codes
    - QR Codes (cv2.QRCodeDetector)

    Returns list of findings:
    [
        {
            "type": str,
            "text": str,
            "bbox": (x, y, w, h),
            "risk_level": "High" | "Medium" | "Low",
            "reason": str
        }, ...
    ]
    """
    try:
        pil_img, cv_img = to_pil_and_cv2(image_input)
    except Exception as e:
        logger.error("Failed to load image: %s", e)
        return []

    findings: List[Dict[str, Any]] = []

    # 1. Detect QR Codes first
    qr_findings = detect_qr_codes(cv_img)
    findings.extend(qr_findings)

    # 2. Extract OCR Tokens
    try:
        tokens = extract_ocr_tokens(pil_img, cv_img)
    except Exception as e:
        logger.error("OCR extraction failed: %s", e)
        return findings

    if not tokens:
        return findings

    lines = group_tokens_into_lines(tokens)
    matched_token_ids = set()

    # Pre-compiled regex patterns
    pan_regex = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")
    ifsc_regex = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")
    dob_regex = re.compile(
        r"\b(?:0[1-9]|[12][0-9]|3[01])[-/.](?:0[1-9]|1[012])[-/.](?:19\d\d|20[0-2]\d)\b"
    )
    phone_regex = re.compile(r"\b(?:\+91[\-\s]?|91[\-\s]?|0)?[6-9]\d{9}\b")
    aadhaar_pure_regex = re.compile(r"\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b")
    account_keyword_regex = re.compile(
        r"(?:A/C|ACCOUNT|ACCT|AC\s*NO|खाता|A/C\s*NO|ACCOUNT\s*NO)", re.IGNORECASE
    )

    # Process line by line
    for line in lines:
        line_full_text = " ".join(t["text"] for t in line)
        n_tokens = len(line)

        # -------------------------------------------------------------
        # A. Check for Aadhaar Numbers (Single token or Merged 2-4 tokens)
        # -------------------------------------------------------------
        # Check merged window of tokens (e.g. 3 tokens: "5489", "1234", "5678")
        for window_size in (3, 4, 2, 1):
            for i in range(n_tokens - window_size + 1):
                sub_tokens = line[i : i + window_size]
                combo_text = "".join(re.sub(r"\D", "", t["text"]) for t in sub_tokens)
                if len(combo_text) == 12 and combo_text[0] in "23456789":
                    if is_valid_aadhaar(combo_text):
                        bbox = merge_bounding_boxes(sub_tokens)
                        formatted_aadhaar = f"{combo_text[:4]} {combo_text[4:8]} {combo_text[8:]}"
                        findings.append({
                            "type": "Aadhaar Number",
                            "text": formatted_aadhaar,
                            "bbox": bbox,
                            "risk_level": "High",
                            "reason": "Aadhaar number can be exploited for identity theft, unauthorized SIM activation, fraudulent KYC, and unauthorized bank mandates.",
                        })
                        for st in sub_tokens:
                            matched_token_ids.add(id(st))
                        break

        # -------------------------------------------------------------
        # B. Check for Payment Card Numbers (Luhn Validated, 13-19 digits)
        # -------------------------------------------------------------
        for window_size in (4, 3, 2, 1):
            for i in range(n_tokens - window_size + 1):
                sub_tokens = line[i : i + window_size]
                if any(id(st) in matched_token_ids for st in sub_tokens):
                    continue
                combo_digits = "".join(re.sub(r"\D", "", t["text"]) for t in sub_tokens)
                if 13 <= len(combo_digits) <= 19:
                    if validate_luhn(combo_digits):
                        bbox = merge_bounding_boxes(sub_tokens)
                        formatted_card = " ".join([combo_digits[j:j+4] for j in range(0, len(combo_digits), 4)])
                        findings.append({
                            "type": "Payment Card Number",
                            "text": formatted_card,
                            "bbox": bbox,
                            "risk_level": "High",
                            "reason": "Card numbers can be used for unauthorized online card-not-present transactions and unauthorized billing.",
                        })
                        for st in sub_tokens:
                            matched_token_ids.add(id(st))
                        break

        # -------------------------------------------------------------
        # C. Token-level and regex scans (PAN, IFSC, DOB, Phone, Account)
        # -------------------------------------------------------------
        for idx, token in enumerate(line):
            if id(token) in matched_token_ids:
                continue

            raw_txt = token["text"]
            clean_alnum = re.sub(r"[^\w]", "", raw_txt).upper()

            # 1. PAN Check
            pan_match = pan_regex.search(clean_alnum)
            if pan_match:
                candidate_pan = pan_match.group(0)
                if is_valid_pan(candidate_pan):
                    findings.append({
                        "type": "PAN Number",
                        "text": candidate_pan,
                        "bbox": (token["x"], token["y"], token["w"], token["h"]),
                        "risk_level": "High",
                        "reason": "PAN provides access to tax records, CIBIL credit profiles, loan applications, and high-value financial fraud.",
                    })
                    matched_token_ids.add(id(token))
                    continue

            # 2. IFSC Code Check
            ifsc_match = ifsc_regex.search(clean_alnum)
            if ifsc_match:
                candidate_ifsc = ifsc_match.group(0)
                if is_valid_ifsc(candidate_ifsc):
                    findings.append({
                        "type": "IFSC Code",
                        "text": candidate_ifsc,
                        "bbox": (token["x"], token["y"], token["w"], token["h"]),
                        "risk_level": "Low",
                        "reason": "Reveals your exact bank branch. Low risk on its own, but enables targeted fraud when paired with an account number.",
                    })
                    matched_token_ids.add(id(token))
                    continue

            # 3. Date of Birth Check
            # Check single token or token pair (e.g. "DOB:" followed by date)
            dob_match = dob_regex.search(raw_txt)
            if dob_match:
                findings.append({
                    "type": "Date of Birth",
                    "text": dob_match.group(0),
                    "bbox": (token["x"], token["y"], token["w"], token["h"]),
                    "risk_level": "Medium",
                    "reason": "Date of birth is a standard secondary verification factor for password resets, banking phone support, and verification.",
                })
                matched_token_ids.add(id(token))
                continue

            # Check if previous token was DOB label
            if idx > 0 and any(kw in line[idx-1]["text"].upper() for kw in ["DOB", "BIRTH", "जन्म"]):
                if is_valid_dob(raw_txt):
                    bbox = merge_bounding_boxes([line[idx-1], token])
                    findings.append({
                        "type": "Date of Birth",
                        "text": raw_txt,
                        "bbox": bbox,
                        "risk_level": "Medium",
                        "reason": "Date of birth is a standard secondary verification factor for password resets, banking phone support, and verification.",
                    })
                    matched_token_ids.add(id(token))
                    matched_token_ids.add(id(line[idx-1]))
                    continue

            # 4. Indian Mobile Phone Number Check
            phone_match = phone_regex.search(raw_txt)
            if phone_match:
                phone_candidate = phone_match.group(0)
                if is_valid_phone(phone_candidate):
                    findings.append({
                        "type": "Mobile Phone Number",
                        "text": phone_candidate,
                        "bbox": (token["x"], token["y"], token["w"], token["h"]),
                        "risk_level": "Medium",
                        "reason": "Direct phone number exposes you to targeted phishing (vishing), SMS spoofing, and social engineering attacks.",
                    })
                    matched_token_ids.add(id(token))
                    continue

            # 5. Bank Account Number Check
            # Look for 9 to 18 digits in line that contains account keywords
            clean_digits = re.sub(r"\D", "", raw_txt)
            if 9 <= len(clean_digits) <= 18:
                # Check if this line or adjacent tokens contain account keywords
                has_acct_kw = bool(account_keyword_regex.search(line_full_text))
                if has_acct_kw and not is_valid_aadhaar(clean_digits) and not validate_luhn(clean_digits):
                    findings.append({
                        "type": "Bank Account Number",
                        "text": clean_digits,
                        "bbox": (token["x"], token["y"], token["w"], token["h"]),
                        "risk_level": "Medium",
                        "reason": "Bank account numbers paired with your name can be targeted for unauthorized auto-debits and phishing campaigns.",
                    })
                    matched_token_ids.add(id(token))
                    continue

    # Deduplicate findings
    # 1. Keep valid QR code detections
    deduped_findings: List[Dict[str, Any]] = list(qr_findings)

    # 2. Separate text findings and sort by entity priority
    # Priority: Aadhaar > Payment Card > PAN > Account > Phone > DOB > IFSC
    priority = {
        "Aadhaar Number": 1,
        "Payment Card Number": 2,
        "PAN Number": 3,
        "Bank Account Number": 4,
        "Mobile Phone Number": 5,
        "Date of Birth": 6,
        "IFSC Code": 7,
    }
    text_findings = [f for f in findings if f.get("type") != "QR Code"]
    text_findings.sort(key=lambda f: priority.get(f.get("type"), 99))

    for f in text_findings:
        overlap = False
        for existing in deduped_findings:
            if existing.get("type") == "QR Code":
                continue
            if is_overlapping(f["bbox"], existing["bbox"]):
                overlap = True
                break
        if not overlap:
            deduped_findings.append(f)

    return deduped_findings


def calculate_risk_score(findings: List[Dict[str, Any]]) -> int:
    """
    Computes a 0-100 Privacy Risk Score based on the detected sensitive items.
    High risk item: 35 points
    Medium risk item: 20 points
    Low risk item: 10 points
    Capped at 100. If any findings exist, minimum score is 25.
    """
    if not findings:
        return 0

    weights = {
        "High": 35,
        "Medium": 20,
        "Low": 10,
    }

    score = sum(weights.get(f.get("risk_level", "Medium"), 15) for f in findings)
    score = max(25, min(100, score))
    return score
