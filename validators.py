"""
ShareSafe - Validators Module
Implements checksum algorithms and domain validations for sensitive Indian identifiers:
1. Verhoeff algorithm for 12-digit Aadhaar numbers
2. Luhn algorithm for payment cards (Credit/Debit)
3. Pattern validators for PAN, Phone numbers, IFSC, Account numbers, and DOB
"""

import re
from typing import Optional

# ==========================================
# Verhoeff Checksum Algorithm
# ==========================================
# Standard tables for the dihedral group D_5
VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]

VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]

VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def validate_verhoeff(number_str: str) -> bool:
    """
    Validates a number string using the Verhoeff algorithm.
    Returns True if valid, False otherwise.
    """
    clean_num = re.sub(r"\D", "", str(number_str))
    if not clean_num:
        return False

    c = 0
    # Process digits in reverse order
    for i, digit in enumerate(reversed(clean_num)):
        c = VERHOEFF_D[c][VERHOEFF_P[i % 8][int(digit)]]

    return c == 0


def generate_verhoeff_check_digit(number_str: str) -> str:
    """
    Calculates the Verhoeff check digit for an uncompleted number string.
    """
    clean_num = re.sub(r"\D", "", str(number_str))
    c = 0
    # For check digit calculation, index starts from 1
    for i, digit in enumerate(reversed(clean_num)):
        c = VERHOEFF_D[c][VERHOEFF_P[(i + 1) % 8][int(digit)]]

    return str(VERHOEFF_INV[c])


def is_valid_aadhaar(number_str: str) -> bool:
    """
    Validates an Aadhaar number:
    - Exactly 12 digits
    - Does not start with 0 or 1 (UIDAI standard)
    - Satisfies Verhoeff checksum
    """
    clean = re.sub(r"\D", "", str(number_str))
    if len(clean) != 12:
        return False
    # UIDAI Aadhaar numbers never start with 0 or 1
    if clean[0] in ("0", "1"):
        return False
    return validate_verhoeff(clean)


def generate_fake_aadhaar(prefix_11: Optional[str] = None, formatted: bool = True) -> str:
    """
    Generates a synthetically valid fake Aadhaar number for demos/testing.
    Defaults to 5489 1234 567x with proper Verhoeff check digit.
    """
    if prefix_11 is None:
        prefix_11 = "54891234567"
    else:
        prefix_11 = re.sub(r"\D", "", prefix_11)[:11]
        if len(prefix_11) < 11:
            prefix_11 = (prefix_11 + "23456789012")[:11]
        if prefix_11[0] in ("0", "1"):
            prefix_11 = "5" + prefix_11[1:]

    check_digit = generate_verhoeff_check_digit(prefix_11)
    full = prefix_11 + check_digit

    if formatted:
        return f"{full[:4]} {full[4:8]} {full[8:]}"
    return full


# ==========================================
# Luhn Algorithm for Payment Cards
# ==========================================
def validate_luhn(card_number_str: str) -> bool:
    """
    Validates a card number using Luhn algorithm (Mod 10).
    Works for 13-19 digit card numbers.
    """
    clean = re.sub(r"\D", "", str(card_number_str))
    if len(clean) < 13 or len(clean) > 19:
        return False

    total = 0
    reverse_digits = clean[::-1]

    for i, char in enumerate(reverse_digits):
        n = int(char)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n

    return total % 10 == 0


# ==========================================
# Pattern Validators
# ==========================================
PAN_REGEX = re.compile(r"^[A-Z]{5}[0-9]{4}[A-Z]$")
PHONE_REGEX = re.compile(r"^(?:\+91[\-\s]?|91[\-\s]?|0)?[6-9]\d{9}$")
IFSC_REGEX = re.compile(r"^[A-Z]{4}0[A-Z0-9]{6}$")


def is_valid_pan(pan_str: str) -> bool:
    """
    Validates Indian Permanent Account Number (PAN):
    - [A-Z]{5}[0-9]{4}[A-Z]
    - Exactly 10 characters
    - 5 uppercase letters, 4 digits, 1 uppercase letter
    """
    pan = pan_str.strip().upper()
    return bool(PAN_REGEX.match(pan))


def is_valid_phone(phone_str: str) -> bool:
    """
    Validates Indian 10-digit mobile phone number, optionally with country code.
    """
    clean = re.sub(r"[\s\-()]", "", phone_str.strip())
    return bool(PHONE_REGEX.match(clean))


def is_valid_ifsc(ifsc_str: str) -> bool:
    """
    Validates Indian Financial System Code (IFSC):
    - 11 characters
    - First 4 alphabetic
    - 5th character is '0'
    - Last 6 alphanumeric
    """
    return bool(IFSC_REGEX.match(ifsc_str.strip().upper()))


def is_valid_dob(dob_str: str) -> bool:
    """
    Validates date string format (DD/MM/YYYY, DD-MM-YYYY, YYYY-MM-DD, etc.)
    """
    patterns = [
        r"^(0[1-9]|[12][0-9]|3[01])[-/.](0[1-9]|1[012])[-/.](19\d\d|20[0-2]\d)$",
        r"^(19\d\d|20[0-2]\d)[-/.](0[1-9]|1[012])[-/.](0[1-9]|[12][0-9]|3[01])$",
    ]
    cleaned = dob_str.strip()
    return any(re.match(p, cleaned) for p in patterns)
