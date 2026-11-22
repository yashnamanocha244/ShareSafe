"""
ShareSafe - Samples Module
Generates realistic synthetic demonstration documents:
1. Fake Aadhaar Card (with Verhoeff-valid 12-digit number, demographics, and QR code)
2. Fake PAN Card (with valid PAN format ABCPE1234F, DOB, photo frame, and QR code)
3. Fake Payment Card (with Luhn-valid 16-digit card number and bank branding)

All generated documents explicitly include a prominent:
"SAMPLE - NOT A REAL DOCUMENT / केवल डेमो के लिए" watermark/banner.
"""

from typing import Tuple
from PIL import Image, ImageDraw, ImageFont
import numpy as np
import cv2

from validators import generate_fake_aadhaar


def get_font(size: int = 20, bold: bool = False) -> ImageFont.ImageFont:
    """Attempts to find system TrueType fonts or falls back cleanly."""
    font_names = (
        ["arialbd.ttf", "segoeuib.ttf", "calibrib.ttf", "Arial Bold.ttf"]
        if bold
        else ["arial.ttf", "segoeui.ttf", "calibri.ttf", "Arial.ttf"]
    )
    for name in font_names:
        try:
            return ImageFont.truetype(name, size)
        except Exception:
            continue
    try:
        return ImageFont.load_default(size=size)
    except Exception:
        return ImageFont.load_default()


def draw_qr_matrix(img: Image.Image, top_left: Tuple[int, int], size: int = 150, payload: str = "https://uidai.gov.in/verify"):
    """Generates and pastes a genuine scannable QR code using cv2.QRCodeEncoder."""
    try:
        enc = cv2.QRCodeEncoder_create()
        qr_matrix = enc.encode(payload)
        # Resize nearest neighbor so crisp blocks
        qr_resized = cv2.resize(qr_matrix, (size, size), interpolation=cv2.INTER_NEAREST)
        qr_pil = Image.fromarray(qr_resized).convert("RGB")
        img.paste(qr_pil, top_left)
    except Exception:
        # Fallback to white box with border
        draw = ImageDraw.Draw(img)
        x0, y0 = top_left
        draw.rectangle((x0, y0, x0 + size, y0 + size), fill=(255, 255, 255), outline=(0, 0, 0), width=2)


def generate_sample_aadhaar() -> Image.Image:
    """
    Generates a synthetic Aadhaar-style card with:
    - Verhoeff-VALID fake 12-digit number (5489 1234 567x)
    - Demographics (Name, DOB, Mobile)
    - QR Code and Photo frame
    - Prominent 'SAMPLE - NOT A REAL DOCUMENT' banner
    """
    w, h = 850, 520
    img = Image.new("RGB", (w, h), color=(253, 253, 254))
    draw = ImageDraw.Draw(img)

    # 1. Top Header Stripes (Indian tricolor subtle bars)
    draw.rectangle((0, 0, w, 14), fill=(255, 153, 51))   # Saffron
    draw.rectangle((0, 14, w, 24), fill=(255, 255, 255)) # White
    draw.rectangle((0, 24, w, 38), fill=(19, 136, 8))    # Green

    # Government Title
    f_title = get_font(size=22, bold=True)
    f_sub = get_font(size=14, bold=False)
    draw.text((60, 48), "भारत सरकार / Government of India", fill=(20, 20, 20), font=f_title)
    draw.text((60, 78), "Unique Identification Authority of India", fill=(70, 70, 70), font=f_sub)

    # Sample Disclaimer Banner
    f_disclaimer = get_font(size=13, bold=True)
    draw.rectangle((w - 380, 48, w - 30, 84), fill=(255, 235, 235), outline=(220, 53, 69), width=2)
    draw.text((w - 365, 58), "⚠️ SAMPLE - NOT A REAL DOCUMENT", fill=(180, 20, 20), font=f_disclaimer)

    # Divider Line
    draw.line((40, 105, w - 40, 105), fill=(210, 210, 215), width=2)

    # Photo Box
    draw.rectangle((60, 130, 210, 310), fill=(235, 240, 245), outline=(160, 170, 180), width=2)
    f_photo = get_font(size=15, bold=True)
    draw.text((105, 205), "[ PHOTO ]", fill=(120, 130, 140), font=f_photo)

    # Demographic Details
    f_label = get_font(size=16, bold=False)
    f_val = get_font(size=18, bold=True)

    draw.text((240, 140), "Name / नाम:", fill=(90, 90, 90), font=f_label)
    draw.text((360, 140), "Aarav Sharma", fill=(15, 15, 15), font=f_val)

    draw.text((240, 185), "DOB / जन्म तिथि:", fill=(90, 90, 90), font=f_label)
    draw.text((360, 185), "12/05/1992", fill=(15, 15, 15), font=f_val)

    draw.text((240, 230), "Gender / लिंग:", fill=(90, 90, 90), font=f_label)
    draw.text((360, 230), "MALE / पुरुष", fill=(15, 15, 15), font=f_val)

    draw.text((240, 275), "Mobile / मोबाइल:", fill=(90, 90, 90), font=f_label)
    draw.text((360, 275), "9876543210", fill=(15, 15, 15), font=f_val)

    # QR Code Box
    draw_qr_matrix(img, (w - 220, 130), size=160, payload="https://uidai.gov.in/verify?uid=548912345674")
    f_qr = get_font(size=11, bold=False)
    draw.text((w - 200, 300), "Secure Digital QR", fill=(100, 100, 100), font=f_qr)

    # Bottom Aadhaar Bar
    draw.rectangle((40, 355, w - 40, 465), fill=(245, 247, 250), outline=(200, 205, 215), width=2)

    # Generate genuine Verhoeff-valid fake Aadhaar number
    aadhaar_valid_str = generate_fake_aadhaar("54891234567", formatted=True)
    f_num = get_font(size=34, bold=True)
    draw.text((180, 385), aadhaar_valid_str, fill=(180, 20, 20), font=f_num)

    f_subaadhaar = get_font(size=14, bold=False)
    draw.text((270, 435), "मेरा आधार, मेरी पहचान (Aadhaar Card)", fill=(80, 80, 80), font=f_subaadhaar)

    # Bottom watermark footer
    f_footer = get_font(size=12, bold=False)
    draw.text((60, 490), "Generated strictly for ShareSafe prototype demonstration. Not valid for any official purpose.", fill=(140, 140, 140), font=f_footer)

    return img


def generate_sample_pan() -> Image.Image:
    """
    Generates a synthetic PAN-style card with:
    - Valid PAN format (ABCPE1234F)
    - Demographics (Name, Father's Name, DOB)
    - Photo, Signature Box, and QR code
    - Prominent 'SAMPLE - NOT A REAL DOCUMENT' banner
    """
    w, h = 850, 520
    # PAN card signature pale blue background
    img = Image.new("RGB", (w, h), color=(238, 246, 252))
    draw = ImageDraw.Draw(img)

    # Header Bar
    draw.rectangle((0, 0, w, 70), fill=(16, 92, 148))
    f_hdr = get_font(size=22, bold=True)
    f_hdre = get_font(size=13, bold=False)
    draw.text((50, 14), "आयकर विभाग / INCOME TAX DEPARTMENT", fill=(255, 255, 255), font=f_hdr)
    draw.text((50, 44), "भारत सरकार / GOVT. OF INDIA", fill=(220, 235, 250), font=f_hdre)

    # Sample Tag
    f_disclaimer = get_font(size=12, bold=True)
    draw.rectangle((w - 360, 14, w - 30, 52), fill=(255, 240, 240), outline=(220, 53, 69), width=2)
    draw.text((w - 345, 24), "⚠️ SAMPLE - NOT A REAL DOCUMENT", fill=(180, 20, 20), font=f_disclaimer)

    # Photo Box
    draw.rectangle((50, 95, 200, 275), fill=(245, 248, 252), outline=(130, 150, 170), width=2)
    f_photo = get_font(size=14, bold=True)
    draw.text((95, 175), "[ PHOTO ]", fill=(120, 140, 160), font=f_photo)

    # Demographics
    f_label = get_font(size=14, bold=False)
    f_val = get_font(size=18, bold=True)

    draw.text((230, 95), "नाम / Name", fill=(80, 100, 120), font=f_label)
    draw.text((230, 120), "PRIYA VERMA", fill=(10, 20, 30), font=f_val)

    draw.text((230, 160), "पिता का नाम / Father's Name", fill=(80, 100, 120), font=f_label)
    draw.text((230, 185), "RAMESH VERMA", fill=(10, 20, 30), font=f_val)

    draw.text((230, 225), "जन्म की तारीख / Date of Birth", fill=(80, 100, 120), font=f_label)
    draw.text((230, 250), "28/11/1995", fill=(10, 20, 30), font=f_val)

    # QR Code
    draw_qr_matrix(img, (w - 220, 95), size=160, payload="https://incometaxindia.gov.in/pan/verify?pan=ABCPE1234F")

    # Signature box
    draw.rectangle((50, 295, 200, 355), fill=(255, 255, 255), outline=(130, 150, 170), width=1)
    f_sig = get_font(size=15, bold=False)
    draw.text((70, 318), "~ Priya Verma ~", fill=(50, 50, 90), font=f_sig)

    # PAN Number Box
    draw.rectangle((50, 380, w - 50, 460), fill=(255, 255, 255), outline=(16, 92, 148), width=3)
    f_pan_lbl = get_font(size=15, bold=False)
    draw.text((70, 408), "Permanent Account Number :", fill=(60, 60, 60), font=f_pan_lbl)

    f_pan_val = get_font(size=34, bold=True)
    draw.text((370, 396), "ABCPE1234F", fill=(16, 92, 148), font=f_pan_val)

    # Bottom legal tag
    f_footer = get_font(size=12, bold=False)
    draw.text((50, 485), "For testing ShareSafe privacy detection engine only. Fictitious identity.", fill=(120, 130, 140), font=f_footer)

    return img


def generate_sample_cheque_or_card() -> Image.Image:
    """
    Generates a synthetic Payment Card / Cheque with:
    - Luhn-valid 16-digit card number (4532 0151 1283 0366)
    - Cardholder Name, Expiry date, Bank branding
    - Prominent 'SAMPLE - NOT A REAL DOCUMENT' banner
    """
    w, h = 850, 520
    # Sleek dark-navy metallic card background
    img = Image.new("RGB", (w, h), color=(26, 38, 57))
    draw = ImageDraw.Draw(img)

    # Subtle gradient or top highlight bar
    draw.rectangle((0, 0, w, 10), fill=(0, 180, 216))

    # Bank Name
    f_bank = get_font(size=26, bold=True)
    draw.text((60, 45), "GLOBAL BANK OF INDIA", fill=(255, 255, 255), font=f_bank)

    # Sample Tag
    f_disclaimer = get_font(size=13, bold=True)
    draw.rectangle((w - 380, 40, w - 40, 80), fill=(255, 235, 235), outline=(220, 53, 69), width=2)
    draw.text((w - 365, 50), "⚠️ SAMPLE - NOT A REAL CARD", fill=(200, 20, 20), font=f_disclaimer)

    # EMV Chip graphic
    chip_x, chip_y = 70, 150
    draw.rectangle((chip_x, chip_y, chip_x + 90, chip_y + 70), fill=(218, 165, 32), outline=(180, 130, 10), width=2)
    draw.line((chip_x + 30, chip_y, chip_x + 30, chip_y + 70), fill=(160, 110, 0), width=2)
    draw.line((chip_x + 60, chip_y, chip_x + 60, chip_y + 70), fill=(160, 110, 0), width=2)
    draw.line((chip_x, chip_y + 35, chip_x + 90, chip_y + 35), fill=(160, 110, 0), width=2)

    # Contactless wave symbol
    f_wave = get_font(size=28, bold=True)
    draw.text((180, 160), ")))", fill=(200, 220, 240), font=f_wave)

    # Luhn-valid card number: 4532 0151 1283 0366
    valid_card_num = "4532  0151  1283  0366"
    f_card_num = get_font(size=36, bold=True)
    draw.text((70, 275), valid_card_num, fill=(255, 255, 255), font=f_card_num)

    # Expiry and Cardholder
    f_exp_lbl = get_font(size=12, bold=False)
    f_exp_val = get_font(size=18, bold=True)
    draw.text((360, 345), "VALID THRU", fill=(170, 190, 210), font=f_exp_lbl)
    draw.text((440, 340), "08/29", fill=(255, 255, 255), font=f_exp_val)

    f_name = get_font(size=22, bold=True)
    draw.text((70, 400), "ROHIT MEHTA", fill=(255, 255, 255), font=f_name)

    # Card Network (RuPay / Visa mock)
    f_network = get_font(size=30, bold=True)
    draw.text((w - 180, 395), "RuPay", fill=(0, 180, 216), font=f_network)

    # Bottom note
    f_footer = get_font(size=12, bold=False)
    draw.text((70, 480), "Mock payment card generated for ShareSafe prototype testing. No monetary value.", fill=(150, 170, 190), font=f_footer)

    return img
