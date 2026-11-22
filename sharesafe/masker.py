"""
ShareSafe - Masker Module
Provides privacy transformation functions:
1. apply_masks(image, findings, mode)
   - "full": Solid opaque blackout boxes over selected sensitive findings
   - "partial": Masks the first 8 digits of Aadhaar (showing only last 4 digits like official masked Aadhaar),
                masks first 12 digits of payment cards, first 6 of phone numbers, etc.
   - "blur": Strong Gaussian blur over selected sensitive regions
   - Note: QR codes are ALWAYS heavily blurred or blacked out when masking is active.
2. add_watermark(image, purpose_text)
   - Stamps semi-transparent diagonal purpose text across the document (e.g. "Shared for: Axis Bank KYC | 22-Nov-2026")
   - Prevents secondary fraudulent KYC reuse by making the copy non-transferable.
"""

from typing import List, Dict, Any, Union, Tuple
from datetime import datetime
import numpy as np
from PIL import Image, ImageDraw, ImageFont, ImageFilter
import cv2

from detector import to_pil_and_cv2


def get_default_font(size: int = 24) -> ImageFont.ImageFont:
    """Attempts to load a clean TrueType font or falls back to PIL default font."""
    font_candidates = [
        "arial.ttf",
        "Arial.ttf",
        "seguiui.ttf",
        "calibri.ttf",
        "C:\\Windows\\Fonts\\arial.ttf",
        "C:\\Windows\\Fonts\\segoeui.ttf",
    ]
    for font_path in font_candidates:
        try:
            return ImageFont.truetype(font_path, size)
        except Exception:
            continue
    try:
        return ImageFont.load_default(size=size)
    except Exception:
        return ImageFont.load_default()


def apply_masks(
    image_input: Union[Image.Image, np.ndarray, str],
    findings: List[Dict[str, Any]],
    mode: str = "partial",
    selected_indices: List[int] = None,
) -> Image.Image:
    """
    Applies privacy masks to sensitive bounding boxes.

    Parameters:
    - image_input: PIL Image or OpenCV numpy array
    - findings: List of finding dicts from detector.py
    - mode: "full", "partial", "blur", or "none" (send original)
    - selected_indices: Optional list of indices in findings to mask. If None, masks all.

    Returns:
    - Masked PIL Image
    """
    pil_img, _ = to_pil_and_cv2(image_input)
    img_width, img_height = pil_img.size

    if mode == "none" or not findings:
        return pil_img

    if selected_indices is None:
        selected_indices = list(range(len(findings)))

    selected_set = set(selected_indices)
    result_img = pil_img.copy()
    draw = ImageDraw.Draw(result_img)

    for idx, finding in enumerate(findings):
        # QR codes are always blurred if masking is active, even if unchecked
        is_qr = finding.get("type") == "QR Code"
        if not is_qr and idx not in selected_set:
            continue

        x, y, w, h = finding["bbox"]
        # Clamp coordinates to image boundaries
        x = max(0, min(x, img_width - 1))
        y = max(0, min(y, img_height - 1))
        w = max(1, min(w, img_width - x))
        h = max(1, min(h, img_height - y))

        ftype = finding.get("type", "")

        # Always blur or black out QR codes
        if is_qr:
            # Crop, blur heavily, paste back
            box = (x, y, x + w, y + h)
            sub = result_img.crop(box)
            # Blur with large radius
            blurred_sub = sub.filter(ImageFilter.GaussianBlur(radius=max(15, min(w, h) // 4)))
            result_img.paste(blurred_sub, box)
            # Draw subtle border and warning label
            draw.rectangle(box, outline=(220, 53, 69), width=2)
            continue

        # 1. Blur Mode
        if mode == "blur":
            box = (x, y, x + w, y + h)
            sub = result_img.crop(box)
            blur_radius = max(12, int(h * 0.75))
            blurred_sub = sub.filter(ImageFilter.GaussianBlur(radius=blur_radius))
            result_img.paste(blurred_sub, box)

        # 2. Partial Mode
        elif mode == "partial":
            if ftype == "Aadhaar Number":
                # Official masked Aadhaar: Mask first 8 digits + spaces (~67% of width), show last 4 digits
                mask_w = int(w * 0.67)
                mask_box = (x, y, x + mask_w, y + h)
                draw.rectangle(mask_box, fill=(20, 20, 20))
                # Add "XXXX XXXX" text watermark inside black box if space permits
                if mask_w > 50 and h > 14:
                    font = get_default_font(size=max(10, min(16, int(h * 0.6))))
                    draw.text((x + 4, y + int(h * 0.2)), "XXXX XXXX", fill=(200, 200, 200), font=font)

            elif ftype == "Payment Card Number":
                # Mask first 12 digits (~72% of width), show last 4 digits
                mask_w = int(w * 0.72)
                mask_box = (x, y, x + mask_w, y + h)
                draw.rectangle(mask_box, fill=(20, 20, 20))
                if mask_w > 60 and h > 14:
                    font = get_default_font(size=max(10, min(16, int(h * 0.6))))
                    draw.text((x + 4, y + int(h * 0.2)), "XXXX XXXX XXXX", fill=(200, 200, 200), font=font)

            elif ftype == "Mobile Phone Number":
                # Mask first 6 digits (~60% of width), show last 4 digits
                mask_w = int(w * 0.60)
                mask_box = (x, y, x + mask_w, y + h)
                draw.rectangle(mask_box, fill=(20, 20, 20))

            elif ftype == "PAN Number":
                # Mask first 5 characters (status and surname initial), leaving last 4 digits + letter
                mask_w = int(w * 0.55)
                mask_box = (x, y, x + mask_w, y + h)
                draw.rectangle(mask_box, fill=(20, 20, 20))

            elif ftype == "Date of Birth":
                # Mask Day and Month (~55% of width), show Year
                mask_w = int(w * 0.55)
                mask_box = (x, y, x + mask_w, y + h)
                draw.rectangle(mask_box, fill=(20, 20, 20))

            elif ftype == "Bank Account Number":
                # Mask all but last 4 digits
                mask_w = int(w * 0.70)
                mask_box = (x, y, x + mask_w, y + h)
                draw.rectangle(mask_box, fill=(20, 20, 20))

            else:
                # Default full mask for low-confidence or other elements
                mask_box = (x, y, x + w, y + h)
                draw.rectangle(mask_box, fill=(20, 20, 20))

        # 3. Full Mode (Solid Blackout)
        else:
            mask_box = (x, y, x + w, y + h)
            draw.rectangle(mask_box, fill=(15, 15, 15))

    return result_img


def add_watermark(
    image_input: Union[Image.Image, np.ndarray, str],
    purpose_text: str = "",
) -> Image.Image:
    """
    Applies diagonal, semi-transparent purpose watermarking across the document.
    Example: "Shared for: Axis Bank KYC | 22-Nov-2026"

    Renders multiple repeating diagonal lines across the image canvas so the document
    cannot be cropped or reused for unauthorized KYC or third-party loans.
    """
    pil_img, _ = to_pil_and_cv2(image_input)
    clean_text = purpose_text.strip()
    if not clean_text:
        return pil_img

    # Ensure date is included if not present
    today_str = datetime.now().strftime("%d-%b-%Y")
    if today_str not in clean_text:
        watermark_str = f"Shared for: {clean_text} | {today_str}"
    else:
        watermark_str = f"Shared for: {clean_text}"

    width, height = pil_img.size

    # Create an RGBA overlay for smooth transparency
    overlay = Image.new("RGBA", (width, height), (255, 255, 255, 0))

    # Dynamic font sizing based on document dimensions
    font_size = max(18, min(42, int(width / 26)))
    font = get_default_font(size=font_size)

    # We create a rotated text stamp on a separate transparent tile
    # Compute tile dimensions to fit diagonal text
    tile_w = int(width * 0.9)
    tile_h = int(height * 0.3)
    text_canvas = Image.new("RGBA", (tile_w, tile_h), (255, 255, 255, 0))
    t_draw = ImageDraw.Draw(text_canvas)

    # High-contrast semi-transparent red-slate watermark color (R, G, B, Alpha)
    watermark_color = (210, 40, 40, 75)

    # Measure text bbox
    try:
        t_bbox = t_draw.textbbox((0, 0), watermark_str, font=font)
        text_w = t_bbox[2] - t_bbox[0]
        text_h = t_bbox[3] - t_bbox[1]
    except Exception:
        text_w = len(watermark_str) * (font_size * 0.6)
        text_h = font_size

    # Center text in tile
    tx = max(10, (tile_w - text_w) // 2)
    ty = max(10, (tile_h - text_h) // 2)

    # Draw protective banner border & text
    t_draw.rectangle(
        (tx - 15, ty - 8, tx + text_w + 15, ty + text_h + 8),
        outline=(210, 40, 40, 90),
        width=2,
    )
    t_draw.text((tx, ty), watermark_str, fill=watermark_color, font=font)

    # Rotate tile by -28 degrees
    rotated_tile = text_canvas.rotate(28, expand=True, resample=Image.BICUBIC)
    rot_w, rot_h = rotated_tile.size

    # Paste repeating rotated tiles across image grid
    y_step = max(int(height * 0.35), rot_h // 2)
    x_step = max(int(width * 0.6), rot_w // 2)

    for y in range(-rot_h // 3, height, y_step):
        for x in range(-rot_w // 3, width, x_step):
            overlay.paste(rotated_tile, (x, y), rotated_tile)

    # Composite overlay onto original image
    base_rgba = pil_img.convert("RGBA")
    combined = Image.alpha_composite(base_rgba, overlay)

    return combined.convert("RGB")
