"""Multimodal input adapters: OCR and QR (contract section 10).

Both adapters degrade gracefully. If the underlying library or binary is not
installed the call does NOT fail — it returns `available=False` with a clear
reason, the API reports it in `degraded_checks`, and the user can type or
paste the text instead. Nothing is ever invented to fill a gap.
"""
from __future__ import annotations

import io
import os
import shutil
import unicodedata
from dataclasses import dataclass, field
from typing import List, Optional

MAX_IMAGE_BYTES = int(os.getenv("REDFLAG_MAX_UPLOAD_BYTES", str(8 * 1024 * 1024)))
ALLOWED_IMAGE_TYPES = {"image/png", "image/jpeg", "image/jpg", "image/webp", "image/bmp"}


@dataclass
class OcrResult:
    available: bool
    text: str = ""
    mean_confidence: float = 0.0
    word_count: int = 0
    languages_used: List[str] = field(default_factory=list)
    boxes: List[dict] = field(default_factory=list)
    reason: Optional[str] = None
    warning: str = ("OCR may be wrong. Review and edit the extracted text before "
                    "relying on the analysis.")

    def to_dict(self) -> dict:
        return {
            "available": self.available, "text": self.text,
            "mean_confidence": round(self.mean_confidence, 1),
            "word_count": self.word_count,
            "languages_used": self.languages_used,
            "boxes": self.boxes[:80],
            "reason": self.reason, "warning": self.warning,
        }


@dataclass
class QrResult:
    available: bool
    payloads: List[dict] = field(default_factory=list)
    reason: Optional[str] = None
    note: str = ("The destination was decoded locally and is shown to you BEFORE "
                 "anything is opened. RedFlag never follows a QR target automatically.")

    def to_dict(self) -> dict:
        return {"available": self.available, "payloads": self.payloads,
                "reason": self.reason, "note": self.note}


def _tesseract_langs() -> List[str]:
    try:
        import pytesseract
        langs = set(pytesseract.get_languages(config=""))
    except Exception:
        return ["eng"]
    chosen = [l for l in ("eng", "tam") if l in langs]
    return chosen or ["eng"]


def run_ocr(image_bytes: bytes) -> OcrResult:
    """Language-aware OCR (English + Tamil when the traineddata is present)."""
    if shutil.which("tesseract") is None:
        return OcrResult(available=False, reason=(
            "Tesseract OCR binary not found on this host. Install "
            "`tesseract-ocr` (and `tesseract-ocr-tam` for Tamil), or paste the "
            "message text manually."))
    try:
        import pytesseract
        from PIL import Image, ImageOps
    except Exception as exc:                                   # pragma: no cover
        return OcrResult(available=False, reason=f"OCR libraries unavailable: {exc}")

    try:
        img = Image.open(io.BytesIO(image_bytes))
        img = ImageOps.exif_transpose(img).convert("L")
        if max(img.size) < 1000:                               # upscale small screenshots
            scale = 1000 / max(img.size)
            img = img.resize((int(img.width * scale), int(img.height * scale)))
        img = ImageOps.autocontrast(img)

        langs = _tesseract_langs()
        data = pytesseract.image_to_data(
            img, lang="+".join(langs),
            output_type=pytesseract.Output.DICT, config="--oem 3 --psm 6",
        )
    except Exception as exc:
        return OcrResult(available=False, reason=f"OCR failed on this image: {exc}")

    words, confs, boxes = [], [], []
    lines: dict = {}
    for i, raw in enumerate(data.get("text", [])):
        w = (raw or "").strip()
        if not w:
            continue
        try:
            conf = float(data["conf"][i])
        except (ValueError, TypeError):
            conf = -1.0
        if conf < 0:
            continue
        words.append(w)
        confs.append(conf)
        key = (data["block_num"][i], data["par_num"][i], data["line_num"][i])
        lines.setdefault(key, []).append(w)
        boxes.append({
            "text": w, "conf": round(conf, 1),
            "x": int(data["left"][i]), "y": int(data["top"][i]),
            "w": int(data["width"][i]), "h": int(data["height"][i]),
        })

    text = "\n".join(" ".join(v) for _, v in sorted(lines.items()))
    # Preserve URLs/numbers/punctuation; only normalize Unicode form.
    text = unicodedata.normalize("NFC", text).strip()

    if not text:
        return OcrResult(available=True, text="", mean_confidence=0.0,
                         languages_used=_tesseract_langs(),
                         reason="No readable text was found in this image.")

    return OcrResult(
        available=True, text=text,
        mean_confidence=sum(confs) / len(confs) if confs else 0.0,
        word_count=len(words), languages_used=_tesseract_langs(), boxes=boxes,
    )


def decode_qr(image_bytes: bytes) -> QrResult:
    """Decode QR codes locally. The destination is returned, never opened."""
    payloads: List[dict] = []
    tried: List[str] = []

    try:
        from pyzbar.pyzbar import decode as zbar_decode    # type: ignore
        from PIL import Image
        img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        for sym in zbar_decode(img):
            payloads.append({
                "data": sym.data.decode("utf-8", errors="replace"),
                "format": sym.type, "decoder": "pyzbar",
            })
    except Exception as exc:
        tried.append(f"pyzbar: {exc}")

    if not payloads:
        try:
            import cv2
            import numpy as np
            arr = np.frombuffer(image_bytes, dtype=np.uint8)
            img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
            if img is not None:
                det = cv2.QRCodeDetector()
                ok, decoded, _pts, _ = det.detectAndDecodeMulti(img)
                if ok:
                    for d in decoded:
                        if d:
                            payloads.append({"data": d, "format": "QRCODE",
                                             "decoder": "opencv"})
        except Exception as exc:
            tried.append(f"opencv: {exc}")

    if payloads:
        for p in payloads:
            d = p["data"]
            p["looks_like_url"] = d.lower().startswith(("http://", "https://", "www."))
            p["looks_like_upi"] = d.lower().startswith("upi://")
        return QrResult(available=True, payloads=payloads)

    return QrResult(available=False, payloads=[], reason=(
        "No QR code could be decoded from this image. "
        + ("Decoder notes: " + "; ".join(tried) if tried else
           "Install `libzbar0` + `pyzbar`, or paste the link manually.")))


def validate_upload(content_type: Optional[str], size: int) -> Optional[str]:
    """Upload hardening (contract section 19). Returns an error string or None."""
    if size <= 0:
        return "Empty file."
    if size > MAX_IMAGE_BYTES:
        return f"File too large. Limit is {MAX_IMAGE_BYTES // (1024 * 1024)} MB."
    if (content_type or "").split(";")[0].strip().lower() not in ALLOWED_IMAGE_TYPES:
        return ("Unsupported file type. Allowed: "
                + ", ".join(sorted(ALLOWED_IMAGE_TYPES)) + ".")
    return None


def sniff_is_image(data: bytes) -> bool:
    """Magic-byte check so a renamed executable cannot slip through."""
    sigs = (b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"BM", b"GIF87a", b"GIF89a")
    if data.startswith(sigs):
        return True
    return len(data) > 12 and data[0:4] == b"RIFF" and data[8:12] == b"WEBP"
