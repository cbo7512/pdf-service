"""
DocFlow PDF Service
- PDF page rendering (PNG)
- Text extraction with positions
- Text replacement via redaction + re-insert
Uses PyMuPDF (fitz) for all PDF operations.
"""
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
import fitz  # PyMuPDF
import uuid, os, time, smtplib, ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from pydantic import BaseModel
from typing import List, Optional

app = FastAPI(title="DocFlow PDF Service", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

TEMP_DIR = Path("/tmp/pdf_sessions")
TEMP_DIR.mkdir(exist_ok=True, parents=True)

# In-memory session store: {session_id: {path, pages, filename, created_at}}
sessions: dict = {}


def cleanup_old_sessions():
    """Remove sessions older than 2 hours to free disk space."""
    now = time.time()
    stale = [sid for sid, s in sessions.items() if now - s.get("created_at", 0) > 7200]
    for sid in stale:
        path = sessions[sid].get("path", "")
        if path and os.path.exists(path):
            os.remove(path)
        del sessions[sid]


def sample_bg_color(page: fitz.Page, x0: float, y0: float, x1: float, y1: float):
    """
    Sample the background colour just ABOVE the text line.
    Returns (r, g, b) as floats 0-1.  Defaults to white.
    """
    try:
        sy0 = max(0, y0 - 4)
        sy1 = max(sy0 + 0.5, y0)
        clip = fitz.Rect(x0, sy0, x1, sy1)
        if clip.is_empty or clip.width < 1:
            return (1.0, 1.0, 1.0)
        pix = page.get_pixmap(matrix=fitz.Matrix(1, 1), clip=clip, alpha=False)
        if pix.width > 0 and pix.height > 0:
            px = pix.pixel(pix.width // 2, 0)
            r, g, b = px[0] / 255.0, px[1] / 255.0, px[2] / 255.0
            if r > 0.94 and g > 0.94 and b > 0.94:
                return (1.0, 1.0, 1.0)
            return (r, g, b)
    except Exception:
        pass
    return (1.0, 1.0, 1.0)


# ─── UPLOAD ────────────────────────────────────────────────────────────────────

@app.post("/upload")
async def upload_pdf(file: UploadFile = File(...)):
    """Accept a PDF upload, return session_id + page count."""
    cleanup_old_sessions()
    if not file.filename.lower().endswith(".pdf"):
        raise HTTPException(400, "Sadece PDF dosyaları kabul edilir")

    session_id = str(uuid.uuid4())
    path = TEMP_DIR / f"{session_id}.pdf"

    content = await file.read()
    path.write_bytes(content)

    try:
        doc = fitz.open(str(path))
        page_count = doc.page_count
        doc.close()
    except Exception as e:
        path.unlink(missing_ok=True)
        raise HTTPException(400, f"PDF açılamadı: {e}")

    sessions[session_id] = {
        "path": str(path),
        "pages": page_count,
        "filename": file.filename,
        "created_at": time.time(),
    }
    return {"session_id": session_id, "pages": page_count, "filename": file.filename}


# ─── RENDER PAGE ───────────────────────────────────────────────────────────────

@app.get("/page/{session_id}/{page_num}")
async def get_page_image(session_id: str, page_num: int, zoom: float = 1.5):
    """Render a PDF page to PNG at the requested zoom level."""
    if session_id not in sessions:
        raise HTTPException(404, "Oturum bulunamadı")
    s = sessions[session_id]
    try:
        doc = fitz.open(s["path"])
        if not (1 <= page_num <= doc.page_count):
            doc.close()
            raise HTTPException(400, f"Sayfa 1-{doc.page_count} arasında olmalı")
        page = doc[page_num - 1]
        pix = page.get_pixmap(matrix=fitz.Matrix(zoom, zoom), alpha=False)
        png = pix.tobytes("png")
        doc.close()
        return Response(content=png, media_type="image/png")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Render hatası: {e}")


# ─── TEXT ITEMS ────────────────────────────────────────────────────────────────

@app.get("/text/{session_id}/{page_num}")
async def get_page_text(session_id: str, page_num: int, zoom: float = 1.5):
    """Return text spans with scaled + original coordinates."""
    if session_id not in sessions:
        raise HTTPException(404, "Oturum bulunamadı")
    s = sessions[session_id]
    try:
        doc = fitz.open(s["path"])
        if not (1 <= page_num <= doc.page_count):
            doc.close()
            raise HTTPException(400, f"Sayfa 1-{doc.page_count} arasında olmalı")
        page = doc[page_num - 1]

        text_dict = page.get_text(
            "dict",
            flags=fitz.TEXT_PRESERVE_WHITESPACE | fitz.TEXT_PRESERVE_LIGATURES,
        )

        items = []
        item_id = 0
        SYMBOL_RANGES = [
            (0x2000, 0x2BFF),   # arrows, symbols, dingbats
            (0xE000, 0xF8FF),   # private use (icon fonts)
            (0x1F000, 0x1FFFF), # emoji
        ]

        for block in text_dict.get("blocks", []):
            if block.get("type") != 0:
                continue
            for line in block.get("lines", []):
                for span in line.get("spans", []):
                    text = span.get("text", "")
                    if not text or not text.strip():
                        continue
                    # Skip pure symbol characters
                    stripped = text.strip()
                    if stripped and len(stripped) <= 2:
                        code = ord(stripped[0])
                        if any(lo <= code <= hi for lo, hi in SYMBOL_RANGES):
                            continue

                    x0, y0, x1, y1 = span.get("bbox", [0, 0, 0, 0])

                    color_val = span.get("color", 0)
                    if isinstance(color_val, int):
                        r = (color_val >> 16) & 0xFF
                        g = (color_val >> 8) & 0xFF
                        b = color_val & 0xFF
                    else:
                        r = g = b = 0
                    color_hex = f"#{r:02x}{g:02x}{b:02x}"

                    fflags = span.get("flags", 0)
                    is_bold   = bool(fflags & (1 << 4))
                    is_italic = bool(fflags & (1 << 1))
                    font_size = span.get("size", 12)

                    items.append({
                        "id":   str(item_id),
                        "text": text,
                        # Scaled coords — for overlay positioning in browser
                        "x":      round(x0 * zoom, 2),
                        "y":      round(y0 * zoom, 2),
                        "width":  round((x1 - x0) * zoom, 2),
                        "height": round((y1 - y0) * zoom, 2),
                        # Original coords — for PDF editing (unscaled)
                        "ox": x0, "oy": y0, "ox1": x1, "oy1": y1,
                        "font":         span.get("font", "Helvetica"),
                        "size":         round(font_size, 2),
                        "display_size": round(font_size * zoom, 2),
                        "bold":   is_bold,
                        "italic": is_italic,
                        "color":  color_hex,
                    })
                    item_id += 1

        page_rect = page.rect
        doc.close()
        return {
            "page":   page_num,
            "width":  round(page_rect.width  * zoom),
            "height": round(page_rect.height * zoom),
            "zoom":   zoom,
            "items":  items,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Metin okuma hatası: {e}")


# ─── APPLY EDITS & DOWNLOAD ────────────────────────────────────────────────────

class EditItem(BaseModel):
    id:       str
    page:     int
    ox:       float   # original bbox x0 (unscaled)
    oy:       float   # original bbox y0
    ox1:      float   # original bbox x1
    oy1:      float   # original bbox y1
    original: str
    new_text: str
    font:     str   = "Helvetica"
    size:     float = 12.0
    bold:     bool  = False
    italic:   bool  = False
    color:    str   = "#000000"


class ApplyEditsRequest(BaseModel):
    edits: List[EditItem]


@app.post("/apply/{session_id}")
async def apply_edits(session_id: str, request: ApplyEditsRequest):
    """
    Apply text edits and return the modified PDF.
    Strategy per changed span:
      1. Add redaction annotation with sampled background fill
      2. apply_redactions() — removes original content
      3. insert_text() — writes replacement
    """
    if session_id not in sessions:
        raise HTTPException(404, "Oturum bulunamadı")
    s = sessions[session_id]

    try:
        doc = fitz.open(s["path"])

        # Group edits by page index (0-based)
        edits_by_page: dict[int, list[EditItem]] = {}
        for edit in request.edits:
            if edit.original != edit.new_text:
                edits_by_page.setdefault(edit.page - 1, []).append(edit)

        for page_idx, page_edits in edits_by_page.items():
            if not (0 <= page_idx < doc.page_count):
                continue
            page = doc[page_idx]

            # ── Pass 1: redact original text ──
            for edit in page_edits:
                rect = fitz.Rect(edit.ox, edit.oy, edit.ox1, edit.oy1).extend(0.5)
                bg   = sample_bg_color(page, edit.ox, edit.oy, edit.ox1, edit.oy1)
                page.add_redact_annot(rect, fill=bg)
            page.apply_redactions(images=fitz.PDF_REDACT_IMAGE_NONE)

            # ── Pass 2: insert new text ──
            for edit in page_edits:
                if not edit.new_text:
                    continue  # empty = intentional deletion
                hex_c = edit.color.lstrip("#")
                try:
                    tc = (int(hex_c[0:2], 16) / 255,
                          int(hex_c[2:4], 16) / 255,
                          int(hex_c[4:6], 16) / 255)
                except Exception:
                    tc = (0.0, 0.0, 0.0)

                fontname = "hebo" if edit.bold else ("heho" if edit.italic else "helv")
                # Baseline = bottom of bbox
                pt = fitz.Point(edit.ox, edit.oy1 - 0.5)
                page.insert_text(pt, edit.new_text,
                                 fontname=fontname,
                                 fontsize=edit.size,
                                 color=tc,
                                 render_mode=0)

        pdf_bytes = doc.tobytes(garbage=4, deflate=True)
        doc.close()

        filename = "edited_" + s["filename"]
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Length": str(len(pdf_bytes)),
            },
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"PDF düzenleme hatası: {e}")


# ─── EMAIL SEND ────────────────────────────────────────────────────────────────

class SendEmailRequest(BaseModel):
    smtp_host: str
    smtp_port: int = 587
    smtp_sec: str = "tls"   # "tls" = STARTTLS, "ssl" = SSL/TLS, "none" = plain
    smtp_user: str
    smtp_pw: str
    smtp_from: str
    to: str
    subject: str
    html_body: str


@app.post("/smtp/send")
async def send_email(req: SendEmailRequest):
    """Send an email via the configured SMTP server."""
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = req.subject
        msg["From"]    = req.smtp_from
        msg["To"]      = req.to
        msg.attach(MIMEText(req.html_body, "html", "utf-8"))

        if req.smtp_sec == "ssl":
            ctx = ssl.create_default_context()
            with smtplib.SMTP_SSL(req.smtp_host, req.smtp_port, context=ctx) as s:
                s.login(req.smtp_user, req.smtp_pw)
                s.sendmail(req.smtp_from, [req.to], msg.as_string())
        else:
            with smtplib.SMTP(req.smtp_host, req.smtp_port) as s:
                s.ehlo()
                if req.smtp_sec == "tls":
                    ctx = ssl.create_default_context()
                    s.starttls(context=ctx)
                    s.ehlo()
                s.login(req.smtp_user, req.smtp_pw)
                s.sendmail(req.smtp_from, [req.to], msg.as_string())

        return {"ok": True}
    except Exception as e:
        raise HTTPException(500, f"E-posta gönderilemedi: {e}")


# ─── WATERMARK ─────────────────────────────────────────────────────────────────

@app.post("/watermark")
async def watermark_pdf(
    file: UploadFile = File(...),
    text: str = Form("TASLAK"),
    opacity: float = Form(0.15),
    color: str = Form("#DC2626"),
    fontsize: int = Form(56),
    rotate: int = Form(-35),
):
    """Apply a diagonal repeating text watermark to a PDF using PyMuPDF."""
    content = await file.read()
    try:
        doc = fitz.open(stream=content, filetype="pdf")

        # Parse hex color → (r, g, b) floats 0-1
        hex_c = color.lstrip("#")
        try:
            rc = int(hex_c[0:2], 16) / 255
            gc = int(hex_c[2:4], 16) / 255
            bc = int(hex_c[4:6], 16) / 255
        except Exception:
            rc, gc, bc = 0.86, 0.15, 0.15

        for page in doc:
            pw = page.rect.width
            ph = page.rect.height

            # Diagonal grid: bottom-left → top-right sweep
            # 3 columns × 4 rows of stamps
            cols, rows = 3, 4
            for row in range(rows):
                for col in range(cols):
                    x = (col + 0.3) * pw / cols
                    y = (row + 0.6) * ph / rows
                    # Slight offset alternation per row for better coverage
                    if row % 2 == 1:
                        x += pw / (cols * 2)
                    try:
                        page.insert_text(
                            fitz.Point(x, y),
                            text,
                            fontsize=fontsize,
                            fontname="hebo",      # Helvetica Bold
                            color=(rc, gc, bc),
                            fill_opacity=opacity,
                            rotate=rotate,
                            overlay=True,
                        )
                    except Exception:
                        pass  # skip if point is outside page

        pdf_bytes = doc.tobytes(garbage=4, deflate=True)
        doc.close()
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="watermarked.pdf"',
                "Content-Length": str(len(pdf_bytes)),
            },
        )
    except Exception as e:
        raise HTTPException(500, f"Watermark hatası: {str(e)}")


# ─── CLEANUP & HEALTH ──────────────────────────────────────────────────────────

@app.delete("/session/{session_id}")
async def delete_session(session_id: str):
    if session_id in sessions:
        path = sessions[session_id].get("path", "")
        if path and os.path.exists(path):
            os.remove(path)
        del sessions[session_id]
    return {"ok": True}


@app.get("/health")
async def health():
    return {
        "status":          "ok",
        "pymupdf":         fitz.__version__,
        "active_sessions": len(sessions),
    }
