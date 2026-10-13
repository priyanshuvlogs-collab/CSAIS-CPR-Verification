"""PDF helpers: render to image, extract text and metadata."""
import pymupdf


def render_first_page_png(data: bytes, zoom: float = 2.0) -> bytes:
    with pymupdf.open(stream=data, filetype="pdf") as doc:
        page = doc[0]
        pix = page.get_pixmap(matrix=pymupdf.Matrix(zoom, zoom))
        return pix.tobytes("png")


def extract_text(data: bytes, max_chars: int = 6000) -> str:
    with pymupdf.open(stream=data, filetype="pdf") as doc:
        text = "\n".join(page.get_text() for page in doc)
    return text[:max_chars]


def pdf_metadata(data: bytes) -> dict:
    with pymupdf.open(stream=data, filetype="pdf") as doc:
        meta = dict(doc.metadata or {})
        meta["page_count"] = doc.page_count
    meta["eof_markers"] = data.count(b"%%EOF")
    return meta
