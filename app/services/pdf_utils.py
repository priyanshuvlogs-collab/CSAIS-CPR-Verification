"""PDF helpers: render a preview image and read metadata."""
import pymupdf


def render_first_page_png(data: bytes, zoom: float = 2.0) -> bytes:
    with pymupdf.open(stream=data, filetype="pdf") as doc:
        page = doc[0]
        pix = page.get_pixmap(matrix=pymupdf.Matrix(zoom, zoom))
        return pix.tobytes("png")


def pdf_metadata(data: bytes) -> dict:
    with pymupdf.open(stream=data, filetype="pdf") as doc:
        meta = dict(doc.metadata or {})
        meta["page_count"] = doc.page_count
    meta["eof_markers"] = data.count(b"%%EOF")
    return meta
