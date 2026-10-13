"""OpenAI vision extraction of CPR certificate fields."""
import base64
import json
from datetime import date

from dateutil import parser as dateparser

from app.config import get_settings

SYSTEM_PROMPT = """You are a document examiner verifying CPR / First Aid / BLS certificates for a security company.
Read the certificate image carefully and return ONLY the requested JSON.
- Dates must be ISO format YYYY-MM-DD. If the certificate shows "Recommended renewal" or "Valid until", that is the expiry date.
- Use null for anything not visible. Do not guess dates.
- In visual_tamper_signs, list concrete visual evidence of editing: mismatched fonts or font sizes in names/dates,
  misaligned text baselines, inconsistent background/texture or compression around text, pixelation or blur patches,
  digits that look pasted, missing/odd logos or seals, inconsistent spelling of the issuing organisation.
  Return an empty list if the document looks genuine. Be specific and conservative.
- is_cpr_certificate: false if this is not a CPR/BLS/First-Aid certificate at all."""

RESPONSE_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "is_cpr_certificate": {"type": "boolean"},
        "holder_name": {"type": ["string", "null"]},
        "issuer": {"type": ["string", "null"]},
        "cert_id": {"type": ["string", "null"]},
        "course_type": {"type": ["string", "null"]},
        "issue_date": {"type": ["string", "null"]},
        "expiry_date": {"type": ["string", "null"]},
        "visual_tamper_signs": {"type": "array", "items": {"type": "string"}},
        "tamper_likelihood": {"type": "string", "enum": ["none", "low", "medium", "high"]},
        "confidence": {"type": "number"},
    },
    "required": [
        "is_cpr_certificate", "holder_name", "issuer", "cert_id", "course_type",
        "issue_date", "expiry_date", "visual_tamper_signs", "tamper_likelihood", "confidence",
    ],
}


class AIUnavailable(Exception):
    pass


def _client():
    settings = get_settings()
    if not settings.openai_api_key:
        raise AIUnavailable("OPENAI_API_KEY is not set")
    from openai import OpenAI

    return OpenAI(api_key=settings.openai_api_key)


def parse_date(value) -> date | None:
    if not value:
        return None
    try:
        return dateparser.parse(str(value)).date()
    except (ValueError, OverflowError, TypeError):
        return None


def extract_fields(image_png_or_jpeg: bytes, mime: str, pdf_text: str | None = None, client=None) -> dict:
    """Call OpenAI vision. Returns the parsed JSON dict (dates still as strings)."""
    client = client or _client()
    settings = get_settings()
    b64 = base64.b64encode(image_png_or_jpeg).decode()
    user_content = [
        {"type": "text", "text": "Extract the certificate details and assess for tampering."},
        {"type": "image_url", "image_url": {"url": f"data:{mime};base64,{b64}", "detail": "high"}},
    ]
    if pdf_text:
        user_content.append({"type": "text", "text": f"Embedded PDF text layer (may help, may differ from image):\n{pdf_text}"})

    resp = client.chat.completions.create(
        model=settings.openai_model,
        temperature=0,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ],
        response_format={
            "type": "json_schema",
            "json_schema": {"name": "cpr_certificate", "strict": True, "schema": RESPONSE_SCHEMA},
        },
    )
    return json.loads(resp.choices[0].message.content)
