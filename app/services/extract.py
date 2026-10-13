"""Claude (Anthropic API) extraction of CPR certificate fields."""
import base64
import json
from datetime import date

from dateutil import parser as dateparser

from app.config import get_settings

SYSTEM_PROMPT = """You are a document examiner verifying CPR / First Aid / BLS certificates for a security company.
Read the certificate carefully and return the requested JSON.
- Dates must be ISO format YYYY-MM-DD. If the certificate shows "Recommended renewal" or "Valid until", that is the expiry date.
- Use null for anything not visible. Do not guess dates.
- In visual_tamper_signs, list concrete visual evidence of editing: mismatched fonts or font sizes in names/dates,
  misaligned text baselines, inconsistent background/texture or compression around text, pixelation or blur patches,
  digits that look pasted, missing/odd logos or seals, inconsistent spelling of the issuing organisation.
  Return an empty list if the document looks genuine. Be specific and conservative.
- is_cpr_certificate: false if this is not a CPR/BLS/First-Aid certificate at all."""

_NULLABLE_STR = {"anyOf": [{"type": "string"}, {"type": "null"}]}

RESPONSE_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "is_cpr_certificate": {"type": "boolean"},
        "holder_name": _NULLABLE_STR,
        "issuer": _NULLABLE_STR,
        "cert_id": _NULLABLE_STR,
        "course_type": _NULLABLE_STR,
        "issue_date": _NULLABLE_STR,
        "expiry_date": _NULLABLE_STR,
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


class AIRefused(Exception):
    pass


def _client():
    settings = get_settings()
    if not settings.anthropic_api_key:
        raise AIUnavailable("ANTHROPIC_API_KEY is not set")
    import anthropic

    return anthropic.Anthropic(api_key=settings.anthropic_api_key)


def parse_date(value) -> date | None:
    if not value:
        return None
    try:
        return dateparser.parse(str(value)).date()
    except (ValueError, OverflowError, TypeError):
        return None


def _file_block(data: bytes, mime: str) -> dict:
    b64 = base64.standard_b64encode(data).decode()
    if mime == "application/pdf":
        return {"type": "document", "source": {"type": "base64", "media_type": "application/pdf", "data": b64}}
    return {"type": "image", "source": {"type": "base64", "media_type": mime, "data": b64}}


def extract_fields(data: bytes, mime: str, client=None) -> dict:
    """Send the certificate (image or PDF) to Claude. Returns the parsed JSON dict (dates still as strings)."""
    client = client or _client()
    settings = get_settings()
    resp = client.beta.messages.create(
        model=settings.anthropic_model,
        max_tokens=16000,
        system=SYSTEM_PROMPT,
        messages=[{
            "role": "user",
            "content": [
                _file_block(data, mime),
                {"type": "text", "text": "Extract the certificate details and assess it for tampering."},
            ],
        }],
        output_config={
            "effort": "high",
            "format": {"type": "json_schema", "schema": RESPONSE_SCHEMA},
        },
        # If a safety classifier declines, retry on a fallback model chosen by the API.
        betas=["server-side-fallback-2026-07-01"],
        fallbacks="default",
    )
    if resp.stop_reason == "refusal":
        detail = getattr(resp.stop_details, "explanation", None) if resp.stop_details else None
        raise AIRefused(f"Claude declined to read this document{': ' + detail if detail else ''}")
    text = next((b.text for b in resp.content if b.type == "text"), None)
    if text is None:
        raise ValueError(f"No JSON in response (stop_reason={resp.stop_reason})")
    return json.loads(text)
