# src/mini_zap/proxy/passive_scan.py
from typing import Dict, Any, Optional, List
from ..utils.logging import get_logger
from ..utils.http import safe_get
from requests.exceptions import ReadTimeout, RequestException, ConnectionError as ReqConnError

logger = get_logger(__name__)

DEFAULT_SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
]

SENSITIVE_STRINGS = [
    ".env", ".git", "password", "secret", "aws_access_key_id", "begin rsa private key"
]

def _header_missing(headers: Dict[str, str], h: str) -> bool:
    if not headers:
        return True
    lower_keys = {k.lower() for k in headers.keys()}
    return h.lower() not in lower_keys

def analyze_response_from_session(url: str, session, rules: Optional[dict] = None) -> Dict[str, Any]:
    """
    GET the URL via provided session (safe_get), analyze headers and body for simple issues.
    Returns a dict summarizing findings. Network errors produce findings rather than exceptions.
    """
    try:
        r = safe_get(session, url)
    except Exception as e:
        # safe_get should swallow most exceptions; keep here just in case
        logger.debug(f"safe_get raised unexpected: {e}", exc_info=True)
        r = None

    findings: List[Dict[str, str]] = []

    if r is None:
        # Could be timeout, connection error, or other request exception logged in safe_get
        findings.append({
            "type": "connection_error",
            "detail": "Connection error (refused/unreachable or timed out)",
            "severity": "low",
            "evidence": "No response or request error occurred (timeout/connection)."
        })
        return {
            "url": url,
            "status_code": None,
            "headers": {},
            "findings": findings
        }

    # headers check
    try:
        headers = {k: v for k, v in r.headers.items()}
    except Exception:
        headers = {}

    for h in DEFAULT_SECURITY_HEADERS:
        if _header_missing(headers, h):
            findings.append({
                "type": "missing_header",
                "header": h,
                "severity": "medium" if h in ("strict-transport-security", "content-security-policy") else "low",
                "detail": f"Header {h} is missing"
            })

    # sensitive content
    try:
        body_text = (r.text or "")
    except Exception:
        body_text = ""

    body_lower = body_text.lower()
    for s in SENSITIVE_STRINGS:
        if s in body_lower:
            findings.append({
                "type": "sensitive_data_exposure",
                "pattern": s,
                "severity": "high" if ".git" in s or "private key" in s else "medium",
                "detail": f"Found pattern '{s}' in response body"
            })

    return {
        "url": url,
        "status_code": r.status_code,
        "headers": dict(headers),
        "findings": findings
    }


# For mitmproxy integration
def analyze_response_flow(flow) -> Dict[str, Any]:
    headers = {k:v for k,v in flow.response.headers.items()}
    findings = []
    lower_keys = {k.lower() for k in headers.keys()}
    for h in DEFAULT_SECURITY_HEADERS:
        if h.lower() not in lower_keys:
            findings.append({"type":"missing_header","header":h,"detail":f"Missing {h}"})
    return {"url": flow.request.url, "status_code": flow.response.status_code, "headers": headers, "findings": findings}
