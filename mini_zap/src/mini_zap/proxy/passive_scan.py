# src/mini_zap/proxy/passive_scan.py
from typing import Dict, Any, Optional, List
from ..utils.logging import get_logger
from ..utils.http import get as session_get

logger = get_logger(__name__)

DEFAULT_SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
]

SENSITIVE_STRINGS = [
    ".env", ".git", "password", "secret", "aws_access_key_id", "BEGIN RSA PRIVATE KEY"
]

def _header_missing(headers: Dict[str, str], h: str) -> bool:
    lower_keys = {k.lower() for k in headers.keys()}
    return h.lower() not in lower_keys

def analyze_response_from_session(url: str, session, rules: Optional[dict] = None) -> Dict[str, Any]:
    """
    GET the URL via provided session, analyze headers and body for simple issues.
    Returns a dict summarizing findings.
    """
    r = session_get(session, url)
    findings: List[Dict[str, str]] = []

    # headers check
    for h in DEFAULT_SECURITY_HEADERS:
        if _header_missing(r.headers, h):
            findings.append({
                "type": "missing_header",
                "header": h,
                "severity": "medium" if h in ("strict-transport-security","content-security-policy") else "low",
                "detail": f"Header {h} is missing"
            })

    # sensitive content
    body_lower = (r.text or "").lower()
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
        "headers": dict(r.headers),
        "findings": findings
    }

# For mitmproxy integration
def analyze_response_flow(flow) -> Dict[str, Any]:
    """
    Convert mitmproxy flow to our finding dict. Minimal example.
    """
    headers = {k:v for k,v in flow.response.headers.items()}
    findings = []
    for h in DEFAULT_SECURITY_HEADERS:
        if h not in {k.lower() for k in headers.keys()}:
            findings.append({"type":"missing_header","header":h,"detail":f"Missing {h}"})
    return {"url": flow.request.url, "status_code": flow.response.status_code, "headers": headers, "findings": findings}
