from typing import Dict, Any
from ..utils.logging import get_logger
from ..utils.http import get as session_get

logger = get_logger(__name__)

def fingerprint(url: str, session) -> Dict[str, Any]:
    """
    Minimal recon: GET root and try detect WordPress via meta generator or well-known paths.
    Returns dictionary with detected items.
    """
    try:
        r = session_get(session, url)
    except Exception as e:
        logger.debug(f"recon GET failed: {e}")
        return {}

    text = (r.text or "").lower()
    detected = {}
    if "wp-content" in text or "wordpress" in text:
        detected["cms"] = "wordpress (heuristic)"
    # try common endpoint
    try:
        r2 = session_get(session, url.rstrip("/") + "/readme.html")
        if r2.status_code == 200 and "wordpress" in (r2.text or "").lower():
            detected["cms"] = "wordpress (readme)"
    except Exception:
        pass
    return detected
