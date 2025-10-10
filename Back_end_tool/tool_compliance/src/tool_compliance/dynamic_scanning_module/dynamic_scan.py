# src/mini_zap/scanner/dynamic_scan.py
from typing import List, Dict, Any
from ..utils.logging import get_logger
from ..utils.http import get as session_get

logger = get_logger(__name__)

# Safe, minimal payloads for demo only
SAFE_PAYLOADS = ["<script>alert(1)</script>", "' OR '1'='1"]

def run_safe_tests(url: str, session) -> List[Dict[str, Any]]:
    """
    Very small, non-destructive active tests:
    - Append a 'test' param with payload and check if reflected.
    WARNING: active tests may alter target. Run only on allowed/test targets.
    """
    findings = []
    for p in SAFE_PAYLOADS:
        try:
            test_url = url
            sep = "&" if "?" in url else "?"
            test_url = f"{url}{sep}test={p}"
            r = session_get(session, test_url)
            if p in (r.text or ""):
                findings.append({
                    "type": "xss_reflection",
                    "payload": p,
                    "evidence": f"payload reflected in response of {test_url}",
                    "severity": "high"
                })
            else:
                # look for SQL error signatures (very naive)
                if any(e in (r.text or "").lower() for e in ["sql syntax", "mysql", "syntax error"]):
                    findings.append({
                        "type": "sql_error",
                        "payload": p,
                        "evidence": f"possible SQL error on {test_url}",
                        "severity": "high"
                    })
        except Exception as e:
            logger.debug(f"active test error for {url} payload {p}: {e}")
    return findings
