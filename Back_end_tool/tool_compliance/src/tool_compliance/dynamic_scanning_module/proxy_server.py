# src/mini_zap/proxy/proxy_server.py
"""
Optional: small mitmproxy addon example to forward flows to passive_scan module.
This file is provided as a placeholder. To use mitmproxy, you must run:
    mitmproxy -s proxy_server.py
and implement integration with passive_scan functions as needed.
"""
from mitmproxy import http
import json
from ..utils.logging import get_logger
from .passive_scan import analyze_response_flow

logger = get_logger(__name__)

# mitmproxy calls request/response handlers; we provide a simple example:
def response(flow: http.HTTPFlow) -> None:
    """
    Called when a server response has been received.
    We call analyze_response_flow to convert to our finding structure.
    """
    try:
        finding = analyze_response_flow(flow)
        # Append to a file for simple persistence (or integrate with orchestrator via IPC)
        with open("proxy_captured.jsonl", "a", encoding="utf-8") as fh:
            fh.write(json.dumps(finding, ensure_ascii=False) + "\n")
    except Exception as e:
        logger.exception(f"proxy_server error: {e}")
