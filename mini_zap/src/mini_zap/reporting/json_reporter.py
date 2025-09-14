# src/mini_zap/reporting/json_reporter.py
import json
from typing import List, Dict, Any

def write_json_report(path: str, start_url: str, results: List[Dict[str, Any]]) -> None:
    out = {
        "start_url": start_url,
        "summary": {"scanned": len(results)},
        "results": results
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2, ensure_ascii=False)
