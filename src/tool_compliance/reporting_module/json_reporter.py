# src/mini_zap/reporting/json_reporter.py
import json
from typing import List, Dict, Any, Optional
from collections import defaultdict

def write_json_report(path: str, start_url: str, results: List[Dict[str, Any]], provided_rule_map: Optional[Dict[str, Any]] = None) -> None:
    """
    Write JSON report. If provided_rule_map is given (from orchestrator mapping), merge it
    with an automatically built map derived from findings so the report contains both.
    """
    out: Dict[str, Any] = {
        "start_url": start_url,
        "summary": {"scanned": len(results)},
        "results": results
    }

    # Build automatic rule->urls mapping from findings
    auto_map: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for item in results:
        url = item.get("url")
        for f in item.get("findings", []):
            rid = f.get("ruleId")
            evidence = f.get("evidence") or f.get("detail")
            if not rid:
                continue
            # ruleId may be a single string or a list of strings
            if isinstance(rid, list):
                for rkey in rid:
                    auto_map[str(rkey)].append({"url": url, "evidence": evidence})
            else:
                auto_map[str(rid)].append({"url": url, "evidence": evidence})

    # Start with provided map if present, else empty
    merged_map: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    if provided_rule_map:
        # Normalize provided map entries (ensure lists of dicts)
        for key, entries in provided_rule_map.items():
            # if entries is not a list of dicts, try to keep sensible form
            if isinstance(entries, list):
                merged_map[str(key)].extend(entries)
            else:
                # unexpected shape, wrap as evidence string
                merged_map[str(key)].append({"url": None, "evidence": str(entries)})

    # Merge auto_map into merged_map without duplicating identical pairs
    for key, entries in auto_map.items():
        existing = merged_map.get(key, [])
        # Use simple dedupe by (url,evidence)
        seen = {(e.get("url"), e.get("evidence")) for e in existing}
        for e in entries:
            tup = (e.get("url"), e.get("evidence"))
            if tup not in seen:
                merged_map[key].append(e)
                seen.add(tup)

    out["rule_map"] = dict(merged_map)

    with open(path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2, ensure_ascii=False)
