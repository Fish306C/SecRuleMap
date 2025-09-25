# src/mini_zap/rules/loader.py
from typing import Dict, Any, List
import os
import yaml
import re
from ..utils.fs import find_files
from ..utils.logging import get_logger

logger = get_logger(__name__)

def load_rule_file(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)

# inside src/mini_zap/rules/loader.py

def _compile_endpoint_regex(endpoint: str):
    """
    Convert '/api/users/{id}' into regex that will match that path in a full URL.
    Also returns None on regex compile failure.
    """
    if not endpoint:
        return None
    e = endpoint.strip()
    if not e.startswith("/"):
        e = "/" + e
    # replace {param} with [^/]+
    e_re = re.sub(r"\{[^/]+\}", r"[^/]+", e)
    # we want to be able to search the full URL for this fragment, so do not anchor
    try:
        # un-escape the [^/]+ token inserted earlier
        pattern = re.escape(e_re).replace(re.escape("[^/]+"), r"[^/]+")
        return re.compile(pattern, re.IGNORECASE)
    except re.error:
        return None

def _normalize_rule(data: Dict[str, Any], path: str) -> Dict[str, Any]:
    norm: Dict[str, Any] = {}
    try:
        rule_id = data.get("ruleId") or data.get("id") or os.path.splitext(os.path.basename(path))[0]
        norm["rule_id"] = rule_id
        rtype = (data.get("type") or "").lower()
        norm["type"] = rtype

        if rtype == "api_check":
            target = data.get("target", {}) or {}
            endpoint = target.get("endpoint") or ""
            norm["endpoint_raw"] = endpoint or ""
            # primary compiled regex (exact as declared)
            norm["endpoint_regex"] = _compile_endpoint_regex(endpoint)
            # if endpoint mentions '/users', also build a core regex starting from '/users...'
            if "/users" in (endpoint or "").lower():
                idx = (endpoint.lower()).find("/users")
                core = endpoint[idx:]  # keep '/users/{id}' or '/users/...'
                norm["endpoint_core_raw"] = core
                norm["endpoint_core_regex"] = _compile_endpoint_regex(core)
        else:
            # other normalization (headers, assertions) as before...
            pass

        # assertion normalization (common)
        assertion = data.get("assertion") or {}
        val = assertion.get("value") or assertion.get("path") or assertion.get("pattern") or ""
        norm["assertion_value"] = str(val).strip().lower() if val is not None else ""
        norm["assertion_condition"] = assertion.get("condition") or assertion.get("cond") or ""
        norm["description"] = str(data.get("description") or data.get("title") or "")
        norm["severity"] = data.get("severity") or data.get("level") or ""
    except Exception as e:
        logger.debug(f"Normalization error for rule {path}: {e}")

    return norm


def load_rules_from_dir(dirpath: str) -> Dict[str, Any]:
    """
    Loads YAML rules from a directory (recursively), returns dict keyed by ruleId/file-name.
    Each rule dict will have an added key '_normalized' for easier programmatic matching.
    """
    rules: Dict[str, Any] = {}
    if not os.path.isdir(dirpath):
        logger.debug(f"Rules directory not found: {dirpath}")
        return rules

    # find YAML files
    files = find_files(dirpath, patterns=["*.yml", "*.yaml"])
    for p in files:
        try:
            data = load_rule_file(p) or {}
        except Exception as e:
            logger.warning(f"Failed to load rule {p}: {e}")
            continue

        # Determine canonical rule id (prefer explicit ruleId then filename)
        rid = data.get("ruleId") or data.get("id") or os.path.splitext(os.path.basename(p))[0]
        # ensure unique key: if duplicate file names, append relative path
        key = rid
        if key in rules:
            # disambiguate by using relative path
            rel = os.path.relpath(p, dirpath).replace(os.sep, "/")
            key = f"{rid}::{rel}"

        # attach path for debugging
        data["_source_file"] = p

        # add normalized info for matching
        data["_normalized"] = _normalize_rule(data, p)

        rules[str(key)] = data
        logger.debug(f"Loaded rule '{key}' from {p} normalized={data['_normalized']}")

    return rules
