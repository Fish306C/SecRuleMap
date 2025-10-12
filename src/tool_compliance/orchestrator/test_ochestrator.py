from typing import List, Dict, Any
import getpass
import re
from urllib.parse import urljoin

from ..utils.logging import setup_logging, get_logger
from ..utils.http import make_session, apply_basic_auth, apply_bearer_token, perform_form_login
from ..dynamic_scanning_module import spider as spider_module
from ..dynamic_scanning_module import passive_scan as passive_module
from ..dynamic_scanning_module import dynamic_scan as legacy_active_module
from ..dynamic_scanning_module.probes.registry import PROBES  # <— NEW
from ..rule_engine import loader as rules_loader
from ..reporting_module import json_reporter, html_reporter
from ..utils.cache import FileCache

logger = get_logger(__name__)

# ------------------------
# Auth helpers
# ------------------------

def parse_cookie_string(cookie_str: str) -> Dict[str, str]:
    cookies = {}
    if not cookie_str:
        return cookies
    for part in cookie_str.split(";"):
        if "=" in part:
            k, v = part.strip().split("=", 1)
            cookies[k] = v
    return cookies


def _perform_auth_if_requested(session, args) -> bool:
    attempted = False

    if getattr(args, "auth_cookie", None):
        cookies = parse_cookie_string(args.auth_cookie)
        if cookies:
            session.cookies.update(cookies)
            logger.info(f"Applied {len(cookies)} cookie(s) to session from --auth-cookie")
            attempted = True

    if getattr(args, "auth_type", None) == "basic":
        attempted = True
        username = getattr(args, "auth_username", None)
        password = getattr(args, "auth_password", None)
        if username and not password:
            password = getpass.getpass(prompt=f"Password for {username}: ")
        apply_basic_auth(session, username, password)
        logger.info("Applied HTTP Basic auth to session")

    if getattr(args, "auth_type", None) == "bearer":
        attempted = True
        token = getattr(args, "auth_token", None)
        if token:
            apply_bearer_token(session, token)
            logger.info("Applied Bearer token to session headers")
        else:
            logger.warning("auth-type bearer requested but --auth-token not provided")

    if getattr(args, "auth_type", None) == "form":
        attempted = True
        login_url = getattr(args, "auth_login_url", None) or "/login"
        username_field = getattr(args, "auth_login_username_field", None) or "email"
        password_field = getattr(args, "auth_login_password_field", None) or "password"
        username = getattr(args, "auth_username", None)
        password = getattr(args, "auth_password", None)
        if username and not password:
            password = getpass.getpass(prompt=f"Password for {username}: ")
        login_full = urljoin(args.url, login_url) if login_url.startswith("/") else login_url
        logger.info(f"Attempting form-login to {login_full} (username field='{username_field}')")
        ok = perform_form_login(session, login_full, username_field, password_field, username, password)
        if ok:
            logger.info("Form login appears successful (cookies set / redirect observed).")
            try:
                logger.info(f"Session cookies after login: {session.cookies.get_dict()}")
            except Exception:
                logger.info("Session cookies after login: <unavailable>")
        else:
            logger.warning("Form login did not show obvious success. Consider --auth-cookie or headless login.")

    return attempted

# ------------------------
# Rule indexing & URL matching (regex-based)
# ------------------------

def _index_api_rules(rules: Dict[str, Any]) -> List[Dict[str, Any]]:
    indexed = []
    for rid, r in rules.items():
        norm = r.get("_normalized", {})
        rtype = (norm.get("type") or r.get("type") or "").lower()
        if rtype != "api_check":
            continue
        rx = norm.get("endpoint_regex")
        if not rx:
            # Attempt compile from raw endpoint as fallback
            raw = norm.get("endpoint_raw") or (r.get("target", {}) or {}).get("endpoint")
            if raw:
                try:
                    e = raw.strip()
                    if not e.startswith("/"):
                        e = "/" + e
                    # Replace {param} → [^/]+ and compile as search pattern
                    pattern = re.escape(re.sub(r"\{[^/]+\}", r"[^/]+", e)).replace(re.escape("[^/]+"), r"[^/]+")
                    rx = re.compile(pattern, re.IGNORECASE)
                except re.error:
                    rx = None
        if rx:
            entry = dict(r)
            entry["__rid"] = rid
            entry["__rx"] = rx
            indexed.append(entry)
    return indexed


def _rules_matching_url(api_rules: List[Dict[str, Any]], url: str) -> List[Dict[str, Any]]:
    matches = []
    for r in api_rules:
        rx = r.get("__rx")
        try:
            if rx and rx.search(url):
                matches.append(r)
        except re.error:
            continue
    return matches

# ------------------------
# Reporting mapping (prefer explicit ruleId)
# ------------------------

def _map_findings_to_rules(rules: Dict[str, Any], results: List[Dict[str, Any]]):
    rule_map: Dict[str, List[Dict[str, Any]]] = {}
    api_index = _index_api_rules(rules)

    def _add(k: str, u: str, ev: str, ft: str):
        rule_map.setdefault(k, []).append({"url": u, "evidence": ev, "finding_type": ft})

    for res in results:
        url = res.get("url", "")
        for f in res.get("findings", []):
            ftype = f.get("type", "")
            detail = f.get("detail", "") or f.get("evidence", "") or ""

            rid = f.get("ruleId")
            if rid:
                _add(str(rid), url, detail, ftype)
                continue

            matched = _rules_matching_url(api_index, url)
            if matched:
                for mr in matched:
                    mrid = mr.get("ruleId") or mr.get("_normalized", {}).get("rule_id") or mr.get("__rid")
                    if mrid:
                        f.setdefault("ruleId", [])
                        if isinstance(f["ruleId"], list):
                            f["ruleId"].append(mrid)
                        _add(str(mrid), url, detail, ftype)
                continue

            _add("UNMAPPED", url, detail, ftype)

    return rule_map

# ------------------------
# Main run
# ------------------------

def run(args):
    setup_logging(level="INFO", logfile=args.log_file)
    logger.info("webscan starting")
    logger.debug(f"args: {args}")

    session = make_session(timeout=getattr(args, "timeout", 10), retries=getattr(args, "retries", 1))

    rules = rules_loader.load_rules_from_dir(getattr(args, "rules_dir", "rules"))
    logger.info(f"Loaded rules: {len(rules)}")

    for rid, r in rules.items():
        if (r.get("type") or "").lower() == "api_check":
            logger.debug("Loaded API rule: %s -> normalized=%s", rid, r.get("_normalized", {}))

    try:
        _perform_auth_if_requested(session, args)
    except Exception as e:
        logger.exception(f"Authentication step failed: {e}")

    urls = set([args.url])
    if getattr(args, "spider", False) or args.scan_type in ("spider", "all"):
        logger.info("Running spider...")
        found = spider_module.crawl(
            args.url,
            session=session,
            max_pages=getattr(args, "max_pages", 50),
            same_domain=getattr(args, "same_domain", True)
        )
        urls.update(found)
        logger.info(f"Spider collected {len(found)} URLs (total {len(urls)})")

    results: List[Dict[str, Any]] = []

    if getattr(args, "passive", False) or args.scan_type in ("passive", "all"):
        logger.info("Running passive scan...")
        for u in sorted(urls):
            try:
                res = passive_module.analyze_response_from_session(u, session, rules=rules)
                results.append(res)
            except Exception as e:
                logger.exception(f"Error passive scanning {u}: {e}")

    if getattr(args, "active", False) or args.scan_type in ("active", "all"):
        logger.warning("Active scan requested. Make sure you have permission to test the target.")
        api_rules = _index_api_rules(rules)
        for u in sorted(urls):
            try:
                matched_rules = _rules_matching_url(api_rules, u)
                # Dispatch by check-type to probe functions
                for rule in matched_rules:
                    check = (rule.get("check") or rule.get("_normalized", {}).get("check") or "").lower()
                    probe = PROBES.get(check)
                    if not probe:
                        continue
                    pfinds = probe(u, session, rule)
                    if pfinds:
                        results.append({
                            "url": u,
                            "status_code": None,
                            "headers": {},
                            "findings": pfinds,
                        })
                # Keep legacy safe tests (optional)
                legacy = legacy_active_module.run_safe_tests(u, session)
                if legacy:
                    for f in legacy:
                        if not f.get("ruleId") and matched_rules:
                            rid = matched_rules[0].get("ruleId") or matched_rules[0].get("_normalized", {}).get("rule_id") or matched_rules[0].get("__rid")
                            if rid:
                                f["ruleId"] = rid
                    results.append({
                        "url": u,
                        "status_code": None,
                        "headers": {},
                        "findings": legacy,
                    })
            except Exception as e:
                logger.exception(f"Error active scanning {u}: {e}")

    try:
        mapped_rule_map = _map_findings_to_rules(rules, results)
        logger.info(f"Mapped findings to {len(mapped_rule_map)} rule keys (including UNMAPPED)")
    except Exception as e:
        logger.exception(f"Error mapping findings to rules: {e}")
        mapped_rule_map = {}

    out = args.output or "report.json"
    try:
        json_reporter.write_json_report(out, args.url, results, mapped_rule_map)
        logger.info(f"JSON report written to {out}")
    except TypeError:
        logger.debug("json_reporter.write_json_report does not accept rule_map; calling fallback signature.")
        json_reporter.write_json_report(out, args.url, results)
        logger.info(f"JSON report written to {out} (rule_map not embedded)")

    if out.endswith(".html"):
        try:
            html_reporter.write_html_report(out, args.url, results)
            logger.info(f"HTML report written to {out}")
        except Exception as e:
            logger.exception(f"Failed to write HTML report: {e}")

    cache = FileCache()
    cache.set("last_scan:start_url", args.url)
    logger.info("webscan finished")
