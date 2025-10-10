# src/mini_zap/orchestrator.py
from typing import List, Dict, Any
import os
import getpass
from ..utils.logging import setup_logging, get_logger
from ..utils.http import make_session, apply_basic_auth, apply_bearer_token, perform_form_login
from ..dynamic_scanning_module import spider as spider_module
from ..dynamic_scanning_module import passive_scan as passive_module
from ..dynamic_scanning_module import dynamic_scan as dynamic_module
from ..rule_engine import loader as rules_loader
from ..reporting_module import json_reporter, html_reporter
from ..utils.cache import FileCache

logger = get_logger(__name__)

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

    # auth-cookie first
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
        if login_url.startswith("/"):
            from urllib.parse import urljoin
            login_full = urljoin(args.url, login_url)
        else:
            login_full = login_url
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

def _looks_like_user_endpoint(endpoint_raw: str) -> bool:
    if not endpoint_raw:
        return False
    s = endpoint_raw.lower()
    return "user" in s or "users" in s

def _url_has_id_segment(url: str) -> bool:
    try:
        from urllib.parse import urlparse
        path = urlparse(url).path or ""
        segs = [s for s in path.split("/") if s]
        # heuristic: trailing segment that looks like DB id (hex or long numeric) or contains mix of letters+digits
        for s in segs[::-1]:
            if len(s) >= 6 and (s.isdigit() or all(c in "0123456789abcdefABCDEF" for c in s) or (any(ch.isdigit() for ch in s) and any(ch.isalpha() for ch in s))):
                return True
        return False
    except Exception:
        return False

# put this inside src/mini_zap/orchestrator.py (replace existing _map_findings_to_rules)

import re
from urllib.parse import urlparse

def _url_has_id_segment(url: str) -> bool:
    """Return True if URL path has a segment looking like an ID (digits or long hex-like)."""
    try:
        path = urlparse(url).path
        segs = [s for s in path.split("/") if s]
        for s in segs:
            # numeric id or long hex-ish (mongo id ~24 hex) or uuid-like
            if s.isdigit() or re.fullmatch(r"[0-9a-fA-F]{20,}", s) or re.fullmatch(r"[0-9a-fA-F\-]{8,}", s):
                return True
    except Exception:
        return False
    return False

def _map_findings_to_rules(rules: Dict[str, Any], results: List[Dict[str, Any]]):
    """
    Map findings -> ruleIds and include rule metadata in rule_map entries.
    Returns rule_map: Dict[ruleId -> list of {url, evidence, finding_type, matched_by, rule_meta}]
    Also mutates findings to include ruleId(s).
    """
    rule_map: Dict[str, List[Dict[str, Any]]] = {}

    # Build indices for quick matching
    header_rules: Dict[str, List[str]] = {}   # header_name -> list of rule keys
    api_rules: List[tuple] = []               # (rule_key, normalized dict, original rule)
    config_rules: List[tuple] = []            # (rule_key, normalized, original)
    other_rules: List[tuple] = []

    # Preprocess rules into indices and prepare metadata
    rule_meta: Dict[str, Dict[str, Any]] = {}  # rule_key -> metadata
    for rk, r in rules.items():
        norm = r.get("_normalized", {}) or {}
        typ = (norm.get("type") or r.get("type") or "").lower()
        # metadata to include for report
        meta = {
            "ruleId": r.get("ruleId") or rk,
            "key": rk,
            "standard": r.get("standard"),
            "description": r.get("description"),
            "severity": r.get("severity"),
            "type": r.get("type"),
            "source_file": r.get("_source_file")
        }
        rule_meta[rk] = meta

        if typ == "header_check":
            hdr = norm.get("header")
            if hdr:
                header_rules.setdefault(hdr.lower(), []).append(rk)
            else:
                other_rules.append((rk, norm, r))
        elif typ == "api_check":
            api_rules.append((rk, norm, r))
        elif typ == "config_check":
            config_rules.append((rk, norm, r))
        else:
            other_rules.append((rk, norm, r))

    def add_mapping(rk: str, url: str, evidence: str, finding_type: str, matched_by: str):
        entry = {
            "url": url,
            "evidence": evidence,
            "finding_type": finding_type,
            "matched_by": matched_by,
            "rule": rule_meta.get(rk, {"ruleId": rk})
        }
        rule_map.setdefault(rule_meta.get(rk, {"ruleId": rk})["ruleId"], []).append(entry)

    def attach_ruleid_to_finding(f: Dict[str, Any], rk: str):
        # attach rule key or ruleId into the finding
        rid = rule_meta.get(rk, {}).get("ruleId", rk)
        if not f.get("ruleId"):
            f["ruleId"] = rid
        else:
            if isinstance(f["ruleId"], list):
                if rid not in f["ruleId"]:
                    f["ruleId"].append(rid)
            else:
                if f["ruleId"] != rid:
                    f["ruleId"] = [f["ruleId"], rid]

    # Now iterate results and try matching
    for item in results:
        url = item.get("url")
        for f in item.get("findings", []):
            mapped_any = False
            ftype = f.get("type", "")
            detail = f.get("detail") or f.get("evidence") or ""

            # 1) missing_header -> header_check direct mapping
            if ftype == "missing_header" and "header" in f:
                h = str(f["header"]).lower()
                # exact header matches
                if h in header_rules:
                    for rk in header_rules[h]:
                        add_mapping(rk, url, detail, ftype, matched_by=f"header_exact:{h}")
                        attach_ruleid_to_finding(f, rk)
                        mapped_any = True
                # fuzzy matches (aliasing)
                if not mapped_any:
                    for hk, rks in header_rules.items():
                        if hk in h or h in hk:
                            for rk in rks:
                                add_mapping(rk, url, detail, ftype, matched_by=f"header_alias:{hk}")
                                attach_ruleid_to_finding(f, rk)
                                mapped_any = True

                # fallback search in config rule descriptions/assertions
                if not mapped_any:
                    for rk, norm, orig in config_rules:
                        aval = str(norm.get("assertion_value") or "").lower()
                        desc = str(norm.get("description") or orig.get("description") or "").lower()
                        if h in aval or h in desc:
                            add_mapping(rk, url, detail, ftype, matched_by=f"config_text:{h}")
                            attach_ruleid_to_finding(f, rk)
                            mapped_any = True
                            break

            # 2) sensitive_data_exposure -> try to map to config/other mentioning the pattern
            if ftype == "sensitive_data_exposure" and "pattern" in f:
                pat = str(f["pattern"]).lower()
                for rk, norm, orig in list(config_rules) + list(other_rules):
                    aval = str(norm.get("assertion_value") or "").lower()
                    desc = str(norm.get("description") or orig.get("description") or "").lower()
                    if pat in aval or pat in desc or pat in desc:
                        add_mapping(rk, url, detail, ftype, matched_by=f"pattern_text:{pat}")
                        attach_ruleid_to_finding(f, rk)
                        mapped_any = True
                        # allow multiple matches

                # special heuristic: password exposure in a /users/ URL -> map to any api_check mentioning users
                if not mapped_any and "password" in pat and url and "/users/" in url:
                    for rk, norm, orig in api_rules:
                        if "users" in (norm.get("endpoint_raw") or "").lower() or "user" in (orig.get("description") or "").lower():
                            add_mapping(rk, url, detail, ftype, matched_by="sensitive_pw_on_users_endpoint")
                            attach_ruleid_to_finding(f, rk)
                            mapped_any = True

            # 3) API checks: match via endpoint_regex, core regex, or heuristics
            for rk, norm, orig in api_rules:
                if mapped_any:
                    break
                endpoint_re = norm.get("endpoint_regex")
                endpoint_core_re = norm.get("endpoint_core_regex")
                endpoint_raw = (norm.get("endpoint_raw") or "").lower()

                try:
                    if endpoint_re and url and endpoint_re.search(url):
                        add_mapping(rk, url, detail, ftype, matched_by="api_exact_regex")
                        attach_ruleid_to_finding(f, rk)
                        mapped_any = True
                        break
                    if endpoint_core_re and url and endpoint_core_re.search(url):
                        add_mapping(rk, url, detail, ftype, matched_by="api_core_regex")
                        attach_ruleid_to_finding(f, rk)
                        mapped_any = True
                        break
                    # heuristic: if endpoint mentions 'users' and url contains '/users/' and looks like id
                    if endpoint_raw and "users" in endpoint_raw and "/users/" in (url or "") and _url_has_id_segment(url):
                        add_mapping(rk, url, detail, ftype, matched_by="api_users_heuristic")
                        attach_ruleid_to_finding(f, rk)
                        mapped_any = True
                        break
                except Exception:
                    continue

            # 4) config_check matching: look at assertion_value or path (ex: '/admin/')
            if not mapped_any:
                for rk, norm, orig in config_rules:
                    aval = str(norm.get("assertion_value") or "").lower()
                    desc = str(norm.get("description") or orig.get("description") or "").lower()
                    # Example: if assertion_value contains '/admin' and url path starts with /admin => matched
                    if aval and aval in (url or "").lower():
                        add_mapping(rk, url, detail, ftype, matched_by=f"config_assertion_in_url:{aval}")
                        attach_ruleid_to_finding(f, rk)
                        mapped_any = True
                        break
                    # If assertion says 'not_exists' path '/admin/' and the finding shows admin is accessible (behavioral), map it.
                    if orig.get("assertion", {}).get("condition") == "not_exists" and "/admin" in aval and "/admin" in (url or "").lower():
                        add_mapping(rk, url, detail, ftype, matched_by="config_not_exists_admin_behavioral")
                        attach_ruleid_to_finding(f, rk)
                        mapped_any = True
                        break

            # 5) Final heuristic: search rule descriptions/assertion values inside the finding detail text
            if not mapped_any:
                token = (detail or "").lower()
                for rk, norm, orig in list(config_rules) + list(other_rules):
                    aval = str(norm.get("assertion_value") or "").lower()
                    desc = str(norm.get("description") or orig.get("description") or "").lower()
                    if aval and aval in token:
                        add_mapping(rk, url, detail, ftype, matched_by="detail_contains_assertion")
                        attach_ruleid_to_finding(f, rk)
                        mapped_any = True
                        break
                    if desc and desc in token:
                        add_mapping(rk, url, detail, ftype, matched_by="detail_contains_description")
                        attach_ruleid_to_finding(f, rk)
                        mapped_any = True
                        break

            # fallback: mark as UNMAPPED
            if not mapped_any:
                add_mapping("UNMAPPED", url, detail, ftype, matched_by="none")
    return rule_map


def run(args):
    # setup logging
    setup_logging(level="INFO", logfile=args.log_file)
    logger.info("mini_zap starting")
    logger.debug(f"args: {args}")

    # create session with timeout/retries
    session = make_session(timeout=getattr(args, "timeout", 10), retries=getattr(args, "retries", 1))

    # load rules
    rules = rules_loader.load_rules_from_dir(getattr(args, "rules_dir", "rules"))
    logger.info(f"Loaded rules: {len(rules)}")

    # DEBUG: print a summary of loaded api_check rules (helps verify normalization)
    for rid, r in rules.items():
        if (r.get("type") or "").lower() == "api_check":
            logger.debug("Loaded API rule: %s -> normalized=%s", rid, r.get("_normalized", {}))

    # perform authentication BEFORE spider so session contains cookies/headers
    try:
        _perform_auth_if_requested(session, args)
    except Exception as e:
        logger.exception(f"Authentication step failed: {e}")

    # spider
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

    # passive scan
    if getattr(args, "passive", False) or args.scan_type in ("passive", "all"):
        logger.info("Running passive scan...")
        for u in sorted(urls):
            try:
                res = passive_module.analyze_response_from_session(u, session, rules=rules)
                results.append(res)
            except Exception as e:
                logger.exception(f"Error passive scanning {u}: {e}")

    # active scan (CAREFUL)
    if getattr(args, "active", False) or args.scan_type == "active":
        logger.warning("Active scan requested. Make sure you have permission to test the target.")
        for u in sorted(urls):
            try:
                findings = active_module.run_safe_tests(u, session)
                if findings:
                    results.append({
                        "url": u,
                        "status_code": None,
                        "headers": {},
                        "findings": findings
                    })
            except Exception as e:
                logger.exception(f"Error active scanning {u}: {e}")

    # Map findings to rules (heuristic) before reporting
    try:
        mapped_rule_map = _map_findings_to_rules(rules, results)
        logger.info(f"Mapped findings to {len(mapped_rule_map)} rule keys (including UNMAPPED)")
    except Exception as e:
        logger.exception(f"Error mapping findings to rules: {e}")
        mapped_rule_map = {}

    # reporting
    out = args.output or "report.json"
    try:
        # prefer reporter that accepts rule_map (newer)
        json_reporter.write_json_report(out, args.url, results, mapped_rule_map)
        logger.info(f"JSON report written to {out}")
    except TypeError:
        # fallback to older reporter signature (without rule_map)
        logger.debug("json_reporter.write_json_report does not accept rule_map; calling fallback signature.")
        json_reporter.write_json_report(out, args.url, results)
        logger.info(f"JSON report written to {out} (rule_map not embedded)")

    if out.endswith(".html"):
        # HTML reporter currently expects (path, start_url, results)
        try:
            html_reporter.write_html_report(out, args.url, results)
            logger.info(f"HTML report written to {out}")
        except Exception as e:
            logger.exception(f"Failed to write HTML report: {e}")

    # cache example
    cache = FileCache()
    cache.set("last_scan:start_url", args.url)
    logger.info("tool_compliance finished")
