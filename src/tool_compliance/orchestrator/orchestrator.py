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

def _map_findings_to_rules(rules: Dict[str, Any], results: List[Dict[str, Any]]):
    """
    Map findings -> ruleIds (a finding may map to multiple rules).
    Returns rule_map: Dict[ruleId -> list of {url, evidence, finding_type}]
    Also mutates findings to include ruleId (string or list).
    """
    rule_map: Dict[str, List[Dict[str, Any]]] = {}

    # build quick indices
    header_rules: Dict[str, List[tuple]] = {}  # header_name -> [(rid, rule), ...]
    api_rules: List[tuple] = []
    config_rules: List[tuple] = []
    other_rules: List[tuple] = []

    for rid, r in rules.items():
        rtype = (r.get("type") or "").lower()
        norm = r.get("_normalized", {}) or {}
        if rtype == "header_check":
            hdr = norm.get("header")
            if hdr:
                header_rules.setdefault(hdr, []).append((rid, r))
        elif rtype == "api_check":
            api_rules.append((rid, r))
        elif rtype == "config_check":
            config_rules.append((rid, r))
        else:
            other_rules.append((rid, r))

    # debug: log normalized api rules (small help to debug mapping)
    for rid, r in api_rules:
        nr = r.get("_normalized", {}) or {}
        logger.debug("API rule load: %s -> raw=%s regex=%s desc=%s", rid, nr.get("endpoint_raw"), getattr(nr.get("endpoint_regex"), "pattern", None), r.get("description"))

    def add_mapping(rid_key: str, url: str, evidence: str, finding_type: str):
        rule_map.setdefault(rid_key, []).append({"url": url, "evidence": evidence, "finding_type": finding_type})

    def attach_ruleid_to_finding(f: Dict[str, Any], rid_key: str):
        if not f.get("ruleId"):
            f["ruleId"] = rid_key
        else:
            existing = f["ruleId"]
            if isinstance(existing, list):
                if rid_key not in existing:
                    existing.append(rid_key)
            else:
                if existing != rid_key:
                    f["ruleId"] = [existing, rid_key]

    for item in results:
        url = item.get("url")
        for f in item.get("findings", []):
            mapped_any = False
            ftype = f.get("type", "")
            detail = f.get("detail") or f.get("evidence") or ""

            # 1) missing_header -> exact header matches and substring matches
            if ftype == "missing_header" and "header" in f:
                h = str(f["header"]).lower()
                # exact matches
                if h in header_rules:
                    for (rid, _) in header_rules[h]:
                        add_mapping(rid, url, detail, ftype)
                        attach_ruleid_to_finding(f, rid)
                        mapped_any = True
                # substring matches
                for hdr_key, entries in header_rules.items():
                    if hdr_key == h:
                        continue
                    if hdr_key in h or h in hdr_key:
                        for (rid, _) in entries:
                            add_mapping(rid, url, detail, ftype)
                            attach_ruleid_to_finding(f, rid)
                            mapped_any = True
                # fallback to config rules containing header name
                if not mapped_any:
                    for rid2, r2 in config_rules:
                        aval = str(r2.get("_normalized", {}).get("assertion_value", "") or "").lower()
                        desc = str(r2.get("description") or "").lower()
                        if h in aval or h in desc:
                            add_mapping(rid2, url, detail, ftype)
                            attach_ruleid_to_finding(f, rid2)
                            mapped_any = True
                            break

            # 2) sensitive_data_exposure -> map to config/other + user-related api rules
            if ftype == "sensitive_data_exposure" and "pattern" in f:
                pat = str(f["pattern"]).lower()
                for rid3, r3 in list(config_rules) + list(other_rules):
                    aval = str(r3.get("_normalized", {}).get("assertion_value", "") or "").lower()
                    desc = str(r3.get("description") or "").lower()
                    if pat in aval or pat in desc:
                        add_mapping(rid3, url, detail, ftype)
                        attach_ruleid_to_finding(f, rid3)
                        mapped_any = True
                # heuristic: if password found and url looks like user resource -> map to user api rules
                if "password" in pat and url and "/users/" in url:
                    for rid4, r4 in api_rules:
                        nr = r4.get("_normalized", {}) or {}
                        endpoint_raw = nr.get("endpoint_raw", "") or ""
                        if _looks_like_user_endpoint(endpoint_raw) or "user" in (r4.get("description") or "").lower():
                            add_mapping(rid4, url, detail, ftype)
                            attach_ruleid_to_finding(f, rid4)
                            mapped_any = True

            # 3) API rules mapping: test endpoint regex / raw fragment
            for rid5, r5 in api_rules:
                nr = r5.get("_normalized", {}) or {}
                endpoint_raw = nr.get("endpoint_raw", "") or ""
                endpoint_re = nr.get("endpoint_regex")
                try:
                    if endpoint_re and url and endpoint_re.search(url):
                        add_mapping(rid5, url, detail, ftype)
                        attach_ruleid_to_finding(f, rid5)
                        mapped_any = True
                    elif endpoint_raw and endpoint_raw.replace("{id}", "").rstrip("/") in (url or ""):
                        add_mapping(rid5, url, detail, ftype)
                        attach_ruleid_to_finding(f, rid5)
                        mapped_any = True
                except Exception:
                    continue

            # 4) NEW HEURISTIC: if URL contains '/users/' and has id-like segment, map to any api_check that mentions 'user' in endpoint_raw or description
            if not mapped_any and url and "/users/" in url and _url_has_id_segment(url):
                for rid6, r6 in api_rules:
                    nr = r6.get("_normalized", {}) or {}
                    endpoint_raw = nr.get("endpoint_raw", "") or ""
                    if _looks_like_user_endpoint(endpoint_raw) or "user" in (r6.get("description") or "").lower():
                        add_mapping(rid6, url, detail, ftype)
                        attach_ruleid_to_finding(f, rid6)
                        mapped_any = True

            # 5) Heuristic: match based on assertion_value / description across config/other using detail token
            if not mapped_any:
                token = (detail or "").lower()
                for rid7, r7 in list(config_rules) + list(other_rules):
                    aval = str(r7.get("_normalized", {}).get("assertion_value", "") or "").lower()
                    desc = str(r7.get("description") or "").lower()
                    if aval and aval in token:
                        add_mapping(rid7, url, detail, ftype)
                        attach_ruleid_to_finding(f, rid7)
                        mapped_any = True
                    elif desc and desc in token:
                        add_mapping(rid7, url, detail, ftype)
                        attach_ruleid_to_finding(f, rid7)
                        mapped_any = True

            # fallback UNMAPPED
            if not mapped_any:
                add_mapping("UNMAPPED", url, detail, ftype)

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
