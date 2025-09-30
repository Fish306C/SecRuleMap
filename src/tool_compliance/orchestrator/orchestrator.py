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
    for res in results:
        url = res.get("url", "")
        for f in res.get("findings", []):
            ftype = f.get("type", "")
            detail = f.get("detail", "") or f.get("evidence", "") or ""
            mapped_any = False
            # Simplified mapping for example
            for rid, rule in rules.items():
                norm = rule.get("_normalized", {})
                if norm.get("type") == "api_check" and _looks_like_user_endpoint(norm.get("endpoint_raw", "")):
                    add_mapping = lambda rid, url, detail, ftype: rule_map.setdefault(rid, []).append({"url": url, "evidence": detail, "finding_type": ftype})
                    attach_ruleid_to_finding = lambda f, rid: f.update({"ruleId": f.get("ruleId", []) + [rid] if isinstance(f.get("ruleId"), list) else [rid]})
                    add_mapping(rid, url, detail, ftype)
                    attach_ruleid_to_finding(f, rid)
                    mapped_any = True
            if not mapped_any:
                add_mapping = lambda rid, url, detail, ftype: rule_map.setdefault(rid, []).append({"url": url, "evidence": detail, "finding_type": ftype})
                add_mapping("UNMAPPED", url, detail, ftype)

    return rule_map

def run(args):
    # setup logging
    setup_logging(level="INFO", logfile=args.log_file)
    logger.info("webscan starting")
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
                findings = dynamic_module.run_safe_tests(u, session)
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
    logger.info("webscan finished")