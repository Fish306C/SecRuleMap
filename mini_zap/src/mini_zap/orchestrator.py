# src/mini_zap/orchestrator.py
from typing import List, Dict, Any
from .utils.logging import setup_logging, get_logger
from .utils.http import make_session
from .scanner import spider as spider_module
from .proxy import passive_scan as passive_module
from .scanner import active_scan as active_module
from .rules import loader as rules_loader
from .reporting import json_reporter, html_reporter
from .utils.cache import FileCache

logger = get_logger(__name__)

def run(args):
    # setup logging
    setup_logging(level="INFO", logfile=args.log_file)
    logger.info("mini_zap starting")
    logger.debug(f"args: {args}")

    # create session
    session = make_session(timeout=10)

    # load rules (optional)
    rules = rules_loader.load_rules_from_dir(args.rules_dir)

    # spider
    urls = set([args.url])
    if args.spider or args.scan_type in ("spider","all"):
        logger.info("Running spider...")
        found = spider_module.crawl(
            args.url,
            session=session,
            max_pages=args.max_pages,
            same_domain=args.same_domain
        )
        urls.update(found)
        logger.info(f"Spider collected {len(found)} URLs (total {len(urls)})")

    results: List[Dict[str, Any]] = []

    # passive scan
    if args.passive or args.scan_type in ("passive","all"):
        logger.info("Running passive scan...")
        for u in sorted(urls):
            try:
                res = passive_module.analyze_response_from_session(u, session, rules=rules)
                results.append(res)
            except Exception as e:
                logger.exception(f"Error passive scanning {u}: {e}")

    # active scan (CAREFUL)
    if args.active or args.scan_type == "active":
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

    # reporting
    out = args.output or "report.json"
    if out.endswith(".json"):
        json_reporter.write_json_report(out, args.url, results)
        logger.info(f"JSON report written to {out}")
    elif out.endswith(".html"):
        html_reporter.write_html_report(out, args.url, results)
        logger.info(f"HTML report written to {out}")
    else:
        json_reporter.write_json_report(out + ".json", args.url, results)
        logger.info(f"Report written to {out}.json")

    # cache example (persisted automatically by cache module)
    cache = FileCache()
    cache.set("last_scan:start_url", args.url)
    logger.info("mini_zap finished")
