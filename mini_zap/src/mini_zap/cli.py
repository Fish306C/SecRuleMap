# src/mini_zap/cli.py
import argparse

def parse_args():
    p = argparse.ArgumentParser(prog="mini_zap", description="mini_zap - lightweight web scanner prototype")
    p.add_argument("--url", "-u", required=True, help="Start URL (e.g. http://example.com)")
    p.add_argument("--scan-type", "-s", choices=["spider","passive","active","all"], default="all",
                   help="Type of scan to run: spider / passive / active / all")
    p.add_argument("--spider", action="store_true", help="Run spider (same as --scan-type spider)")
    p.add_argument("--passive", action="store_true", help="Run passive scan (same as --scan-type passive)")
    p.add_argument("--active", action="store_true", help="Run active scan (same as --scan-type active) -- use with caution")
    p.add_argument("--output", "-o", default="report.json", help="Output file path (.json or .html)")
    p.add_argument("--max-pages", type=int, default=50, help="Max pages to crawl with spider")
    p.add_argument("--same-domain", action="store_true", default=True, help="Restrict spider to same domain")
    p.add_argument("--rules-dir", default="rules", help="Directory containing YAML rules")
    p.add_argument("--log-file", default=None, help="Optional log file path")
    return p.parse_args()
