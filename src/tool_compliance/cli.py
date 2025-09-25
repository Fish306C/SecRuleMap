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

    # Auth options
    p.add_argument("--auth-type", choices=["none","basic","bearer","form"], default="none",
                   help="Authentication type to perform before scanning (none/basic/bearer/form)")
    p.add_argument("--auth-username", help="Username/email for auth (basic or form)")
    p.add_argument("--auth-password", help="Password for auth (basic or form) - if omitted program may prompt")
    p.add_argument("--auth-token", help="Token for bearer auth")
    p.add_argument("--auth-login-url", help="Login URL (relative or absolute) for form auth, e.g. /login")
    p.add_argument("--auth-login-username-field", default="email", help="Form field name for username/email (default: email)")
    p.add_argument("--auth-login-password-field", default="password", help="Form field name for password (default: password)")
    p.add_argument("--auth-cookie", help="Cookies to set on session (format: name=value; name2=value2) - useful if you copied cookies from browser")

    # network / robustness
    p.add_argument("--timeout", type=int, default=10, help="Per-request read timeout in seconds (default 10)")
    p.add_argument("--retries", type=int, default=1, help="HTTP retry attempts for transient errors (default 1)")

    return p.parse_args()
