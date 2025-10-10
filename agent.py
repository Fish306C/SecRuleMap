#!/usr/bin/env python3
# apache_agent.py
# Usage: python apache_agent.py
# Mount expected:
#  - ./container-apache2 -> /etc/apache2 (read-only)
#  - ./container-www -> /var/www/html (optional, read-only)

import os
import re
import json
from pathlib import Path
import glob

APACHE_ROOT = "container-apache2"
WWW_ROOT = "container-www"

def read_file(path):
    try:
        return Path(path).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return None

def find_includes(text):
    includes = []
    for m in re.finditer(r'^\s*Include(?:Optional)?\s+(.+)$', text, flags=re.IGNORECASE | re.MULTILINE):
        inc = m.group(1).strip().strip('"').strip("'")
        includes.append(inc)
    return includes

def normalize_path(inc, base):
    if inc.startswith("/"):
        return inc
    return os.path.normpath(os.path.join(base, inc))

def list_conf_files(root):
    files = []
    for dirpath, dirs, filenames in os.walk(root):
        for fn in filenames:
            if fn.endswith(".conf") or fn.endswith(".load") or fn.endswith(".env"):
                files.append(os.path.join(dirpath, fn))
    return sorted(files)

def parse_vhosts_from_file(path, text):
    vhosts = []
    for m in re.finditer(r'(?is)<VirtualHost\s+([^>]+)>(.*?)</VirtualHost>', text):
        vh_addr = m.group(1).strip()
        body = m.group(2)
        info = {"file": path, "vhost_addr": vh_addr}

        def get_single(pat):
            mm = re.search(pat, body, re.IGNORECASE | re.MULTILINE)
            return mm.group(1).strip() if mm else None

        info["server_name"] = get_single(r'^\s*ServerName\s+(.+)$')
        aliases = re.findall(r'^\s*ServerAlias\s+(.+)$', body, re.IGNORECASE | re.MULTILINE)
        if aliases:
            info["server_alias"] = " ".join(a.strip() for a in aliases)
        info["document_root"] = get_single(r'^\s*DocumentRoot\s+(.+)$')
        info["ssl_cert"] = get_single(r'^\s*SSLCertificateFile\s+(.+)$')
        info["ssl_key"] = get_single(r'^\s*SSLCertificateKeyFile\s+(.+)$')
        proxies = re.findall(r'^\s*ProxyPass\s+(.+)$', body, re.IGNORECASE | re.MULTILINE)
        if proxies:
            info["proxy_pass"] = [p.strip() for p in proxies]
        rewrites = re.findall(r'^\s*RewriteRule\s+(.+)$', body, re.IGNORECASE | re.MULTILINE)
        if rewrites:
            info["rewrite_rules"] = [r.strip() for r in rewrites]
        opts = re.search(r'^\s*<Directory\s+(.+?)>(.*?)</Directory>', body, re.IGNORECASE | re.DOTALL)
        if opts:
            dirbody = opts.group(2)
            if re.search(r'Options\s+.*Indexes', dirbody, re.IGNORECASE):
                info["directory_indexing_enabled"] = True
        vhosts.append(info)
    return vhosts

def detect_global_issues(files_text):
    issues = []
    if re.search(r'^\s*ServerSignature\s+On', files_text, re.IGNORECASE | re.MULTILINE):
        issues.append({"id":"server_signature_on","message":"ServerSignature is On (may leak server info)"})
    st = re.search(r'^\s*ServerTokens\s+(.+)$', files_text, re.IGNORECASE | re.MULTILINE)
    if st:
        val = st.group(1).strip()
        if val.lower() in ("full","os"):
            issues.append({"id":"servertokens_full","message":f"ServerTokens set to {val} (reveals version info)"})
    if re.search(r'<Directory\s+/var/www/>(?:.|\n)*?AllowOverride\s+All', files_text, re.IGNORECASE):
        issues.append({"id":"allowoverride_all_www","message":"AllowOverride All set for /var/www (enables .htaccess overrides)."})
    if re.search(r'Options\s+.*Indexes', files_text, re.IGNORECASE):
        issues.append({"id":"global_indexes","message":"Options Indexes appears in config (directory listings may be enabled)."})
    return issues

def main():
    report = {"apache_root_provided": os.path.isdir(APACHE_ROOT), "files": [], "vhosts": [], "issues": []}
    conf_files = list_conf_files(APACHE_ROOT) if os.path.isdir(APACHE_ROOT) else []
    for f in conf_files:
        txt = read_file(f)
        report["files"].append({"path": f, "size": len(txt) if txt else 0})

    for d in (os.path.join(APACHE_ROOT,"sites-available"), os.path.join(APACHE_ROOT,"sites-enabled")):
        if os.path.isdir(d):
            for fn in sorted(os.listdir(d)):
                full = os.path.join(d, fn)
                txt = read_file(full) or ""
                vhs = parse_vhosts_from_file(full, txt)
                if vhs:
                    report["vhosts"].extend(vhs)

    main_conf = read_file(os.path.join(APACHE_ROOT,"apache2.conf")) or ""
    includes = find_includes(main_conf)
    resolved_includes = []
    for inc in includes:
        if "*" in inc:
            pattern = os.path.join(APACHE_ROOT, inc)
            for p in glob.glob(pattern):
                resolved_includes.append(p)
        else:
            resolved_includes.append(normalize_path(inc, APACHE_ROOT))
    report["includes"] = resolved_includes

    all_text = main_conf
    for p in resolved_includes:
        t = read_file(p) or ""
        all_text += "\n" + t
    report["issues"] = detect_global_issues(all_text)

    for v in report["vhosts"]:
        cert = v.get("ssl_cert")
        key = v.get("ssl_key")
        if cert:
            v["ssl_cert_exists"] = os.path.exists(cert)
        if key:
            v["ssl_key_exists"] = os.path.exists(key)
        if v.get("document_root"):
            v["document_root_exists"] = os.path.exists(v["document_root"])

    print(json.dumps(report, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()