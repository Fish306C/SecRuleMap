#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Apache Configuration & Environment Collector (auto-path + extra scans)

- Auto-detect Apache config root (APACHE_ROOT env or possible paths)
- Collect:
  - modules (LoadModule)
  - includes (Include / IncludeOptional)
  - directives (common ones)
  - <Directory> blocks
  - envvars (/etc/apache2/envvars)
  - document roots (DocumentRoot)
  - runtime paths (pid, lock, scoreboard, core dump)
  - SSL cert/key file paths referenced in config (SSLCertificateFile, SSLCertificateKeyFile)
  - system user info (apache user from envvars, /etc/passwd, /etc/shadow if readable)
  - extra scans: /var/www, /var/log/apache2, /var/run/apache2, /etc/ssl, /etc/pki
  - permissions summary for scanned directories
- Output: JSON (structured facts only, no policy logic)
"""

from pathlib import Path
import os
import re
import json
import stat
import pwd
import grp
import itertools

# ----------------------------
# Config: detection paths
# ----------------------------
POSSIBLE_PATHS = [
    "/etc/apache2",                 # Debian/Ubuntu
    "/usr/local/apache2/conf",      # compiled from source (default)
    "/usr/local/etc/apache2",
    "/etc/httpd",                   # CentOS/RHEL layout (may contain conf)
    "/usr/pkg/etc/httpd",
    "/opt/apache2/conf",
    "/Applications/MAMP/conf/apache" # macOS MAMP
]

# Extra system paths to scan (if exist) — used for rules in 3.x and 7.x etc.
EXTRA_PATHS = [
    "/var/www",             # document roots
    "/var/log/apache2",     # logs (Debian)
    "/var/log/httpd",       # logs (CentOS)
    "/var/run/apache2",     # pid, scoreboard, runtime dir (Debian)
    "/var/run",             # fallback
    "/var/lock/apache2",    # lock dir
    "/run/apache2",         # runtime dir
    "/etc/ssl",             # SSL certs (common)
    "/etc/pki/tls",         # SSL certs (RHEL/CentOS)
    "/etc/logrotate.d",     # logrotate conf (check for apache2)
    "/home",                # possible userdir content
]

# Give control via envvar
APACHE_ROOT = os.environ.get("APACHE_ROOT")
if not APACHE_ROOT:
    for p in POSSIBLE_PATHS:
        if os.path.isdir(p):
            APACHE_ROOT = p
            break

if not APACHE_ROOT:
    print(json.dumps({"error": "Apache config root not found. Set APACHE_ROOT or mount a path."}))
    raise SystemExit(1)

# ----------------------------
# Helpers
# ----------------------------
def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""

def list_conf_files(root: str):
    rootp = Path(root)
    files = []
    for p in rootp.rglob("*"):
        if p.is_file() and (p.suffix in (".conf", ".load", ".cnf") or p.name in ("envvars",)):
            files.append(str(p))
    return sorted(files)

def parse_loadmodules_from_text(text):
    mods = []
    for line in text.splitlines():
        m = re.match(r'^\s*LoadModule\s+(\S+)\s+(\S+)', line, re.IGNORECASE)
        if m:
            mods.append({"name": m.group(1), "path": m.group(2), "line": line.strip()})
    return mods

def parse_includes_from_text(text):
    incs = []
    for m in re.finditer(r'^\s*Include(?:Optional)?\s+(.+)$', text, re.IGNORECASE | re.MULTILINE):
        raw = m.group(1).strip().strip('"').strip("'")
        incs.append(raw)
    return incs

def parse_directives_from_text(text, patterns):
    directives = {}
    for p in patterns:
        vals = []
        for line in text.splitlines():
            m = re.match(rf'^\s*{re.escape(p)}\s+(.+)$', line, re.IGNORECASE)
            if m:
                vals.append(m.group(1).strip())
        if vals:
            directives[p] = vals if len(vals) > 1 else vals[0]
    return directives

def parse_directory_blocks_from_text(text):
    blocks = []
    # simple regex to extract Directory blocks
    for m in re.finditer(r'(?is)<Directory\s+([^>]+)>(.*?)</Directory>', text):
        path = m.group(1).strip()
        body = m.group(2)
        options = re.findall(r'^\s*Options\s+(.+)$', body, re.IGNORECASE | re.MULTILINE)
        allow = re.findall(r'^\s*AllowOverride\s+(.+)$', body, re.IGNORECASE | re.MULTILINE)
        require = re.findall(r'^\s*Require\s+(.+)$', body, re.IGNORECASE | re.MULTILINE)
        blocks.append({"path": path, "options": options, "allow_override": allow, "require": require})
    return blocks

def extract_directive_values(text, name):
    vals = []
    for line in text.splitlines():
        m = re.match(rf'^\s*{re.escape(name)}\s+(.+)$', line, re.IGNORECASE)
        if m:
            vals.append(m.group(1).strip().strip('"').strip("'"))
    return vals

def stat_summary(path: Path):
    summary = {"exists": path.exists()}
    try:
        st = path.stat()
        mode = stat.S_IMODE(st.st_mode)
        summary.update({
            "is_file": path.is_file(),
            "is_dir": path.is_dir(),
            "uid": st.st_uid,
            "gid": st.st_gid,
            "mode_octal": oct(mode),
            "world_writable": bool(mode & 0o002),
            "group_writable": bool(mode & 0o020)
        })
    except Exception as e:
        summary["stat_error"] = str(e)
    return summary

def scan_directory_listing(path: Path, limit=50):
    out = {"exists": path.exists(), "total_entries": 0, "sample": []}
    if not path.exists() or not path.is_dir():
        return out
    try:
        entries = list(path.iterdir())
        out["total_entries"] = len(entries)
        sample = []
        for e in entries[:limit]:
            try:
                st = e.stat()
                sample.append({
                    "name": e.name,
                    "is_dir": e.is_dir(),
                    "is_file": e.is_file(),
                    "uid": st.st_uid,
                    "gid": st.st_gid,
                    "mode": oct(stat.S_IMODE(st.st_mode))
                })
            except Exception:
                sample.append({"name": e.name, "error": "stat_failed"})
        out["sample"] = sample
    except Exception as ex:
        out["error"] = str(ex)
    return out

def read_passwd(username):
    try:
        with open("/etc/passwd", "r", encoding="utf-8") as f:
            for l in f:
                if l.startswith(username + ":"):
                    parts = l.strip().split(":")
                    return {"user": parts[0], "uid": int(parts[2]), "gid": int(parts[3]), "gecos": parts[4], "home": parts[5], "shell": parts[6]}
    except Exception:
        return None

def read_shadow(username):
    try:
        with open("/etc/shadow", "r", encoding="utf-8") as f:
            for l in f:
                if l.startswith(username + ":"):
                    parts = l.strip().split(":")
                    return {"user": parts[0], "passwd_field": parts[1]}
    except Exception:
        return None

def uniq_by_key(seq, key):
    seen = set()
    out = []
    for item in seq:
        k = item.get(key)
        if k not in seen:
            seen.add(k)
            out.append(item)
    return out

# ----------------------------
# Collector
# ----------------------------
def collect(apache_root):
    root = Path(apache_root)
    conf_files = list_conf_files(apache_root)

    report = {
        "apache_root": apache_root,
        "files_scanned": len(conf_files),
        "files": conf_files,
        "modules": [],
        "includes": [],
        "directives": {},
        "directory_blocks": [],
        "envvars": {},
        "document_roots": [],
        "runtime": {},
        "ssl": {"certs": [], "keys": []},
        "users": {},
        "permissions_summary": {},
        "extra_scans": {}
    }

    # read all text combined (for global searches)
    all_text = ""
    for fp in conf_files:
        txt = read_text(Path(fp))
        all_text += "\n" + txt

        report["modules"].extend(parse_loadmodules_from_text(txt))
        report["includes"].extend(parse_includes_from_text(txt))
        report["directory_blocks"].extend(parse_directory_blocks_from_text(txt))
        # collect directives incremental
        directives = parse_directives_from_text(txt, [
            "ServerTokens", "ServerSignature", "Timeout", "KeepAlive",
            "MaxKeepAliveRequests", "KeepAliveTimeout", "LogLevel",
            "User", "Group", "ErrorLog", "PidFile", "ScoreBoardFile",
            "AccessFileName", "HostnameLookups", "CoreDumpDirectory",
            "SSLCertificateFile", "SSLCertificateKeyFile", "SSLProtocol", "SSLCipherSuite"
        ])
        # merge: keep earlier values unless new ones
        for k, v in directives.items():
            if k not in report["directives"]:
                report["directives"][k] = v
            else:
                # if multiple, ensure list
                existing = report["directives"][k]
                if isinstance(existing, list):
                    if isinstance(v, list):
                        existing.extend(v)
                    else:
                        existing.append(v)
                    report["directives"][k] = existing
                else:
                    if existing != v:
                        report["directives"][k] = [existing, v]

    # dedupe modules by name
    report["modules"] = uniq_by_key(report["modules"], "name")
    report["includes"] = sorted(list(set(report["includes"])))
    report["directory_blocks"] = report["directory_blocks"]  # as collected

    # envvars
    envvars_path = root / "envvars"
    if envvars_path.exists():
        for line in read_text(envvars_path).splitlines():
            m = re.match(r'^\s*export\s+(\w+)\s*=\s*"?([^"\s#]+)"?', line)
            if m:
                report["envvars"][m.group(1)] = m.group(2)

    # document roots
    docroots = set()
    docroots.update(extract_directive_values(all_text, "DocumentRoot"))
    # also try parse vhost confs: <VirtualHost> ... DocumentRoot inside
    for m in re.finditer(r'(?is)<VirtualHost\b[^>]*>(.*?)</VirtualHost>', all_text):
        body = m.group(1)
        docroots.update(extract_directive_values(body, "DocumentRoot"))
    report["document_roots"] = sorted(list(docroots))

    # runtime/pid/scoreboard/core dump/lock dir from directives or envvars
    pidfiles = []
    pidfiles.extend(extract_directive_values(all_text, "PidFile"))
    if "APACHE_PID_FILE" in report["envvars"]:
        pidfiles.append(report["envvars"]["APACHE_PID_FILE"])
    report["runtime"]["pid_files"] = [p for p in pidfiles if p]

    scoreboard = extract_directive_values(all_text, "ScoreBoardFile")
    report["runtime"]["scoreboard_files"] = scoreboard

    coredirs = extract_directive_values(all_text, "CoreDumpDirectory")
    if "APACHE_RUN_DIR" in report["envvars"]:
        # sometimes core uses APACHE_RUN_DIR
        coredirs.append(report["envvars"]["APACHE_RUN_DIR"])
    report["runtime"]["core_directories"] = [p for p in coredirs if p]

    # lock dir
    lockdirs = []
    # try parse Mutex file: file:${APACHE_LOCK_DIR}
    if "APACHE_LOCK_DIR" in report["envvars"]:
        lockdirs.append(report["envvars"]["APACHE_LOCK_DIR"])
    report["runtime"]["lock_directories"] = lockdirs

    # SSL cert/key list from collected directives
    ssl_certs = []
    ssl_keys = []
    if "SSLCertificateFile" in report["directives"]:
        vals = report["directives"]["SSLCertificateFile"]
        if isinstance(vals, list):
            ssl_certs.extend(vals)
        else:
            ssl_certs.append(vals)
    if "SSLCertificateKeyFile" in report["directives"]:
        vals = report["directives"]["SSLCertificateKeyFile"]
        if isinstance(vals, list):
            ssl_keys.extend(vals)
        else:
            ssl_keys.append(vals)

    # also scan vhosts for SSLCertificate* (already covered via combined all_text but just in case)
    report["ssl"]["certs"] = []
    report["ssl"]["keys"] = []
    for c in ssl_certs:
        p = Path(c) if os.path.isabs(c) else Path(APACHE_ROOT) / c
        report["ssl"]["certs"].append({"path": str(p), **stat_summary(p)})
    for k in ssl_keys:
        p = Path(k) if os.path.isabs(k) else Path(APACHE_ROOT) / k
        report["ssl"]["keys"].append({"path": str(p), **stat_summary(p)})

    # user info (apache user)
    apache_user = None
    if "APACHE_RUN_USER" in report["envvars"]:
        apache_user = report["envvars"]["APACHE_RUN_USER"]
    else:
        # fallback common user
        for guess in ("www-data", "apache", "httpd", "www"):
            try:
                pwd.getpwnam(guess)
                apache_user = guess
                break
            except KeyError:
                continue
    report["users"]["apache_user_guess"] = apache_user
    if apache_user:
        passwd_info = read_passwd(apache_user)
        shadow_info = read_shadow(apache_user)
        report["users"]["apache_user_passwd"] = passwd_info
        report["users"]["apache_user_shadow"] = None
        if shadow_info is not None:
            # only include a boolean locked indicator, not the hash
            pwfield = shadow_info.get("passwd_field")
            report["users"]["apache_user_shadow"] = {"locked": pwfield.startswith("!") or pwfield.startswith("*")}
        else:
            report["users"]["apache_user_shadow"] = {"available": False}

    # permissions summary for apache_root
    report["permissions_summary"] = summarize_permissions_dir(Path(APACHE_ROOT))

    # scan extra paths
    extra = {}
    for p in EXTRA_PATHS:
        try:
            pathp = Path(p)
            extra[p] = {
                "exists": pathp.exists(),
                "stat": stat_summary(pathp),
                "listing": scan_directory_listing(pathp, limit=40) if pathp.is_dir() else None
            }
        except Exception as ex:
            extra[p] = {"error": str(ex)}
    # also include document roots specifically
    for dr in report["document_roots"]:
        dp = Path(dr)
        if not str(dp) in extra:
            extra[str(dp)] = {
                "exists": dp.exists(),
                "stat": stat_summary(dp),
                "listing": scan_directory_listing(dp, limit=40) if dp.is_dir() else None
            }

    report["extra_scans"] = extra

    # runtime file stats (pid/scoreboard/lock/core)
    runtime_checks = {}
    for k, arr in (("pid_files", report["runtime"].get("pid_files", [])),
                   ("scoreboard_files", report["runtime"].get("scoreboard_files", [])),
                   ("core_directories", report["runtime"].get("core_directories", [])),
                   ("lock_directories", report["runtime"].get("lock_directories", []))):
        runtime_checks[k] = []
        for path in arr:
            # expand env vars like ${APACHE_RUN_DIR}
            expanded = expand_path(path, report["envvars"])
            p = Path(expanded)
            runtime_checks[k].append({"path": expanded, **stat_summary(p)})
    report["runtime"]["resolved"] = runtime_checks

    # logrotate check for apache
    lr_path = Path("/etc/logrotate.d")
    report["logrotate_apache"] = False
    if lr_path.exists():
        for f in lr_path.glob("apache*"):
            report["logrotate_apache"] = True
            break

    return report

# ----------------------------
# Utility helpers used in collect
# ----------------------------
def extract_directive_values(text, name):
    vals = []
    for line in text.splitlines():
        m = re.match(rf'^\s*{re.escape(name)}\s+(.+)$', line, re.IGNORECASE)
        if m:
            vals.append(m.group(1).strip().strip('"').strip("'"))
    return vals

def summarize_permissions_dir(path: Path):
    stats = {"total": 0, "owned_by_root": 0, "gid_root": 0, "world_writable": 0, "group_writable": 0}
    if not path.exists():
        return stats
    for p in itertools.islice(path.rglob("*"), 0, None):
        try:
            st = p.stat()
        except Exception:
            continue
        stats["total"] += 1
        if st.st_uid == 0:
            stats["owned_by_root"] += 1
        if st.st_gid == 0:
            stats["gid_root"] += 1
        mode = stat.S_IMODE(st.st_mode)
        if mode & 0o002:
            stats["world_writable"] += 1
        if mode & 0o020:
            stats["group_writable"] += 1
    return stats

def expand_path(path_str, envvars):
    if not path_str:
        return path_str
    p = path_str
    # replace ${VAR} style
    for k, v in envvars.items():
        p = p.replace("${" + k + "}", v)
    # simple replacement for $VAR
    for k, v in envvars.items():
        p = p.replace("$" + k, v)
    return p

# ----------------------------
# Entry point
# ----------------------------
if __name__ == "__main__":
    out = collect(APACHE_ROOT)
    print(json.dumps(out, indent=2, ensure_ascii=False))
