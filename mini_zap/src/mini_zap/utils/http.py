# src/mini_zap/utils/http.py
import requests
from requests.exceptions import RequestException, ConnectionError as ReqConnError, ReadTimeout
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from typing import Optional, Dict, Any
from .logging import get_logger
from bs4 import BeautifulSoup

logger = get_logger(__name__)

def make_session(timeout: int = 10, headers: Optional[Dict[str,str]] = None,
                 retries: int = 1, backoff_factor: float = 0.3) -> requests.Session:
    """
    Create a requests.Session with optional default headers, default_timeout attribute,
    and configured retry behaviour for transient errors.
    """
    s = requests.Session()
    s.headers.update(headers or {})
    setattr(s, "default_timeout", timeout)

    retry = Retry(
        total=max(0, int(retries)),
        connect=max(0, int(retries)),
        read=0,  # avoid retrying read timeouts by default to surface slow endpoints
        backoff_factor=backoff_factor,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET","POST","PUT","DELETE","HEAD","OPTIONS"])
    )
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s

def safe_get(session: requests.Session, url: str, **kwargs) -> Optional[requests.Response]:
    """
    Wrapped GET that returns None on request errors (and logs debug).
    """
    timeout = kwargs.pop("timeout", getattr(session, "default_timeout", 10))
    try:
        return session.get(url, timeout=timeout, allow_redirects=True, **kwargs)
    except ReadTimeout as e:
        logger.debug(f"ReadTimeout GET {url}: {e}")
        return None
    except ReqConnError as e:
        logger.debug(f"ConnectionError GET {url}: {e}")
        return None
    except RequestException as e:
        logger.debug(f"RequestException GET {url}: {e}")
        return None

def safe_post(session: requests.Session, url: str, data: Optional[Dict[str,Any]] = None, json: Optional[Any] = None, **kwargs) -> Optional[requests.Response]:
    timeout = kwargs.pop("timeout", getattr(session, "default_timeout", 10))
    try:
        return session.post(url, data=data, json=json, timeout=timeout, allow_redirects=True, **kwargs)
    except ReadTimeout as e:
        logger.debug(f"ReadTimeout POST {url}: {e}")
        return None
    except ReqConnError as e:
        logger.debug(f"ConnectionError POST {url}: {e}")
        return None
    except RequestException as e:
        logger.debug(f"RequestException POST {url}: {e}")
        return None

def get(session: requests.Session, url: str, **kwargs) -> requests.Response:
    """
    Backwards-compatible wrapper named `get`. This will raise RequestException on failure.
    Use safe_get if you prefer None on error.
    """
    timeout = kwargs.pop("timeout", getattr(session, "default_timeout", 10))
    resp = session.get(url, timeout=timeout, allow_redirects=True, **kwargs)
    return resp

# Authentication / helpers
def apply_bearer_token(session: requests.Session, token: str) -> None:
    if not token:
        return
    session.headers.update({"Authorization": f"Bearer {token}"})
    logger.debug("Applied bearer token to session headers")

def apply_basic_auth(session: requests.Session, username: str, password: str) -> None:
    if username is None or password is None:
        return
    session.auth = (username, password)
    logger.debug("Applied basic auth to session")

def _extract_csrf_field(html_text: str) -> Optional[tuple]:
    """
    Try to find a hidden input that looks like CSRF (common names: _csrf, csrfToken).
    Returns tuple (field_name, value) or None.
    """
    try:
        soup = BeautifulSoup(html_text, "html.parser")
        for inp in soup.find_all("input", {"type": "hidden"}):
            name = inp.get("name", "")
            if name and ("csrf" in name.lower() or "_csrf" in name.lower() or "token" in name.lower()):
                return (name, inp.get("value", ""))
    except Exception:
        pass
    return None

def perform_form_login(session: requests.Session,
                       login_url: str,
                       username_field: str,
                       password_field: str,
                       username: str,
                       password: str,
                       success_indicator: Optional[str] = None) -> bool:
    """
    Simple form-login helper:
      - GET login_url (to acquire cookies / CSRF token if any),
      - POST username/password fields (and CSRF if detected),
      - follow redirects and check session.cookies for authentication cookie (e.g., 'tokenuser').
    Returns True when login appears successful (cookie set, redirect, or optional success_indicator found).
    """
    if not login_url or username is None or password is None:
        logger.debug("Missing parameters for form login")
        return False

    # 1) GET login page to prime cookies and possibly capture CSRF token
    r_get = safe_get(session, login_url)
    csrf_pair = None
    if r_get and getattr(r_get, "text", None):
        csrf_pair = _extract_csrf_field(r_get.text or "")

    # 2) Prepare payload
    payload = {username_field: username, password_field: password}
    if csrf_pair and csrf_pair[0] not in payload:
        payload[csrf_pair[0]] = csrf_pair[1]

    # 3) POST credentials
    headers = {"User-Agent": "mini_zap/1.0"}
    r_post = safe_post(session, login_url, data=payload, headers=headers)

    if r_post is None:
        logger.debug(f"Form login POST returned None for {login_url}")
        return False

    # 4) If redirected (common for successful login)
    if 300 <= getattr(r_post, "status_code", 0) < 400:
        logger.debug(f"Form login returned redirect ({r_post.status_code}) — treating as success")
        logger.debug(f"Session cookies after login: {session.cookies.get_dict()}")
        return True

    # 5) Look for success indicator in body (optional)
    body = (r_post.text or "").lower()
    if success_indicator and success_indicator.lower() in body:
        logger.debug("Found success indicator in response body after login")
        return True

    # 6) Inspect cookies set by server — prefer explicit cookie names like tokenuser or connect.sid
    ck = session.cookies.get_dict()
    if ck:
        logger.debug(f"Cookies set after login: {ck}")
        # heuristic: if tokenuser present or any fairly long cookie value -> success
        if "tokenuser" in ck or "connect.sid" in ck or any(len(v) > 10 for v in ck.values()):
            return True
        # otherwise still treat any cookie set as potential success
        return True

    logger.debug("No cookies found after form login and no redirect or success indicator; login likely failed")
    return False
