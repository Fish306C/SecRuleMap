# src/mini_zap/utils/http.py
from typing import Optional, Dict, Any
import requests
from requests.adapters import HTTPAdapter, Retry

def make_session(
    timeout: int = 10,
    retries: int = 3,
    backoff_factor: float = 0.3,
    status_forcelist: tuple = (500, 502, 503, 504),
    user_agent: str = "mini_zap/0.1",
    proxies: Optional[Dict[str, str]] = None,
    verify: bool = True,
) -> requests.Session:
    session = requests.Session()
    session.headers.update({"User-Agent": user_agent})
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.request_timeout = timeout  # type: ignore[attr-defined]
    if proxies:
        session.proxies.update(proxies)
    session.verify = verify
    return session

def _resolve_timeout(session: requests.Session, timeout: Optional[int]) -> int:
    return timeout if timeout is not None else getattr(session, "request_timeout", 40)

def get(session: requests.Session, url: str, **kwargs) -> requests.Response:
    timeout = kwargs.pop("timeout", None)
    resolved = _resolve_timeout(session, timeout)
    return session.get(url, timeout=resolved, **kwargs)

def post(session: requests.Session, url: str, data: Any = None, json: Any = None, **kwargs) -> requests.Response:
    timeout = kwargs.pop("timeout", None)
    resolved = _resolve_timeout(session, timeout)
    return session.post(url, data=data, json=json, timeout=resolved, **kwargs)
