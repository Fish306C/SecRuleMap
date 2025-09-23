# src/mini_zap/scanner/spider.py
from typing import Set
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from ..utils.logging import get_logger
from ..utils.http import safe_get

logger = get_logger(__name__)

def _is_same_domain(start_url: str, candidate: str) -> bool:
    try:
        return urlparse(start_url).netloc == urlparse(candidate).netloc
    except Exception:
        return False

# Keywords which indicate state-changing or non-HTTP GET endpoints we should skip
_SKIP_KEYWORDS = (
    "logout", "signout", "dangxuat",       # logging out
    "xoagiohang", "add-to-cart", "addtocart", "remove", "delete",  # cart / destructive actions
    "checkout", "pay", "vnpay",            # payment / checkout callbacks
    "ws", "websocket", "socket", "chat"    # websockets / chat / long-polling
)

def _should_skip_href(href: str) -> bool:
    if not href:
        return True
    h = href.lower()
    # obvious non-http actions
    if h.startswith("javascript:") or h.startswith("#") or h.startswith("mailto:") or h.startswith("tel:"):
        return True
    # skip if contains any of skip keywords
    for kw in _SKIP_KEYWORDS:
        if kw in h:
            return True
    return False

def crawl(start_url: str, session, max_pages: int = 50, same_domain: bool = True) -> Set[str]:
    """
    Simple BFS crawler returning a set of absolute URLs.

    Uses safe_get(session, url) so network errors don't raise. Avoids crawling
    links likely to change server state (logout, cart mutations, payment callbacks)
    or non-HTTP endpoints (websockets).
    """
    visited = set()
    queue = [start_url]

    while queue and len(visited) < max_pages:
        url = queue.pop(0)
        if url in visited:
            continue

        try:
            logger.info(f"Crawling {url}")
            # debug: show cookie keys so we can verify session auth persists
            try:
                ck = session.cookies.get_dict()
                if ck:
                    logger.debug(f"Session cookies keys before GET {url}: {list(ck.keys())}")
            except Exception:
                # session may not be a real requests.Session, ignore errors
                pass

            r = safe_get(session, url)
            visited.add(url)

            if r is None:
                logger.debug(f"No response for {url} (timeout/connection error).")
                continue

            # only parse HTML/text responses
            content_type = (r.headers.get("Content-Type") or "").lower()
            if "html" not in content_type and "text" not in content_type:
                logger.debug(f"Skipping non-HTML content at {url} (Content-Type: {content_type}).")
                continue

            if r.status_code != 200:
                logger.debug(f"Skipping {url} due to status {r.status_code}")
                continue

            soup = BeautifulSoup(r.text or "", "lxml")
            for a in soup.find_all("a", href=True):
                href = a.get("href").strip()
                if _should_skip_href(href):
                    logger.debug(f"Skipping href '{href}' (matched skip rule).")
                    continue

                abs_url = urljoin(url, href)
                # same domain enforcement
                if same_domain and not _is_same_domain(start_url, abs_url):
                    logger.debug(f"Skipping external link {abs_url}")
                    continue

                # normalize (remove trailing slash duplicates)
                norm = abs_url.rstrip("/")

                if norm not in visited and norm not in queue:
                    queue.append(norm)

        except Exception as e:
            logger.debug(f"Failed crawling {url}: {e}", exc_info=True)
            # still add url to visited to avoid infinite loop
            visited.add(url)

    return visited
