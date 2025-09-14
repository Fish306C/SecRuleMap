# src/mini_zap/scanner/spider.py
from typing import Set
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from ..utils.logging import get_logger
from ..utils.http import get as session_get

logger = get_logger(__name__)

def _is_same_domain(start_url: str, candidate: str) -> bool:
    try:
        return urlparse(start_url).netloc == urlparse(candidate).netloc
    except Exception:
        return False

def crawl(start_url: str, session, max_pages: int = 50, same_domain: bool = True) -> Set[str]:
    """
    Simple BFS crawler returning a set of absolute URLs.
    """
    visited = set()
    queue = [start_url]

    while queue and len(visited) < max_pages:
        url = queue.pop(0)
        if url in visited:
            continue
        try:
            logger.info(f"Crawling {url}")
            r = session_get(session, url)
            visited.add(url)
            if r.status_code != 200:
                continue
            soup = BeautifulSoup(r.text or "", "lxml")
            for a in soup.find_all("a", href=True):
                href = a.get("href").strip()
                if href.startswith("javascript:") or href.startswith("#") or href.lower().startswith("mailto:"):
                    continue
                abs_url = urljoin(url, href)
                if same_domain and not _is_same_domain(start_url, abs_url):
                    continue
                if abs_url not in visited and abs_url not in queue:
                    queue.append(abs_url)
        except Exception as e:
            logger.debug(f"Failed crawling {url}: {e}")
            visited.add(url)
    return visited
