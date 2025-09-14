# src/mini_zap/reporting/html_reporter.py
import os
from jinja2 import Environment, FileSystemLoader, select_autoescape
from typing import List, Dict, Any

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")
TEMPLATE_NAME = "report.html.j2"

def write_html_report(path: str, start_url: str, results: List[Dict[str, Any]]) -> None:
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR), autoescape=select_autoescape(["html","xml"]))
    tpl = env.get_template(TEMPLATE_NAME)
    html = tpl.render(start_url=start_url, results=results)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
