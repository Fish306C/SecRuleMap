# src/mini_zap/utils/logging.py
from __future__ import annotations
import logging
from typing import Optional
def setup_logging(level: str = "INFO", logfile: Optional[str] = None, console: bool = True) -> None:
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    root = logging.getLogger()
    if root.handlers:
        return
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    if console:
        ch = logging.StreamHandler()
        ch.setLevel(numeric_level)
        ch.setFormatter(formatter)
        root.addHandler(ch)
    if logfile:
        fh = logging.FileHandler(logfile)
        fh.setLevel(numeric_level)
        fh.setFormatter(formatter)
        root.addHandler(fh)
    root.setLevel(numeric_level)
def get_logger(name: Optional[str] = None) -> logging.Logger:
    return logging.getLogger(name or "mini_zap")
logger = get_logger("mini_zap")
