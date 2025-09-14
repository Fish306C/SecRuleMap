# src/mini_zap/rules/loader.py
from typing import Dict, Any
import os
import yaml
from ..utils.fs import find_files
from ..utils.logging import get_logger

logger = get_logger(__name__)

def load_rule_file(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)

def load_rules_from_dir(dirpath: str) -> Dict[str, Any]:
    rules = {}
    if not os.path.isdir(dirpath):
        logger.debug(f"Rules directory not found: {dirpath}")
        return rules
    files = find_files(dirpath, patterns=["*.yml","*.yaml"])
    for p in files:
        try:
            data = load_rule_file(p)
            rules[os.path.basename(p)] = data
            logger.debug(f"Loaded rule {p}")
        except Exception as e:
            logger.warning(f"Failed to load rule {p}: {e}")
    return rules
