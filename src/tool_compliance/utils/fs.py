# src/mini_zap/utils/fs.py
from pathlib import Path
from typing import Any, Iterable, List, Optional
import json
import yaml
import io

def ensure_dir(path: str) -> Path:
    p = Path(path)
    if p.is_file():
        p = p.parent
    p.mkdir(parents=True, exist_ok=True)
    return p

def read_text(path: str, encoding: str = "utf-8") -> str:
    return Path(path).read_text(encoding=encoding)

def write_text(path: str, content: str, encoding: str = "utf-8") -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding=encoding)

def read_json(path: str) -> Any:
    text = read_text(path)
    return json.loads(text)

def write_json(path: str, obj: Any, ensure_ascii: bool = False, indent: int = 2) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, ensure_ascii=ensure_ascii, indent=indent), encoding="utf-8")

def read_yaml(path: str) -> Any:
    text = read_text(path)
    return yaml.safe_load(text)

def write_yaml(path: str, obj: Any) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(yaml.safe_dump(obj, sort_keys=False), encoding="utf-8")

def find_files(directory: str, patterns: Optional[Iterable[str]] = None) -> List[str]:
    p = Path(directory)
    if patterns is None:
        patterns = ["*"]
    results: List[str] = []
    for pat in patterns:
        for f in p.rglob(pat):
            if f.is_file():
                results.append(str(f))
    return results

def read_lines(path: str) -> List[str]:
    return Path(path).read_text(encoding="utf-8").splitlines()

def safe_open(path: str, mode: str = "r", encoding: str = "utf-8"):
    p = Path(path)
    if "w" in mode or "a" in mode or "x" in mode:
        p.parent.mkdir(parents=True, exist_ok=True)
    return io.open(str(p), mode=mode, encoding=encoding)
