# src/mini_zap/utils/cache.py
from pathlib import Path
from typing import Any, Optional, Dict
import json
import time

class FileCache:
    def __init__(self, path: str = "~/.mini_zap/cache.json", autosave: bool = True):
        self.path = Path(path).expanduser()
        self.autosave = autosave
        self._data: Dict[str, Dict[str, Any]] = {}
        if self.path.exists():
            try:
                text = self.path.read_text(encoding="utf-8")
                self._data = json.loads(text) or {}
            except Exception:
                self._data = {}

    def _persist(self) -> None:
        if not self.path.parent.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._data, indent=2, ensure_ascii=False), encoding="utf-8")

    def get(self, key: str) -> Optional[Any]:
        entry = self._data.get(key)
        if not entry:
            return None
        expires = entry.get("expires")
        if expires and time.time() > expires:
            try:
                del self._data[key]
            except KeyError:
                pass
            if self.autosave:
                self._persist()
            return None
        return entry.get("value")

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        obj: Dict[str, Any] = {"value": value}
        if ttl:
            obj["expires"] = int(time.time()) + int(ttl)
        else:
            obj["expires"] = None
        self._data[key] = obj
        if self.autosave:
            self._persist()

    def delete(self, key: str) -> None:
        if key in self._data:
            del self._data[key]
            if self.autosave:
                self._persist()

    def clear(self) -> None:
        self._data = {}
        if self.autosave:
            self._persist()
