from typing import Callable, Dict, List
from utils.logging import get_logger

logger = get_logger(__name__)

class ProbeRegistry:
    def __init__(self):
        self.probes: Dict[str, Callable] = {}  # probe_id -> function

    def register(self, probe_id: str, check_type: str = None):
        def decorator(func: Callable):
            self.probes[probe_id] = {"func": func, "check_type": check_type}
            logger.debug(f"Registered probe: {probe_id} (type: {check_type})")
            return func
        return decorator

    def run_probes_for_type(self, check_type: str, url: str, session, **kwargs) -> List[Dict]:
        findings = []
        for probe_id, probe in self.probes.items():
            if probe["check_type"] == check_type:
                try:
                    result = probe["func"](url, session, **kwargs)
                    if result:
                        findings.append({"probe_id": probe_id, "findings": result})
                except Exception as e:
                    logger.error(f"Probe {probe_id} failed on {url}: {e}")
        return findings

    def run_all(self, url: str, session, **kwargs) -> List[Dict]:
        findings = []
        for probe_id, probe in self.probes.items():
            try:
                result = probe["func"](url, session, **kwargs)
                if result:
                    findings.append({"probe_id": probe_id, "findings": result})
            except Exception as e:
                logger.error(f"Probe {probe_id} failed on {url}: {e}")
        return findings