from typing import List, Dict, Any
from .registry import registry
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from utils.logging import get_logger

logger = get_logger(__name__)

# Giả định rules được load từ rules_dir (tích hợp với orchestrator.py)
def load_a06_rules(rules: Dict[str, Any]) -> List[Dict]:
    return [rule for rule in rules.values() if rule.get("category") == "A06"]

@registry.register("A06_Version_Leak_Headers", check_type="version_leak")
def check_version_leak_headers(url: str, session: requests.Session, rules: Dict[str, Any] = None) -> List[Dict]:
    findings = []
    try:
        resp = session.get(url, timeout=10)
        headers = resp.headers
        a06_rules = load_a06_rules(rules) if rules else []
        
        for rule in a06_rules:
            if rule.get("type") == "version_leak" and rule.get("target", {}).get("header"):
                header_name = rule["target"]["header"]
                if header_name in headers:
                    header_value = headers[header_name]
                    condition = rule.get("assertion", {}).get("condition")
                    value = rule.get("assertion", {}).get("value", "")
                    
                    if condition == "contains" and any(v in header_value for v in value.split("|")):
                        findings.append({
                            "type": "version_leak",
                            "detail": f"Header {header_name}: {header_value} exposes version info",
                            "ruleId": rule["ruleId"],
                            "severity": rule["severity"]
                        })
    except Exception as e:
        logger.error(f"Error checking headers for {url}: {e}")
    return findings

@registry.register("A06_Version_Leak_Body", check_type="version_leak")
def check_version_leak_body(url: str, session: requests.Session, rules: Dict[str, Any] = None) -> List[Dict]:
    findings = []
    try:
        resp = session.get(url, timeout=10)
        soup = BeautifulSoup(resp.text, "html.parser")
        a06_rules = load_a06_rules(rules) if rules else []
        
        for rule in a06_rules:
            if rule.get("type") == "version_leak" and rule.get("target", {}).get("body"):
                target = rule["target"]["body"]  # e.g., "meta[name=generator]"
                condition = rule.get("assertion", {}).get("condition")
                value = rule.get("assertion", {}).get("value", "")
                
                if target.startswith("meta"):
                    meta_name = target.split("name=")[1].strip("]'")
                    meta = soup.find("meta", {"name": meta_name})
                    if meta and condition == "contains" and any(v in meta.get("content", "") for v in value.split("|")):
                        findings.append({
                            "type": "version_leak",
                            "detail": f"Meta tag {meta_name}: {meta.get('content')} exposes version info",
                            "ruleId": rule["ruleId"],
                            "severity": rule["severity"]
                        })
                # Thêm logic cho comments hoặc script tags nếu cần
    except Exception as e:
        logger.error(f"Error checking body for {url}: {e}")
    return findings

# Placeholder cho component-based checks (tích hợp sau khi có components/)
@registry.register("A06_Component_No_Known_Vulns", check_type="component_no_known_vulns")
def check_no_known_vulns(url: str, session: requests.Session, inventory: List[Dict] = None, **kwargs) -> List[Dict]:
    findings = []
    if not inventory:
        logger.debug("No inventory provided for component_no_known_vulns check")
        return findings
    # TODO: Query CVE database (e.g., OSSIndex) cho inventory[{ecosystem, name, version}]
    return findings

# Tương tự cho các check khác: component_stale, component_abandoned, etc.