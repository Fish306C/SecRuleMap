# src/mini_zap/rules/schemas.py
"""
Placeholder schema definitions for rules (can be expanded and validated with jsonschema).
Example rule fields: id, title, check, header, severity, message
"""
RULE_TEMPLATE = {
    "id": "string",
    "title": "string",
    "check": "string",  # e.g., header_exists, resource_exposed
    "severity": "string",
    "data": {}
}
