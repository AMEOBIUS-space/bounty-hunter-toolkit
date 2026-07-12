"""Tests for CWE mapping on patterns."""

from apply_fix import all_patterns, CWE_MAP


def test_all_patterns_have_cwe():
    for name, p in all_patterns().items():
        assert p.cwe, f"{name}: missing CWE"
        assert p.cwe.startswith("CWE-"), f"{name}: invalid CWE format"


def test_all_patterns_have_severity():
    for name, p in all_patterns().items():
        assert p.severity in ("critical", "high", "medium", "low"), \
            f"{name}: invalid severity '{p.severity}'"


def test_cwe_map_covers_all_patterns():
    patterns = all_patterns()
    for name in patterns:
        assert name in CWE_MAP, f"{name}: not in CWE_MAP"


def test_sarif_rules_include_cwe():
    from sarif_export import _pattern_to_rule
    patterns = all_patterns()
    for name, p in patterns.items():
        rule = _pattern_to_rule(name, p)
        assert rule["properties"].get("cwe", "").startswith("CWE-"), \
            f"{name}: SARIF rule missing CWE"
