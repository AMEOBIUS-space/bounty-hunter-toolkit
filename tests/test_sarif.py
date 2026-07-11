"""Tests for SARIF export."""
import json
import tempfile
from pathlib import Path
from sarif_export import generate_sarif, scan_file, all_patterns


def test_generate_sarif_structure():
    """SARIF output has required top-level fields."""
    sarif = generate_sarif([], all_patterns())
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert "tool" in run
    assert "results" in run


def test_sarif_has_rules():
    """SARIF contains rules for all patterns."""
    patterns = all_patterns()
    sarif = generate_sarif([], patterns)
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == len(patterns)


def test_scan_detects_sql_injection():
    """Scanning a file with vulnerable code produces a finding."""
    patterns = all_patterns()
    # Write a vulnerable file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        # Get the sql_injection bad snippet
        if "sql_injection" in patterns:
            f.write(patterns["sql_injection"].bad)
            f.flush()
            results = scan_file(f.name, patterns)
            assert any(r["ruleId"] == "sql_injection" for r in results), \
                "Expected sql_injection finding"


def test_scan_clean_file_no_findings():
    """Clean file produces no findings."""
    patterns = all_patterns()
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write("x = 1\nprint(x)\n")
        f.flush()
        results = scan_file(f.name, patterns)
        assert len(results) == 0


def test_sarif_locations_have_physical_location():
    """Each finding has a proper location with startLine."""
    patterns = all_patterns()
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        if "sql_injection" in patterns:
            f.write(patterns["sql_injection"].bad)
            f.flush()
            results = scan_file(f.name, patterns)
            for r in results:
                assert "locations" in r
                loc = r["locations"][0]
                assert "physicalLocation" in loc
                assert "region" in loc["physicalLocation"]
                assert "startLine" in loc["physicalLocation"]["region"]
                assert loc["physicalLocation"]["region"]["startLine"] > 0
