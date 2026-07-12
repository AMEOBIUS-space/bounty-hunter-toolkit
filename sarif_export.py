"""SARIF 2.1.0 export for bounty-hunter-toolkit scan results.

Produces a SARIF file compatible with `github/codeql-action/upload-sarif`,
so findings appear in the Security tab of any GitHub repository.

Usage:
    python -m sarif_export scan --file app.py --output results.sarif
    python -m sarif_export scan --directory ./src --output results.sarif
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from apply_fix import all_patterns, FixPattern


def _pattern_to_rule(pattern_name: str, pattern: FixPattern) -> dict:
    """Convert a FixPattern to a SARIF rule object."""
    return {
        "id": pattern_name,
        "name": pattern_name.replace("_", " ").title(),
        "shortDescription": {"text": pattern.desc},
        "fullDescription": {"text": f"Detects vulnerable pattern in {pattern.lang} code and provides a fix."},
        "help": {"text": f"Replace the vulnerable snippet with the hardened version.", "markdown": f"**Vulnerable:**\n```\n{pattern.bad[:200]}\n```\n\n**Fixed:**\n```\n{pattern.good[:200]}\n```"},
        "properties": {
            "language": pattern.lang,
            "tags": ["security", pattern.lang, "vulnerability"],
            "cwe": getattr(pattern, "cwe", ""),
            "severity": getattr(pattern, "severity", "medium"),
        },
    }


def scan_file(file_path: str | Path, patterns: dict[str, FixPattern] | None = None) -> list[dict]:
    """Scan a file for all known patterns. Returns SARIF results."""
    if patterns is None:
        patterns = all_patterns()

    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    content = path.read_text(encoding="utf-8", errors="replace")
    results = []

    for name, pattern in patterns.items():
        if pattern.bad in content:
            line_num = content[: content.index(pattern.bad)].count("\n") + 1
            results.append({
                "ruleId": name,
                "level": "warning",
                "message": {"text": pattern.desc},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": str(path),
                            },
                            "region": {
                                "startLine": line_num,
                            },
                        }
                    }
                ],
                "fixes": [
                    {
                        "description": {"text": "Apply the secure fix pattern"},
                        "artifactChanges": [
                            {
                                "artifactLocation": {"uri": str(path)},
                                "replacements": [
                                    {
                                        "deletedRegion": {
                                            "startLine": line_num,
                                        },
                                        "insertedContent": {
                                            "text": pattern.good,
                                        },
                                    }
                                ],
                            }
                        ],
                    }
                ],
            })

    return results


def generate_sarif(results: list[dict], patterns: dict[str, FixPattern]) -> dict:
    """Generate a SARIF 2.1.0 document from scan results."""
    rules = [_pattern_to_rule(name, p) for name, p in patterns.items()]

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "bounty-hunter-toolkit",
                        "version": "1.4.0",
                        "informationUri": "https://github.com/AMEOBIUS-team/bounty-hunter-toolkit",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="SARIF export for bounty-hunter-toolkit")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Scan a file or directory and output SARIF")
    scan_p.add_argument("--file", help="Single file to scan")
    scan_p.add_argument("--directory", help="Directory to scan recursively")
    scan_p.add_argument("--output", "-o", default="results.sarif", help="Output SARIF file path")

    args = parser.parse_args()

    patterns = all_patterns()
    all_results = []

    if args.file:
        all_results.extend(scan_file(args.file, patterns))
    elif args.directory:
        for py_file in Path(args.directory).rglob("*.py"):
            all_results.extend(scan_file(py_file, patterns))
    else:
        print("Error: --file or --directory required", file=sys.stderr)
        sys.exit(1)

    sarif = generate_sarif(all_results, patterns)

    output_path = Path(args.output)
    output_path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    print(f"SARIF: {len(all_results)} findings → {output_path}")


if __name__ == "__main__":
    main()
