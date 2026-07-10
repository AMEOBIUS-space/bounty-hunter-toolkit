#!/usr/bin/env python3
"""Bounty Hunter Toolkit public API and CLI entry point.

This module re-exports the toolkit API so the package can be imported as
described in the README:

    from bounty_hunter_toolkit import PatternMatcher

    matcher = PatternMatcher()
    patterns = matcher.find("sql injection")
"""

from __future__ import annotations

import sys

from apply_fix import PatternMatcher, main

__all__ = ["PatternMatcher", "main"]

if __name__ == "__main__":
    sys.exit(main())
