"""bannerscan - banner-grabbing vulnerability *awareness* scanner.

AWARENESS ONLY, NOT EXPLOITATION.
"""
__version__ = "1.0.0"

DISCLAIMER = (
    "AWARENESS ONLY - NOT EXPLOITATION. Findings are based solely on version "
    "strings advertised in service banners compared against an offline dataset. "
    "They are indicators for follow-up, not confirmed vulnerabilities. "
    "Vendors often backport fixes without changing the advertised version, so "
    "false positives (and false negatives) are expected."
)
