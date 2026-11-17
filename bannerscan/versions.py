"""Small, dependency-free version parsing and range checking."""
import re
from typing import Optional, Tuple

_NUM = re.compile(r"\d+")


def parse_version(text: str) -> Tuple[int, ...]:
    """'9.6p1' -> (9, 6, 1); '2016.72' -> (2016, 72); '1.3.5b' -> (1, 3, 5)."""
    return tuple(int(n) for n in _NUM.findall(text or ""))


def compare(a: Tuple[int, ...], b: Tuple[int, ...]) -> int:
    n = max(len(a), len(b))
    a = a + (0,) * (n - len(a))
    b = b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def in_range(version: Tuple[int, ...], introduced: Optional[str], fixed: Optional[str]) -> bool:
    """True if introduced <= version < fixed (either bound may be None)."""
    if not version:
        return False
    if introduced and compare(version, parse_version(introduced)) < 0:
        return False
    if fixed and compare(version, parse_version(fixed)) >= 0:
        return False
    return True
