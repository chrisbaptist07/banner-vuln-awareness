"""Cross-reference detected versions against the offline CVE dataset."""
import json
from pathlib import Path
from typing import Dict, List, Tuple

from .parser import Service
from .versions import in_range, parse_version

DEFAULT_DATASET = Path(__file__).parent / "data" / "cves.json"


def load_dataset(path=None) -> Tuple[List[dict], dict]:
    with open(path or DEFAULT_DATASET, encoding="utf-8") as fh:
        data = json.load(fh)
    return data["entries"], data.get("_meta", {})


def match(service: Service, entries: List[dict]) -> List[Dict[str, str]]:
    version = parse_version(service.version)
    hits = []
    for entry in entries:
        if entry["product"] != service.product:
            continue
        for rng in entry["ranges"]:
            if in_range(version, rng.get("introduced"), rng.get("fixed")):
                hits.append({
                    "cve": entry["cve"],
                    "summary": entry["summary"],
                    "fixed_in": rng.get("fixed") or "n/a",
                    "reference": f"https://nvd.nist.gov/vuln/detail/{entry['cve']}",
                })
                break
    return hits
