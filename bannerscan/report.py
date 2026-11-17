"""Text, JSON and Markdown renderers. Every format carries the disclaimer."""
import json
from datetime import datetime, timezone
from typing import List

from . import DISCLAIMER, TOOL_TITLE, __author__, __version__

RULE = "=" * 78


def build(reports: List[dict], meta: dict) -> dict:
    return {
        "tool": f"bannerscan {__version__}",
        "author": __author__,
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "disclaimer": DISCLAIMER,
        "dataset": meta,
        "hosts": reports,
    }


def render_json(doc: dict) -> str:
    return json.dumps(doc, indent=2)


def render_text(doc: dict, verbose: bool = False) -> str:
    out = [RULE, f"  {TOOL_TITLE}", f"  Author: {__author__}   |   v{__version__}", RULE, ""]
    meta = doc["dataset"]
    out.append(f"Dataset: {meta.get('name', 'unknown')} (updated {meta.get('updated', 'n/a')})")
    for host in doc["hosts"]:
        out += ["", f"Host: {host['host']}", "-" * 78]
        shown = [p for p in host["ports"] if p["open"] or verbose]
        if not shown:
            out.append("  No open ports found in the scanned range.")
        for p in shown:
            svc = p["service"]
            if not p["open"]:
                out.append(f"  {p['port']:>5}/tcp  closed/filtered ({p['error']})")
                continue
            if not svc:
                snippet = (p["banner"].splitlines() or ["<no banner>"])[0][:60]
                out.append(f"  {p['port']:>5}/tcp  open  unidentified banner: {snippet}")
                continue
            adv = p["advisories"]
            status = f"POTENTIALLY OUTDATED ({len(adv)} advisory match(es))" if adv else "no dataset matches"
            out.append(f"  {p['port']:>5}/tcp  open  {svc['display']} {svc['version']}  ->  {status}")
            for a in adv:
                out.append(f"           - {a['cve']}  (fixed in {a['fixed_in']}): {a['summary']}")
                out.append(f"             {a['reference']}")
    out += ["", RULE,
            "'No dataset matches' does NOT mean secure: the dataset is a small offline sample.",
            "Verify with the vendor/distro advisory (backports!) before drawing conclusions.",
            "AWARENESS ONLY - NOT EXPLOITATION.", RULE]
    return "\n".join(out)


def render_markdown(doc: dict) -> str:
    out = [f"# {TOOL_TITLE}", "", f"_Author: {__author__} | Generated {doc['generated_utc']} | {doc['tool']}_", ""]
    for host in doc["hosts"]:
        out += [f"## {host['host']}", "", "| Port | Service | Version | Advisories |", "|---|---|---|---|"]
        for p in host["ports"]:
            if not p["open"]:
                continue
            svc = p["service"]
            if not svc:
                out.append(f"| {p['port']} | unidentified | - | - |")
                continue
            cves = ", ".join(a["cve"] for a in p["advisories"]) or "none in dataset"
            out.append(f"| {p['port']} | {svc['display']} | {svc['version']} | {cves} |")
        out.append("")
    out += ["---", f"_{DISCLAIMER}_"]
    return "\n".join(out)
