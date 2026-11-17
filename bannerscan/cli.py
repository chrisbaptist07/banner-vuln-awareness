import argparse
import sys

from . import DISCLAIMER, __version__
from .grabber import DEFAULT_PORTS, parse_ports, scan_host
from .matcher import load_dataset, match
from .parser import identify
from .report import build, render_json, render_markdown, render_text


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="bannerscan",
        description="Banner-grabbing vulnerability AWARENESS scanner. Awareness only, not exploitation.",
        epilog="Only scan systems you own or have explicit written permission to test.",
    )
    p.add_argument("targets", nargs="+", help="hostname(s) or IP(s) to scan")
    p.add_argument("-p", "--ports", default=",".join(map(str, DEFAULT_PORTS)),
                   help="ports, e.g. 22,80,8000-8010 (default: common service ports)")
    p.add_argument("-t", "--timeout", type=float, default=3.0, help="per-connection timeout, seconds")
    p.add_argument("-w", "--workers", type=int, default=16, help="concurrent connections")
    p.add_argument("-d", "--dataset", help="path to a custom CVE dataset JSON")
    p.add_argument("-f", "--format", choices=["text", "json", "md"], default="text")
    p.add_argument("-o", "--output", help="write report to file instead of stdout")
    p.add_argument("-v", "--verbose", action="store_true", help="also list closed ports (text format)")
    p.add_argument("--authorized", action="store_true",
                   help="confirm you are authorized to scan the given targets (required)")
    p.add_argument("--version", action="version", version=f"bannerscan {__version__}")
    return p


def analyze(host, ports, entries, timeout, workers) -> dict:
    rows = []
    for r in scan_host(host, ports, timeout, workers):
        svc = identify(r.banner) if r.open else None
        rows.append({
            "port": r.port, "open": r.open, "error": r.error, "banner": r.banner,
            "service": ({"product": svc.product, "display": svc.display, "version": svc.version}
                        if svc else None),
            "advisories": match(svc, entries) if svc else [],
        })
    return {"host": host, "ports": rows}


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if not args.authorized:
        print("Refusing to scan: pass --authorized to confirm you have permission to test "
              "these targets.\n" + DISCLAIMER, file=sys.stderr)
        return 2
    try:
        ports = parse_ports(args.ports)
        entries, meta = load_dataset(args.dataset)
    except (ValueError, OSError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    reports = [analyze(t, ports, entries, args.timeout, args.workers) for t in args.targets]
    doc = build(reports, meta)
    text = {"json": render_json, "md": render_markdown}.get(
        args.format, lambda d: render_text(d, args.verbose))(doc)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"Report written to {args.output}  (awareness only, not exploitation)")
    else:
        print(text)
    return 0
