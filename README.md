# bannerscan: Banner-Grabbing Vulnerability Awareness Scanner

> **AWARENESS ONLY - NOT EXPLOITATION.**
> bannerscan reads the version banners that services voluntarily advertise and compares them with a local, offline CVE dataset to flag *potentially* outdated software. It contains no exploit code, performs no authentication attempts, and never tries to trigger a vulnerability.

## Features
- Concurrent TCP banner grabbing (passive-first; at most one HTTP `HEAD` probe on silent or web ports; TLS ports supported)
- Identifies OpenSSH, Dropbear, Apache httpd, nginx, Microsoft IIS, vsftpd, ProFTPD and Exim
- Offline matching against `bannerscan/data/cves.json` (no network lookups, no API keys)
- Text, JSON and Markdown reports, each carrying the awareness-only disclaimer
- Zero runtime dependencies (Python 3.8+ standard library)
- Requires an explicit `--authorized` flag before it will scan anything

## Install & run
```bash
git clone https://github.com/<your-username>/banner-vuln-awareness.git
cd banner-vuln-awareness
pip install -e .

bannerscan 192.168.1.10 --authorized
bannerscan scanme.example.org -p 21,22,80,443,8000-8010 -f md -o report.md --authorized
python -m bannerscan 10.0.0.5 -f json --authorized     # without installing
```

## Example output
```
==============================================================================
  AWARENESS ONLY - NOT EXPLOITATION
==============================================================================
Host: 192.168.1.10
    22/tcp  open  OpenSSH 7.4  ->  POTENTIALLY OUTDATED (3 advisory match(es))
           - CVE-2018-15473  (fixed in 7.8): Username enumeration via ...
```

## Limitations (please read)
- **Backports:** Distros (Debian, Ubuntu, RHEL...) patch security fixes without changing the version string, so an "outdated" flag may be a false positive. Always check the distro advisory.
- **Hidden/modified banners:** Admins can hide or spoof banners, giving false negatives.
- **Small dataset:** "No dataset matches" does **not** mean secure.
- Only TCP banners; no UDP, no deep fingerprinting.

## Updating the dataset
Entries in `cves.json` follow this shape; `introduced` is inclusive, `fixed` is exclusive:
```json
{"cve": "CVE-XXXX-YYYY", "product": "nginx", "summary": "...",
 "ranges": [{"introduced": "1.1.3", "fixed": "1.22.1"}]}
```
Use `-d my_dataset.json` to point at your own file. Source data from [NVD](https://nvd.nist.gov/) or vendor advisories.

## Tests
```bash
pip install pytest && pytest
```

## Responsible use
Only scan systems you own or have **explicit written permission** to assess. Unauthorized scanning may be illegal in your jurisdiction. The authors accept no liability for misuse.

## Project layout
```
bannerscan/   grabber.py  parser.py  matcher.py  versions.py  report.py  cli.py  data/cves.json
tests/        test_core.py
```

## License
MIT
