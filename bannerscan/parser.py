"""Turn a raw banner into a (product, version) pair."""
import re
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Service:
    product: str   # key used in the CVE dataset
    display: str   # human-friendly name
    version: str


_SIGNATURES = [
    ("openssh", "OpenSSH", re.compile(r"SSH-\d\.\d+-OpenSSH_(\d+(?:\.\d+)*(?:p\d+)?)", re.I)),
    ("dropbear", "Dropbear SSH", re.compile(r"SSH-\d\.\d+-dropbear_(\d+(?:\.\d+)*)", re.I)),
    ("apache_httpd", "Apache HTTP Server", re.compile(r"Apache/(\d+(?:\.\d+)+)", re.I)),
    ("nginx", "nginx", re.compile(r"nginx/(\d+(?:\.\d+)+)", re.I)),
    ("iis", "Microsoft IIS", re.compile(r"Microsoft-IIS/(\d+(?:\.\d+)*)", re.I)),
    ("vsftpd", "vsftpd", re.compile(r"vsFTPd (\d+(?:\.\d+)+)", re.I)),
    ("proftpd", "ProFTPD", re.compile(r"ProFTPD (\d+(?:\.\d+)+[a-z]?)", re.I)),
    ("exim", "Exim", re.compile(r"Exim (\d+(?:\.\d+)+)", re.I)),
]


def identify(banner: str) -> Optional[Service]:
    for product, display, pattern in _SIGNATURES:
        m = pattern.search(banner or "")
        if m:
            return Service(product, display, m.group(1))
    return None
