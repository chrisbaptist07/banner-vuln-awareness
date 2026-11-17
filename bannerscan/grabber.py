"""Passive-first banner grabbing. Sends at most a single HTTP HEAD request."""
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import List, Optional

HTTP_PORTS = {80, 8000, 8008, 8080, 8888}
TLS_HTTP_PORTS = {443, 8443}
DEFAULT_PORTS = [21, 22, 25, 80, 110, 143, 443, 587, 8000, 8080, 8443]
MAX_BYTES = 1024


@dataclass
class BannerResult:
    host: str
    port: int
    open: bool
    banner: str = ""
    error: Optional[str] = None


def parse_ports(spec: str) -> List[int]:
    """'22,80,8000-8010' -> sorted unique list of valid ports."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = (int(x) for x in part.split("-", 1))
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(part))
    bad = [p for p in ports if not 1 <= p <= 65535]
    if bad:
        raise ValueError(f"invalid port(s): {sorted(bad)}")
    return sorted(ports)


def _http_head(host: str) -> bytes:
    return f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: bannerscan-awareness\r\n\r\n".encode()


def _recv(sock: socket.socket) -> str:
    try:
        return sock.recv(MAX_BYTES).decode("latin-1", errors="replace").strip()
    except (socket.timeout, OSError):
        return ""


def grab_banner(host: str, port: int, timeout: float = 3.0) -> BannerResult:
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        return BannerResult(host, port, False, error=type(exc).__name__)

    sock = raw
    try:
        sock.settimeout(timeout)
        if port in TLS_HTTP_PORTS:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False          # we only read a banner; no trust decision
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw, server_hostname=host)

        if port in HTTP_PORTS or port in TLS_HTTP_PORTS:
            sock.sendall(_http_head(host))
            banner = _recv(sock)
        else:
            sock.settimeout(min(timeout, 2.0))   # SSH/FTP/SMTP speak first
            banner = _recv(sock)
            if not banner:                       # silent service: one HTTP probe
                try:
                    sock.sendall(_http_head(host))
                    banner = _recv(sock)
                except OSError:
                    pass
        return BannerResult(host, port, True, banner=banner)
    except (OSError, ssl.SSLError) as exc:
        return BannerResult(host, port, True, error=type(exc).__name__)
    finally:
        try:
            sock.close()
        except OSError:
            pass


def scan_host(host: str, ports: List[int], timeout: float = 3.0, workers: int = 16) -> List[BannerResult]:
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        return list(pool.map(lambda p: grab_banner(host, p, timeout), ports))
