import socket
import threading

from bannerscan.grabber import grab_banner, parse_ports
from bannerscan.matcher import load_dataset, match
from bannerscan.parser import identify
from bannerscan.versions import in_range, parse_version
from bannerscan import cli


def test_parse_version():
    assert parse_version("9.6p1") == (9, 6, 1)
    assert parse_version("2016.72") == (2016, 72)


def test_range_boundaries():
    assert in_range(parse_version("2.4.49"), "2.4.49", "2.4.50")
    assert not in_range(parse_version("2.4.50"), "2.4.49", "2.4.50")
    assert not in_range(parse_version("9.8p1"), "8.5", "9.8")
    assert in_range(parse_version("9.7p1"), "8.5", "9.8")


def test_identify():
    assert identify("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3").version == "8.9p1"
    assert identify("HTTP/1.1 200 OK\r\nServer: nginx/1.18.0").product == "nginx"
    assert identify("220 (vsFTPd 2.3.4)").product == "vsftpd"
    assert identify("garbage") is None


def test_matcher_flags_and_clears():
    entries, _ = load_dataset()
    old = match(identify("SSH-2.0-OpenSSH_7.4"), entries)
    assert {"CVE-2018-15473", "CVE-2023-38408"} <= {h["cve"] for h in old}
    assert not any(h["cve"] == "CVE-2024-6387" for h in match(identify("SSH-2.0-OpenSSH_9.8p1"), entries))


def test_parse_ports():
    assert parse_ports("22,80,8000-8002") == [22, 80, 8000, 8001, 8002]


def test_grab_and_refuse_without_authorization(capsys):
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
    port = srv.getsockname()[1]

    def serve():
        conn, _ = srv.accept(); conn.sendall(b"SSH-2.0-OpenSSH_7.4\r\n"); conn.close()
    threading.Thread(target=serve, daemon=True).start()
    r = grab_banner("127.0.0.1", port, timeout=2)
    srv.close()
    assert r.open and r.banner.startswith("SSH-2.0-OpenSSH_7.4")

    assert cli.main(["127.0.0.1"]) == 2
    assert "Refusing to scan" in capsys.readouterr().err
