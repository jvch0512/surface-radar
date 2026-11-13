#!/usr/bin/env python3
"""Writes two fictional nmap -oX snapshots (documentation address ranges, invented hostnames)."""
import calendar, pathlib, time
from xml.sax.saxutils import quoteattr as qa

OUT = pathlib.Path(__file__).resolve().parent.parent / "samples"

def ts(y, m, d): return calendar.timegm((y, m, d, 3, 0, 0))

def port(num, proto="tcp", state="open", name="", product="", version="", cert=None, tls=()):
    s = f'<port protocol="{proto}" portid="{num}"><state state="{state}" reason="syn-ack"/>'
    s += f'<service name={qa(name)}' + (f' product={qa(product)}' if product else '') + (f' version={qa(version)}' if version else '') + '/>'
    if cert:
        subj, iss, nb, na = cert
        s += ('<script id="ssl-cert" output="">'
              f'<table key="subject"><elem key="commonName">{subj}</elem></table>'
              f'<table key="issuer"><elem key="commonName">{iss}</elem></table>'
              f'<table key="validity"><elem key="notBefore">{nb}</elem><elem key="notAfter">{na}</elem></table></script>')
    if tls:
        s += '<script id="ssl-enum-ciphers" output="">' + ''.join(f'<table key="{t}"><elem key="warnings"/></table>' for t in tls) + '</script>'
    return s + '</port>'

def host(addr, name, ports):
    return (f'<host><status state="up"/><address addr="{addr}" addrtype="ipv4"/>'
            f'<hostnames><hostname name="{name}" type="user"/></hostnames><ports>{"".join(ports)}</ports></host>')

def scan(start, hosts):
    return ('<?xml version="1.0"?>\n<nmaprun scanner="nmap" args="nmap -sV --script ssl-cert,ssl-enum-ciphers -oX scan.xml" '
            f'start="{start}" version="7.95">\n' + "\n".join(hosts) + '\n</nmaprun>\n')

web = lambda extra=(): [port(22, name="ssh", product="OpenSSH", version="8.9p1"),
                        port(80, name="http", product="nginx", version="1.24.0"),
                        port(443, name="https", product="nginx", version="1.24.0",
                             cert=("www.example-corp.test", "Example Corp CA", "2025-12-01T00:00:00", "2026-03-01T00:00:00"), tls=("TLSv1.2", "TLSv1.3")), *extra]

before = scan(ts(2026, 2, 1), [
    host("203.0.113.10", "www.example-corp.test", web()),
    host("203.0.113.11", "mail.example-corp.test", [
        port(25, name="smtp", product="Postfix smtpd"), port(143, name="imap", product="Dovecot imapd"),
        port(443, name="https", product="Apache httpd", version="2.4.58",
             cert=("mail.example-corp.test", "Example Corp CA", "2025-09-01T00:00:00", "2026-09-01T00:00:00"), tls=("TLSv1.2",))]),
    host("203.0.113.20", "legacy.example-corp.test", [
        port(21, name="ftp", product="vsftpd", version="3.0.5"),
        port(80, name="http", product="Apache httpd", version="2.2.34"),
        port(443, name="https", product="Apache httpd", version="2.2.34",
             cert=("legacy.example-corp.test", "legacy.example-corp.test", "2020-01-01T00:00:00", "2030-01-01T00:00:00"), tls=("TLSv1.0", "TLSv1.1", "TLSv1.2"))]),
    host("10.20.0.5", "fileserver.corp.test", [port(445, name="microsoft-ds"), port(3389, name="ms-wbt-server")]),
])

after = scan(ts(2026, 2, 22), [
    host("203.0.113.10", "www.example-corp.test", web([port(8080, name="http-proxy", product="Jetty", version="9.4.51")])),
    host("203.0.113.11", "mail.example-corp.test", [
        port(25, name="smtp", product="Postfix smtpd"),
        port(443, name="https", product="Apache httpd", version="2.4.58",
             cert=("mail.example-corp.test", "Example Corp CA", "2025-09-01T00:00:00", "2026-09-01T00:00:00"), tls=("TLSv1.2",))]),
    host("203.0.113.20", "legacy.example-corp.test", [
        port(21, name="ftp", product="vsftpd", version="3.0.5"),
        port(80, name="http", product="Apache httpd", version="2.2.34"),
        port(3389, name="ms-wbt-server"), port(6379, name="redis", product="Redis key-value store", version="6.0.16"),
        port(443, name="https", product="Apache httpd", version="2.2.34",
             cert=("legacy.example-corp.test", "legacy.example-corp.test", "2020-01-01T00:00:00", "2030-01-01T00:00:00"), tls=("TLSv1.0", "TLSv1.1", "TLSv1.2"))]),
    host("203.0.113.55", "dev-db.example-corp.test", [
        port(22, name="ssh", product="OpenSSH", version="7.2p2"), port(5432, name="postgresql", product="PostgreSQL DB", version="12.3"),
        port(21, name="ftp", product="vsftpd", version="2.3.4")]),
    host("10.20.0.5", "fileserver.corp.test", [port(445, name="microsoft-ds"), port(3389, name="ms-wbt-server")]),
])
(OUT / "scan-2026-02-01.xml").write_text(before)
(OUT / "scan-2026-02-22.xml").write_text(after)
print("samples written")
