# Attack surface report

5 hosts up, 16 open ports, 13 findings. Scan started 2026-02-22T03:00:00Z.

| Host | Score | Critical | High | Medium | Low |
|---|---:|---:|---:|---:|---:|
| legacy.example-corp.test (203.0.113.20) | 100 | 2 | 3 | 1 | 2 |
| dev-db.example-corp.test (203.0.113.55) | 100 | 2 | 1 | 1 | 0 |
| www.example-corp.test (203.0.113.10) | 12 | 0 | 0 | 1 | 0 |
| fileserver.corp.test (10.20.0.5) | 0 | 0 | 0 | 0 | 0 |
| mail.example-corp.test (203.0.113.11) | 0 | 0 | 0 | 0 | 0 |

## legacy.example-corp.test (203.0.113.20) (score 100)

- **CRITICAL** RDP exposed on 3389/tcp on 3389/tcp: RDP remote desktop, top ransomware entry point. Seen as ms-wbt-server.
- **CRITICAL** Redis exposed on 6379/tcp on 6379/tcp: Redis often unauthenticated, allows code execution. Seen as redis Redis key-value store 6.0.16.
- **HIGH** FTP exposed on 21/tcp on 21/tcp: FTP sends credentials in clear text. Seen as ftp vsftpd 3.0.5.
- **HIGH** Apache httpd 2.2.34 is outdated on 443/tcp: Apache 2.2 branch is end of life.
- **HIGH** Apache httpd 2.2.34 is outdated on 80/tcp: Apache 2.2 branch is end of life.
- **MEDIUM** TLS 1.0 enabled on 443/tcp: TLS 1.0 is deprecated and blocked by PCI DSS.
- **LOW** TLS 1.1 enabled on 443/tcp: TLS 1.1 is deprecated.
- **LOW** Self-signed certificate on a public host on 443/tcp: Subject and issuer are both legacy.example-corp.test.

## dev-db.example-corp.test (203.0.113.55) (score 100)

- **CRITICAL** vsftpd 2.3.4 backdoor on 21/tcp: This exact release shipped with a known backdoor.
- **CRITICAL** PostgreSQL exposed on 5432/tcp on 5432/tcp: PostgreSQL database reachable from the internet. Seen as postgresql PostgreSQL DB 12.3.
- **HIGH** FTP exposed on 21/tcp on 21/tcp: FTP sends credentials in clear text. Seen as ftp vsftpd 2.3.4.
- **MEDIUM** OpenSSH 7.2p2 is outdated on 22/tcp: OpenSSH before 7.4 is out of support.

## www.example-corp.test (203.0.113.10) (score 12)

- **MEDIUM** Certificate expires in 6 days on 443/tcp: Certificate for www.example-corp.test expires 2026-03-01T00:00:00Z.
