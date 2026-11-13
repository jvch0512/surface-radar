# Attack surface change report

## New hosts

- dev-db.example-corp.test (203.0.113.55)

## Newly open ports

- www.example-corp.test (203.0.113.10) 8080/tcp: http-proxy Jetty 9.4.51
- legacy.example-corp.test (203.0.113.20) 3389/tcp: ms-wbt-server
- legacy.example-corp.test (203.0.113.20) 6379/tcp: redis Redis key-value store 6.0.16

## Closed ports

- mail.example-corp.test (203.0.113.11) 143/tcp: was imap Dovecot imapd

## New findings

- **CRITICAL** dev-db.example-corp.test (203.0.113.55) 21/tcp: vsftpd 2.3.4 backdoor
- **CRITICAL** dev-db.example-corp.test (203.0.113.55) 5432/tcp: PostgreSQL exposed on 5432/tcp
- **CRITICAL** legacy.example-corp.test (203.0.113.20) 3389/tcp: RDP exposed on 3389/tcp
- **CRITICAL** legacy.example-corp.test (203.0.113.20) 6379/tcp: Redis exposed on 6379/tcp
- **HIGH** dev-db.example-corp.test (203.0.113.55) 21/tcp: FTP exposed on 21/tcp
- **MEDIUM** dev-db.example-corp.test (203.0.113.55) 22/tcp: OpenSSH 7.2p2 is outdated

