package dev.jvch.radar;

import dev.jvch.radar.Model.*;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Exposure, end-of-life version, TLS and certificate rules. Pure functions over a parsed scan. */
public final class Rules {
    private Rules() {}

    public enum Scope { EXTERNAL, ALL }

    private record Risk(String name, Severity sev, String why) {}

    private static final Map<String, Risk> BY_PORT = Map.ofEntries(
        Map.entry("21/tcp", new Risk("FTP", Severity.HIGH, "sends credentials in clear text")),
        Map.entry("23/tcp", new Risk("Telnet", Severity.CRITICAL, "unencrypted remote shell")),
        Map.entry("69/udp", new Risk("TFTP", Severity.HIGH, "no authentication")),
        Map.entry("111/tcp", new Risk("rpcbind", Severity.MEDIUM, "lists RPC services and feeds amplification")),
        Map.entry("135/tcp", new Risk("MS-RPC", Severity.HIGH, "Windows RPC endpoint mapper")),
        Map.entry("139/tcp", new Risk("NetBIOS", Severity.HIGH, "legacy Windows file sharing")),
        Map.entry("445/tcp", new Risk("SMB", Severity.CRITICAL, "Windows file sharing, wormable history")),
        Map.entry("161/udp", new Risk("SNMP", Severity.HIGH, "community strings leak device data")),
        Map.entry("389/tcp", new Risk("LDAP", Severity.HIGH, "directory exposed without TLS")),
        Map.entry("1433/tcp", new Risk("MSSQL", Severity.CRITICAL, "database reachable from the internet")),
        Map.entry("1521/tcp", new Risk("Oracle", Severity.CRITICAL, "database reachable from the internet")),
        Map.entry("2049/tcp", new Risk("NFS", Severity.HIGH, "network file system exposed")),
        Map.entry("2375/tcp", new Risk("Docker API", Severity.CRITICAL, "unauthenticated container control")),
        Map.entry("2379/tcp", new Risk("etcd", Severity.CRITICAL, "cluster secrets store")),
        Map.entry("3306/tcp", new Risk("MySQL", Severity.CRITICAL, "database reachable from the internet")),
        Map.entry("3389/tcp", new Risk("RDP", Severity.CRITICAL, "remote desktop, top ransomware entry point")),
        Map.entry("5432/tcp", new Risk("PostgreSQL", Severity.CRITICAL, "database reachable from the internet")),
        Map.entry("5900/tcp", new Risk("VNC", Severity.CRITICAL, "remote desktop with weak authentication")),
        Map.entry("5984/tcp", new Risk("CouchDB", Severity.HIGH, "database HTTP API exposed")),
        Map.entry("5985/tcp", new Risk("WinRM", Severity.HIGH, "remote Windows management")),
        Map.entry("5986/tcp", new Risk("WinRM", Severity.HIGH, "remote Windows management")),
        Map.entry("6379/tcp", new Risk("Redis", Severity.CRITICAL, "often unauthenticated, allows code execution")),
        Map.entry("9200/tcp", new Risk("Elasticsearch", Severity.CRITICAL, "data store HTTP API exposed")),
        Map.entry("10250/tcp", new Risk("Kubelet", Severity.CRITICAL, "node control API")),
        Map.entry("11211/tcp", new Risk("Memcached", Severity.CRITICAL, "no authentication, amplification")),
        Map.entry("27017/tcp", new Risk("MongoDB", Severity.CRITICAL, "database reachable from the internet")));

    /** Same risks found on non-standard ports are caught by the service name nmap detected. */
    private static final Map<String, String> SERVICE_TO_PORT = Map.of(
        "telnet", "23/tcp", "ms-wbt-server", "3389/tcp", "microsoft-ds", "445/tcp", "vnc", "5900/tcp",
        "redis", "6379/tcp", "mongod", "27017/tcp", "mysql", "3306/tcp", "postgresql", "5432/tcp",
        "ms-sql-s", "1433/tcp", "memcache", "11211/tcp");

    private record Eol(String product, String below, Severity sev, String why) {}

    private static final List<Eol> EOL = List.of(
        new Eol("apache httpd", "2.4", Severity.HIGH, "Apache 2.2 branch is end of life"),
        new Eol("php", "7.4", Severity.HIGH, "PHP releases before 7.4 are end of life"),
        new Eol("openssl", "1.1.1", Severity.HIGH, "OpenSSL before 1.1.1 is end of life"),
        new Eol("microsoft iis httpd", "10.0", Severity.HIGH, "IIS before 10.0 runs on unsupported Windows Server"),
        new Eol("openssh", "7.4", Severity.MEDIUM, "OpenSSH before 7.4 is out of support"),
        new Eol("nginx", "1.18", Severity.MEDIUM, "nginx before 1.18 is out of support"),
        new Eol("mysql", "8.0", Severity.MEDIUM, "MySQL 5.x is end of life"),
        new Eol("tomcat", "9.0", Severity.MEDIUM, "Tomcat 8.5 and older are end of life"));

    public static List<Finding> evaluate(Scan scan, Scope scope) {
        List<Finding> out = new ArrayList<>();
        for (Host h : scan.hosts()) {
            boolean external = Net.isExternal(h.addr());
            String host = h.label();
            for (Port p : h.ports()) {
                if (!p.open()) continue;
                if (external || scope == Scope.ALL) {
                    Risk r = BY_PORT.get(p.key());
                    if (r == null && p.service() != null) {
                        String k = SERVICE_TO_PORT.get(p.service());
                        if (k != null) r = BY_PORT.get(k);
                    }
                    if (r != null) out.add(new Finding("exposed-service", r.sev, host, p.key(),
                        r.name + " exposed on " + p.key(), r.name + " " + r.why + (external ? "" : " (internal host, scope=all)") + ". Seen as " + p.banner() + "."));
                }
                eol(p).ifPresent(f -> out.add(new Finding("outdated-software", f.sev, host, p.key(), p.product() + " " + p.version() + " is outdated", f.why + ".")));
                if (p.product() != null && p.product().toLowerCase().contains("vsftpd") && "2.3.4".equals(p.version()))
                    out.add(new Finding("backdoored-release", Severity.CRITICAL, host, p.key(), "vsftpd 2.3.4 backdoor", "This exact release shipped with a known backdoor."));
                for (String t : p.tlsVersions()) {
                    if (t.equals("SSLv3")) out.add(new Finding("weak-tls", Severity.HIGH, host, p.key(), "SSLv3 enabled", "SSLv3 is broken (POODLE)."));
                    else if (t.equals("TLSv1.0")) out.add(new Finding("weak-tls", Severity.MEDIUM, host, p.key(), "TLS 1.0 enabled", "TLS 1.0 is deprecated and blocked by PCI DSS."));
                    else if (t.equals("TLSv1.1")) out.add(new Finding("weak-tls", Severity.LOW, host, p.key(), "TLS 1.1 enabled", "TLS 1.1 is deprecated."));
                }
                cert(p, host, scan.start(), external).forEach(out::add);
            }
        }
        // one entry per (rule, host, port, title) is enough, and ids must be unique for diffing
        List<Finding> uniq = new ArrayList<>();
        java.util.Set<String> seen = new java.util.HashSet<>();
        for (Finding f : out) if (seen.add(f.id() + "|" + f.title())) uniq.add(f);
        return uniq;
    }

    private static java.util.Optional<Eol> eol(Port p) {
        if (p.product() == null || p.version() == null || p.version().isEmpty()) return java.util.Optional.empty();
        String prod = p.product().toLowerCase();
        for (Eol e : EOL) if (prod.contains(e.product) && Version.compare(p.version(), e.below) < 0) return java.util.Optional.of(e);
        return java.util.Optional.empty();
    }

    private static List<Finding> cert(Port p, String host, Instant now, boolean external) {
        List<Finding> out = new ArrayList<>();
        Cert c = p.cert();
        if (c == null) return out;
        if (c.notAfter() != null && now.isAfter(Instant.EPOCH)) {
            long days = Duration.between(now, c.notAfter()).toDays();
            if (c.notAfter().isBefore(now)) out.add(new Finding("certificate", Severity.HIGH, host, p.key(), "Certificate expired", "Certificate for " + c.subject() + " expired " + c.notAfter() + "."));
            else if (days <= 30) out.add(new Finding("certificate", Severity.MEDIUM, host, p.key(), "Certificate expires in " + days + " days", "Certificate for " + c.subject() + " expires " + c.notAfter() + "."));
        }
        if (c.selfSigned() && external) out.add(new Finding("certificate", Severity.LOW, host, p.key(), "Self-signed certificate on a public host", "Subject and issuer are both " + c.subject() + "."));
        return out;
    }
}
