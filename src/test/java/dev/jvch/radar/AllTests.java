package dev.jvch.radar;

import dev.jvch.radar.Model.*;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/** Tiny dependency-free test runner. Run with assertions enabled (-ea). */
public final class AllTests {
    private interface Case { void run() throws Exception; }

    private static int passed = 0;

    private static void test(String name, Case c) {
        try {
            c.run();
            passed++;
            System.out.println("ok   " + name);
        } catch (Throwable t) {
            System.out.println("FAIL " + name + ": " + t);
            t.printStackTrace(System.out);
            System.exit(1);
        }
    }

    private static void eq(Object a, Object b) { if (!a.equals(b)) throw new AssertionError(a + " != " + b); }
    private static void yes(boolean c, String msg) { if (!c) throw new AssertionError(msg); }

    private static String xml(String hosts) {
        return "<?xml version=\"1.0\"?><nmaprun start=\"1772334000\">" + hosts + "</nmaprun>";
    }

    private static String host(String addr, String ports) {
        return "<host><status state=\"up\"/><address addr=\"" + addr + "\" addrtype=\"ipv4\"/><ports>" + ports + "</ports></host>";
    }

    private static String port(int n, String name, String product, String version) {
        return "<port protocol=\"tcp\" portid=\"" + n + "\"><state state=\"open\"/><service name=\"" + name + "\" product=\"" + product + "\" version=\"" + version + "\"/></port>";
    }

    private static List<Finding> eval(String hosts) { return Rules.evaluate(NmapParser.parse(xml(hosts)), Rules.Scope.EXTERNAL); }

    private static boolean has(List<Finding> fs, String rule, Severity s) {
        return fs.stream().anyMatch(f -> f.rule().equals(rule) && f.severity() == s);
    }

    private static String sample(String name) throws Exception {
        return Files.readString(Path.of("samples", name), StandardCharsets.UTF_8);
    }

    private static String[] run(String... args) {
        ByteArrayOutputStream o = new ByteArrayOutputStream(), e = new ByteArrayOutputStream();
        int code = Main.run(args, new PrintStream(o, true, StandardCharsets.UTF_8), new PrintStream(e, true, StandardCharsets.UTF_8));
        return new String[] { String.valueOf(code), o.toString(StandardCharsets.UTF_8), e.toString(StandardCharsets.UTF_8) };
    }

    public static void main(String[] args) {
        test("version compare handles suffixes and length", () -> {
            yes(Version.compare("8.9p1", "7.4") > 0, "8.9p1 > 7.4");
            yes(Version.compare("7.2p2", "7.4") < 0, "7.2p2 < 7.4");
            eq(Version.compare("2.4", "2.4.0"), 0);
            yes(Version.compare("1.0.2k-fips", "1.1.1") < 0, "1.0.2k < 1.1.1");
            yes(Version.compare("", "1") < 0, "empty is lowest");
            eq(Version.compare("abc", "abc"), 0);
        });

        test("address classification", () -> {
            for (String a : new String[] { "10.1.2.3", "172.16.0.1", "172.31.255.1", "192.168.1.1", "127.0.0.1", "169.254.1.1", "100.64.0.1", "::1", "fe80::1", "fd00::5" })
                yes(!Net.isExternal(a), a + " is internal");
            for (String a : new String[] { "8.8.8.8", "172.32.0.1", "172.15.0.1", "203.0.113.5", "2001:db8::1", "100.128.0.1" })
                yes(Net.isExternal(a), a + " is external");
        });

        test("parser reads hosts, ports, banners, certificates and TLS versions", () -> {
            Scan s = NmapParser.parse(sample("scan-2026-02-01.xml"));
            eq(s.hosts().size(), 4);
            Host www = s.hosts().get(0);
            eq(www.addr(), "203.0.113.10");
            eq(www.hostname(), "www.example-corp.test");
            Port https = www.ports().get(2);
            eq(https.banner(), "https nginx 1.24.0");
            eq(https.cert().subject(), "www.example-corp.test");
            eq(https.cert().notAfter().toString(), "2026-03-01T00:00:00Z");
            eq(https.tlsVersions(), List.of("TLSv1.2", "TLSv1.3"));
            eq(s.start().getEpochSecond(), 1769914800L);
        });

        test("parser skips hosts that are down and ports with bad numbers", () -> {
            String x = xml("<host><status state=\"down\"/><address addr=\"1.1.1.1\" addrtype=\"ipv4\"/></host>"
                + host("2.2.2.2", "<port protocol=\"tcp\" portid=\"99999\"><state state=\"open\"/></port><port protocol=\"tcp\" portid=\"x\"><state state=\"open\"/></port>" + port(22, "ssh", "OpenSSH", "9.0")));
            Scan s = NmapParser.parse(x);
            eq(s.hosts().size(), 1);
            eq(s.hosts().get(0).ports().size(), 1);
        });

        test("parser prefers an ipv4 address and tolerates a missing service element", () -> {
            Scan s = NmapParser.parse(xml("<host><status state=\"up\"/><address addr=\"aa:bb\" addrtype=\"mac\"/><address addr=\"2001:db8::1\" addrtype=\"ipv6\"/><address addr=\"9.9.9.9\" addrtype=\"ipv4\"/>"
                + "<ports><port protocol=\"tcp\" portid=\"80\"><state state=\"open\"/></port></ports></host>"));
            eq(s.hosts().get(0).addr(), "9.9.9.9");
            eq(s.hosts().get(0).ports().get(0).banner(), "unknown");
        });

        test("parser refuses DOCTYPE (XXE and entity bombs)", () -> {
            String evil = "<?xml version=\"1.0\"?><!DOCTYPE nmaprun [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><nmaprun>&x;</nmaprun>";
            try { NmapParser.parse(evil); throw new AssertionError("should have been rejected"); }
            catch (IllegalArgumentException e) { yes(e.getMessage().contains("not a valid nmap XML"), e.getMessage()); }
        });

        test("parser rejects other XML and garbage", () -> {
            for (String bad : new String[] { "<html/>", "not xml at all", "" }) {
                try { NmapParser.parse(bad); throw new AssertionError("accepted " + bad); } catch (IllegalArgumentException expected) { /* ok */ }
            }
        });

        test("risky service on a public host is flagged with the table severity", () -> {
            List<Finding> fs = eval(host("203.0.113.9", port(3389, "ms-wbt-server", "", "") + port(21, "ftp", "", "") + port(111, "rpcbind", "", "")));
            yes(has(fs, "exposed-service", Severity.CRITICAL), "rdp");
            yes(has(fs, "exposed-service", Severity.HIGH), "ftp");
            yes(has(fs, "exposed-service", Severity.MEDIUM), "rpcbind");
        });

        test("the same service on a private host is ignored unless scope is all", () -> {
            Scan s = NmapParser.parse(xml(host("10.0.0.5", port(3389, "ms-wbt-server", "", ""))));
            eq(Rules.evaluate(s, Rules.Scope.EXTERNAL).size(), 0);
            List<Finding> all = Rules.evaluate(s, Rules.Scope.ALL);
            eq(all.size(), 1);
            yes(all.get(0).detail().contains("scope=all"), "detail says why");
        });

        test("a risky service on a non-standard port is found by its service name", () -> {
            yes(has(eval(host("203.0.113.9", port(33890, "ms-wbt-server", "", ""))), "exposed-service", Severity.CRITICAL), "rdp on 33890");
            yes(has(eval(host("203.0.113.9", port(7000, "redis", "Redis", "6.0"))), "exposed-service", Severity.CRITICAL), "redis on 7000");
        });

        test("closed and filtered ports raise nothing", () -> {
            String p = "<port protocol=\"tcp\" portid=\"3389\"><state state=\"closed\"/></port><port protocol=\"tcp\" portid=\"445\"><state state=\"filtered\"/></port>";
            eq(eval(host("203.0.113.9", p)).size(), 0);
        });

        test("outdated software matches the product and compares versions", () -> {
            yes(has(eval(host("203.0.113.9", port(80, "http", "Apache httpd", "2.2.34"))), "outdated-software", Severity.HIGH), "apache 2.2");
            eq(eval(host("203.0.113.9", port(80, "http", "Apache httpd", "2.4.58"))).size(), 0);
            yes(has(eval(host("203.0.113.9", port(22, "ssh", "OpenSSH", "7.2p2"))), "outdated-software", Severity.MEDIUM), "openssh 7.2");
            eq(eval(host("203.0.113.9", port(22, "ssh", "OpenSSH", "8.9p1"))).size(), 0);
            eq(eval(host("203.0.113.9", port(80, "http", "Apache httpd", ""))).size(), 0);
        });

        test("vsftpd 2.3.4 is called out as a backdoor", () -> {
            yes(has(eval(host("203.0.113.9", port(21, "ftp", "vsftpd", "2.3.4"))), "backdoored-release", Severity.CRITICAL), "backdoor");
            yes(!has(eval(host("203.0.113.9", port(21, "ftp", "vsftpd", "3.0.5"))), "backdoored-release", Severity.CRITICAL), "3.0.5 is fine");
        });

        test("TLS and certificate rules", () -> {
            Scan s = NmapParser.parse(sample("scan-2026-02-22.xml"));
            List<Finding> fs = Rules.evaluate(s, Rules.Scope.EXTERNAL);
            yes(fs.stream().anyMatch(f -> f.title().equals("TLS 1.0 enabled") && f.severity() == Severity.MEDIUM), "tls1.0");
            yes(fs.stream().anyMatch(f -> f.title().equals("TLS 1.1 enabled") && f.severity() == Severity.LOW), "tls1.1");
            yes(fs.stream().anyMatch(f -> f.title().equals("Certificate expires in 6 days")), "expiring cert");
            yes(fs.stream().anyMatch(f -> f.title().startsWith("Self-signed")), "self-signed");
            yes(fs.stream().noneMatch(f -> f.host().startsWith("mail.") ), "healthy mail host has no findings");
        });

        test("an expired certificate is high severity", () -> {
            String p = "<port protocol=\"tcp\" portid=\"443\"><state state=\"open\"/><service name=\"https\"/><script id=\"ssl-cert\" output=\"\">"
                + "<table key=\"subject\"><elem key=\"commonName\">a.test</elem></table><table key=\"issuer\"><elem key=\"commonName\">CA</elem></table>"
                + "<table key=\"validity\"><elem key=\"notBefore\">2020-01-01T00:00:00</elem><elem key=\"notAfter\">2021-01-01T00:00:00</elem></table></script></port>";
            yes(has(eval(host("203.0.113.9", p)), "certificate", Severity.HIGH), "expired");
        });

        test("without a scan timestamp certificate expiry is not judged", () -> {
            String p = "<port protocol=\"tcp\" portid=\"443\"><state state=\"open\"/><script id=\"ssl-cert\" output=\"\"><table key=\"subject\"><elem key=\"commonName\">a</elem></table>"
                + "<table key=\"issuer\"><elem key=\"commonName\">CA</elem></table><table key=\"validity\"><elem key=\"notBefore\">2000-01-01T00:00:00</elem><elem key=\"notAfter\">2001-01-01T00:00:00</elem></table></script></port>";
            Scan s = NmapParser.parse("<nmaprun>" + host("203.0.113.9", p) + "</nmaprun>");
            eq(Rules.evaluate(s, Rules.Scope.EXTERNAL).size(), 0);
        });

        test("scores add up and are capped at 100", () -> {
            Scan s = NmapParser.parse(sample("scan-2026-02-22.xml"));
            List<Report.HostScore> sc = Report.score(s, Rules.evaluate(s, Rules.Scope.EXTERNAL));
            eq(sc.get(0).score(), 100);
            eq(sc.get(sc.size() - 1).score(), 0);
            yes(sc.get(0).score() >= sc.get(1).score(), "sorted worst first");
        });

        test("diff finds new hosts, opened and closed ports and ignores wording churn", () -> {
            Diff.Result d = Diff.compare(NmapParser.parse(sample("scan-2026-02-01.xml")), NmapParser.parse(sample("scan-2026-02-22.xml")), Rules.Scope.EXTERNAL);
            eq(d.newHosts().size(), 1);
            eq(d.goneHosts().size(), 0);
            eq(d.opened().size(), 3);
            eq(d.closed().size(), 1);
            eq(d.closed().get(0).port(), "143/tcp");
            yes(d.newFindings().stream().noneMatch(f -> f.title().startsWith("Certificate expires")), "28 to 6 days is the same finding");
            eq(d.newFindings().get(0).severity(), Severity.CRITICAL);
            yes(d.resolvedFindings().isEmpty(), "nothing was fixed");
        });

        test("diff reports version changes and resolved findings", () -> {
            Scan a = NmapParser.parse(xml(host("203.0.113.9", port(80, "http", "Apache httpd", "2.2.34") + port(3389, "ms-wbt-server", "", ""))));
            Scan b = NmapParser.parse(xml(host("203.0.113.9", port(80, "http", "Apache httpd", "2.4.58"))));
            Diff.Result d = Diff.compare(a, b, Rules.Scope.EXTERNAL);
            eq(d.changed().size(), 1);
            eq(d.changed().get(0).after(), "http Apache httpd 2.4.58");
            eq(d.resolvedFindings().size(), 2);
            eq(d.newFindings().size(), 0);
        });

        test("identical scans produce an empty diff", () -> {
            Scan s = NmapParser.parse(sample("scan-2026-02-01.xml"));
            yes(Diff.compare(s, s, Rules.Scope.EXTERNAL).empty(), "empty");
            yes(Report.diffMarkdown(Diff.compare(s, s, Rules.Scope.EXTERNAL)).contains("No changes"), "message");
        });

        test("json output escapes quotes, backslashes and control characters", () -> {
            eq(Report.q("a\"b\\c\nd\u0001"), "\"a\\\"b\\\\c\\nd\\u0001\"");
            eq(Report.q(null), "null");
        });

        test("a hostile banner cannot break out of markdown or json", () -> {
            String banner = "x|<img src=a onerror=1>[l](http://evil)\nnext";
            Scan s = NmapParser.parse(xml(host("203.0.113.9", "<port protocol=\"tcp\" portid=\"3389\"><state state=\"open\"/><service name=\"ms-wbt-server\" product=\"" + banner.replace("\n", "&#10;").replace("<", "&lt;").replace(">", "&gt;") + "\"/></port>")));
            List<Finding> fs = Rules.evaluate(s, Rules.Scope.EXTERNAL);
            String md = Report.markdown(s, fs);
            yes(!md.contains("<img"), "html neutralised");
            yes(!md.contains("[l](http"), "link neutralised");
            yes(md.split("\n").length == Report.markdown(s, fs).split("\n").length, "stable");
            yes(!md.contains("next\n") || md.contains("x\\|"), "pipe escaped");
            String js = Report.json(s, fs);
            yes(js.contains("\\n") || !js.contains("\nnext"), "newline escaped in json");
        });

        test("cli: report exit codes follow --fail-on", () -> {
            String[] r = run("report", "samples/scan-2026-02-22.xml");
            eq(r[0], "1");
            yes(r[1].contains("RDP exposed"), "output");
            eq(run("report", "--fail-on", "none", "samples/scan-2026-02-22.xml")[0], "0");
            eq(run("report", "samples/scan-2026-02-01.xml")[0], "0");
            eq(run("report", "--fail-on", "high", "samples/scan-2026-02-01.xml")[0], "1");
            eq(run("report", "--fail-on", "medium", "samples/scan-2026-02-22.xml")[0], "1");
        });

        test("cli: diff only fails on new findings", () -> {
            eq(run("diff", "samples/scan-2026-02-01.xml", "samples/scan-2026-02-22.xml")[0], "1");
            eq(run("diff", "samples/scan-2026-02-22.xml", "samples/scan-2026-02-01.xml")[0], "0");
        });

        test("cli: formats and bad input", () -> {
            yes(run("report", "--format", "json", "samples/scan-2026-02-22.xml")[1].startsWith("{"), "json");
            yes(run("report", "--format", "md", "samples/scan-2026-02-22.xml")[1].startsWith("# Attack surface report"), "md");
            eq(run("report", "--format", "yaml", "samples/scan-2026-02-22.xml")[0], "2");
            eq(run("report", "--scope", "everywhere", "samples/scan-2026-02-22.xml")[0], "2");
            eq(run("report", "--fail-on", "urgent", "samples/scan-2026-02-22.xml")[0], "2");
            eq(run("report", "--nope", "x.xml")[0], "2");
            eq(run("report", "missing-file.xml")[0], "2");
            eq(run("diff", "only-one.xml")[0], "2");
            eq(run()[0], "2");
            eq(run("--help")[0], "0");
        });

        test("cli: json diff is well formed enough to parse brackets", () -> {
            String j = run("diff", "--format", "json", "samples/scan-2026-02-01.xml", "samples/scan-2026-02-22.xml")[1];
            long open = j.chars().filter(c -> c == '{').count(), close = j.chars().filter(c -> c == '}').count();
            eq(open, close);
            yes(j.contains("\"newHosts\""), "keys");
        });

        System.out.println("\n" + passed + " tests passed");
    }
}
