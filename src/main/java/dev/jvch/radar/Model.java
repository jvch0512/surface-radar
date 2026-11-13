package dev.jvch.radar;

import java.time.Instant;
import java.util.List;

/** Plain data carried between the parser, the rules and the reports. */
public final class Model {
    private Model() {}

    public record Cert(String subject, String issuer, Instant notBefore, Instant notAfter) {
        public boolean selfSigned() { return subject != null && subject.equals(issuer); }
    }

    public record Port(int number, String proto, String state, String service, String product,
                       String version, Cert cert, List<String> tlsVersions) {
        public String key() { return number + "/" + proto; }
        public boolean open() { return state.equals("open"); }
        public String banner() {
            StringBuilder b = new StringBuilder(service == null ? "unknown" : service);
            if (product != null && !product.isEmpty()) b.append(" ").append(product);
            if (version != null && !version.isEmpty()) b.append(" ").append(version);
            return b.toString();
        }
    }

    public record Host(String addr, String hostname, List<Port> ports) {
        public String label() { return hostname == null || hostname.isEmpty() ? addr : hostname + " (" + addr + ")"; }
    }

    public record Scan(Instant start, List<Host> hosts) {}

    public enum Severity {
        LOW(4), MEDIUM(12), HIGH(25), CRITICAL(40);
        public final int weight;
        Severity(int w) { weight = w; }
        public static Severity parse(String s) {
            for (Severity v : values()) if (v.name().equalsIgnoreCase(s)) return v;
            throw new IllegalArgumentException("unknown severity: " + s);
        }
    }

    /** id is stable across scans: rule + host + port, so diffs can tell new from existing. */
    public record Finding(String rule, Severity severity, String host, String port, String title, String detail) {
        public String id() { return rule + "|" + host + "|" + port; }
    }
}
