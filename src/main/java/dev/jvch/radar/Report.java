package dev.jvch.radar;

import dev.jvch.radar.Model.*;

import java.util.*;

/** Text, Markdown and JSON renderings. JSON is hand-written to keep the project dependency free. */
public final class Report {
    private Report() {}

    public record HostScore(Host host, int score, List<Finding> findings) {}

    public static List<HostScore> score(Scan scan, List<Finding> findings) {
        Map<String, List<Finding>> by = new LinkedHashMap<>();
        for (Finding f : findings) by.computeIfAbsent(f.host(), k -> new ArrayList<>()).add(f);
        List<HostScore> out = new ArrayList<>();
        for (Host h : scan.hosts()) {
            List<Finding> fs = new ArrayList<>(by.getOrDefault(h.label(), List.of()));
            fs.sort(Comparator.comparing((Finding f) -> f.severity().weight).reversed().thenComparing(Finding::port));
            int s = 0;
            for (Finding f : fs) s += f.severity().weight;
            out.add(new HostScore(h, Math.min(100, s), fs));
        }
        out.sort(Comparator.comparingInt(HostScore::score).reversed().thenComparing(x -> x.host().addr()));
        return out;
    }

    public static String markdown(Scan scan, List<Finding> findings) {
        List<HostScore> hs = score(scan, findings);
        StringBuilder b = new StringBuilder("# Attack surface report\n\n");
        long open = scan.hosts().stream().mapToLong(h -> h.ports().stream().filter(Model.Port::open).count()).sum();
        b.append(scan.hosts().size()).append(" hosts up, ").append(open).append(" open ports, ").append(findings.size()).append(" findings");
        if (scan.start().isAfter(java.time.Instant.EPOCH)) b.append(". Scan started ").append(scan.start());
        b.append(".\n\n| Host | Score | Critical | High | Medium | Low |\n|---|---:|---:|---:|---:|---:|\n");
        for (HostScore s : hs) b.append("| ").append(esc(s.host.label())).append(" | ").append(s.score).append(" | ")
            .append(count(s.findings, Severity.CRITICAL)).append(" | ").append(count(s.findings, Severity.HIGH)).append(" | ")
            .append(count(s.findings, Severity.MEDIUM)).append(" | ").append(count(s.findings, Severity.LOW)).append(" |\n");
        for (HostScore s : hs) {
            if (s.findings.isEmpty()) continue;
            b.append("\n## ").append(esc(s.host.label())).append(" (score ").append(s.score).append(")\n\n");
            for (Finding f : s.findings) b.append("- **").append(f.severity()).append("** ").append(esc(f.title())).append(" on ").append(f.port())
                .append(": ").append(esc(f.detail())).append('\n');
        }
        return b.toString();
    }

    public static String text(Scan scan, List<Finding> findings) {
        StringBuilder b = new StringBuilder();
        for (HostScore s : score(scan, findings)) {
            b.append(String.format("%-34s score %3d  %d findings%n", s.host.label(), s.score, s.findings.size()));
            for (Finding f : s.findings) b.append(String.format("    %-8s %-10s %s%n", f.severity(), f.port(), f.title()));
        }
        return b.toString();
    }

    public static String json(Scan scan, List<Finding> findings) {
        StringBuilder b = new StringBuilder("{\n  \"scanStart\": ").append(q(scan.start().toString())).append(",\n  \"hosts\": [");
        List<HostScore> hs = score(scan, findings);
        for (int i = 0; i < hs.size(); i++) {
            HostScore s = hs.get(i);
            b.append(i == 0 ? "\n" : ",\n").append("    {\"address\": ").append(q(s.host.addr())).append(", \"hostname\": ").append(q(s.host.hostname()))
                .append(", \"score\": ").append(s.score).append(", \"findings\": [");
            for (int j = 0; j < s.findings.size(); j++) b.append(j == 0 ? "" : ", ").append(finding(s.findings.get(j)));
            b.append("]}");
        }
        return b.append(hs.isEmpty() ? "" : "\n  ").append("]\n}\n").toString();
    }

    public static String diffMarkdown(Diff.Result d) {
        StringBuilder b = new StringBuilder("# Attack surface change report\n\n");
        if (d.empty()) return b.append("No changes between the two scans.\n").toString();
        list(b, "New hosts", d.newHosts());
        list(b, "Hosts no longer seen", d.goneHosts());
        changes(b, "Newly open ports", d.opened());
        changes(b, "Closed ports", d.closed());
        changes(b, "Service or version changed", d.changed());
        findings(b, "New findings", d.newFindings());
        findings(b, "Resolved findings", d.resolvedFindings());
        return b.toString();
    }

    public static String diffJson(Diff.Result d) {
        StringBuilder b = new StringBuilder("{\n");
        b.append("  \"newHosts\": ").append(strs(d.newHosts())).append(",\n  \"goneHosts\": ").append(strs(d.goneHosts())).append(",\n");
        b.append("  \"opened\": ").append(pcs(d.opened())).append(",\n  \"closed\": ").append(pcs(d.closed())).append(",\n  \"changed\": ").append(pcs(d.changed())).append(",\n");
        b.append("  \"newFindings\": [");
        for (int i = 0; i < d.newFindings().size(); i++) b.append(i == 0 ? "" : ", ").append(finding(d.newFindings().get(i)));
        b.append("],\n  \"resolvedFindings\": [");
        for (int i = 0; i < d.resolvedFindings().size(); i++) b.append(i == 0 ? "" : ", ").append(finding(d.resolvedFindings().get(i)));
        return b.append("]\n}\n").toString();
    }

    private static void list(StringBuilder b, String h, List<String> xs) {
        if (xs.isEmpty()) return;
        b.append("## ").append(h).append("\n\n");
        for (String x : xs) b.append("- ").append(esc(x)).append('\n');
        b.append('\n');
    }

    private static void changes(StringBuilder b, String h, List<Diff.PortChange> xs) {
        if (xs.isEmpty()) return;
        b.append("## ").append(h).append("\n\n");
        for (Diff.PortChange c : xs) {
            b.append("- ").append(esc(c.host())).append(" ").append(c.port()).append(": ");
            if (c.before() == null) b.append(esc(c.after()));
            else if (c.after() == null) b.append("was ").append(esc(c.before()));
            else b.append(esc(c.before())).append(" to ").append(esc(c.after()));
            b.append('\n');
        }
        b.append('\n');
    }

    private static void findings(StringBuilder b, String h, List<Finding> xs) {
        if (xs.isEmpty()) return;
        b.append("## ").append(h).append("\n\n");
        for (Finding f : xs) b.append("- **").append(f.severity()).append("** ").append(esc(f.host())).append(" ").append(f.port()).append(": ").append(esc(f.title())).append('\n');
        b.append('\n');
    }

    private static long count(List<Finding> fs, Severity s) { return fs.stream().filter(f -> f.severity() == s).count(); }

    private static String finding(Finding f) {
        return "{\"rule\": " + q(f.rule()) + ", \"severity\": " + q(f.severity().name().toLowerCase()) + ", \"port\": " + q(f.port())
            + ", \"title\": " + q(f.title()) + ", \"detail\": " + q(f.detail()) + "}";
    }

    private static String strs(List<String> xs) {
        StringBuilder b = new StringBuilder("[");
        for (int i = 0; i < xs.size(); i++) b.append(i == 0 ? "" : ", ").append(q(xs.get(i)));
        return b.append("]").toString();
    }

    private static String pcs(List<Diff.PortChange> xs) {
        StringBuilder b = new StringBuilder("[");
        for (int i = 0; i < xs.size(); i++) {
            Diff.PortChange c = xs.get(i);
            b.append(i == 0 ? "" : ", ").append("{\"host\": ").append(q(c.host())).append(", \"port\": ").append(q(c.port()))
                .append(", \"before\": ").append(c.before() == null ? "null" : q(c.before())).append(", \"after\": ").append(c.after() == null ? "null" : q(c.after())).append("}");
        }
        return b.append("]").toString();
    }

    /** Banners come from scanned hosts, so every string is escaped, including control characters. */
    public static String q(String s) {
        if (s == null) return "null";
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> b.append("\\\"");
                case '\\' -> b.append("\\\\");
                case '\n' -> b.append("\\n");
                case '\r' -> b.append("\\r");
                case '\t' -> b.append("\\t");
                default -> { if (c < 0x20) b.append(String.format("\\u%04x", (int) c)); else b.append(c); }
            }
        }
        return b.append('"').toString();
    }

    /** Markdown cells and list items: banners must not be able to inject tables, links or HTML. */
    static String esc(String s) {
        return s == null ? "" : s.replaceAll("[\\r\\n]+", " ").replace("\\", "\\\\").replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;").replace("[", "\\[").replace("]", "\\]");
    }
}
