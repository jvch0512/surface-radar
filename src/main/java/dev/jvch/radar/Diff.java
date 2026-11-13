package dev.jvch.radar;

import dev.jvch.radar.Model.*;

import java.util.*;

/** Compares two scans of the same estate. Hosts are matched by address. */
public final class Diff {
    public record PortChange(String host, String port, String before, String after) {}

    public record Result(List<String> newHosts, List<String> goneHosts, List<PortChange> opened, List<PortChange> closed,
                         List<PortChange> changed, List<Finding> newFindings, List<Finding> resolvedFindings) {
        public boolean empty() {
            return newHosts.isEmpty() && goneHosts.isEmpty() && opened.isEmpty() && closed.isEmpty() && changed.isEmpty()
                && newFindings.isEmpty() && resolvedFindings.isEmpty();
        }
    }

    private Diff() {}

    public static Result compare(Scan before, Scan after, Rules.Scope scope) {
        Map<String, Host> a = byAddr(before), b = byAddr(after);
        List<String> newHosts = new ArrayList<>(), gone = new ArrayList<>();
        List<PortChange> opened = new ArrayList<>(), closed = new ArrayList<>(), changed = new ArrayList<>();
        for (String addr : new TreeSet<>(b.keySet())) if (!a.containsKey(addr)) newHosts.add(b.get(addr).label());
        for (String addr : new TreeSet<>(a.keySet())) if (!b.containsKey(addr)) gone.add(a.get(addr).label());
        for (String addr : new TreeSet<>(b.keySet())) {
            Host old = a.get(addr);
            if (old == null) continue;
            Map<String, Port> op = openPorts(old), np = openPorts(b.get(addr));
            for (String k : new TreeSet<>(np.keySet())) {
                if (!op.containsKey(k)) opened.add(new PortChange(b.get(addr).label(), k, null, np.get(k).banner()));
                else if (!op.get(k).banner().equals(np.get(k).banner()))
                    changed.add(new PortChange(b.get(addr).label(), k, op.get(k).banner(), np.get(k).banner()));
            }
            for (String k : new TreeSet<>(op.keySet())) if (!np.containsKey(k)) closed.add(new PortChange(old.label(), k, op.get(k).banner(), null));
        }
        Map<String, Finding> fa = index(Rules.evaluate(before, scope)), fb = index(Rules.evaluate(after, scope));
        List<Finding> added = new ArrayList<>(), resolved = new ArrayList<>();
        for (Map.Entry<String, Finding> e : fb.entrySet()) if (!fa.containsKey(e.getKey())) added.add(e.getValue());
        for (Map.Entry<String, Finding> e : fa.entrySet()) if (!fb.containsKey(e.getKey())) resolved.add(e.getValue());
        Comparator<Finding> bySev = Comparator.comparing((Finding f) -> f.severity().weight).reversed().thenComparing(Finding::host).thenComparing(Finding::port);
        added.sort(bySev);
        resolved.sort(bySev);
        return new Result(newHosts, gone, opened, closed, changed, added, resolved);
    }

    private static Map<String, Host> byAddr(Scan s) {
        Map<String, Host> m = new LinkedHashMap<>();
        for (Host h : s.hosts()) m.put(h.addr(), h);
        return m;
    }

    private static Map<String, Port> openPorts(Host h) {
        Map<String, Port> m = new LinkedHashMap<>();
        for (Port p : h.ports()) if (p.open()) m.put(p.key(), p);
        return m;
    }

    /** A finding that only changed wording (e.g. "expires in 29 days" to "28 days") is still the same finding. */
    private static Map<String, Finding> index(List<Finding> fs) {
        Map<String, Finding> m = new LinkedHashMap<>();
        for (Finding f : fs) m.putIfAbsent(f.rule() + "|" + f.host().replaceAll(".*\\(", "").replace(")", "") + "|" + f.port() + "|" + f.title().replaceAll("\\d+ days", "N days"), f);
        return m;
    }
}
