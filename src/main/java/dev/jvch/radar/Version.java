package dev.jvch.radar;

/** Dotted numeric version comparison that ignores trailing suffixes such as "p1" or "-ubuntu". */
public final class Version {
    private Version() {}

    public static int compare(String a, String b) {
        int[] x = nums(a), y = nums(b);
        for (int i = 0; i < Math.max(x.length, y.length); i++) {
            int u = i < x.length ? x[i] : 0, v = i < y.length ? y[i] : 0;
            if (u != v) return Integer.compare(u, v);
        }
        return 0;
    }

    static int[] nums(String s) {
        String[] parts = s.trim().split("\\.");
        int[] out = new int[parts.length];
        int n = 0;
        for (String p : parts) {
            int i = 0;
            while (i < p.length() && Character.isDigit(p.charAt(i))) i++;
            if (i == 0) break;
            try { out[n++] = Integer.parseInt(p.substring(0, Math.min(i, 9))); } catch (NumberFormatException e) { break; }
            if (i < p.length()) break; // suffix ends the numeric prefix
        }
        return java.util.Arrays.copyOf(out, n);
    }
}
