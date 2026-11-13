package dev.jvch.radar;

/** Address classification. Documentation ranges count as external so the bundled samples behave like real scans. */
public final class Net {
    private Net() {}

    public static boolean isExternal(String addr) {
        if (addr.indexOf(':') >= 0) {
            String a = addr.toLowerCase();
            return !(a.equals("::1") || a.startsWith("fe8") || a.startsWith("fe9") || a.startsWith("fea") || a.startsWith("feb")
                || a.startsWith("fc") || a.startsWith("fd"));
        }
        String[] p = addr.split("\\.");
        if (p.length != 4) return true;
        int[] o = new int[4];
        try { for (int i = 0; i < 4; i++) o[i] = Integer.parseInt(p[i]); } catch (NumberFormatException e) { return true; }
        if (o[0] == 10 || o[0] == 127 || o[0] == 0) return false;
        if (o[0] == 172 && o[1] >= 16 && o[1] <= 31) return false;
        if (o[0] == 192 && o[1] == 168) return false;
        if (o[0] == 169 && o[1] == 254) return false;
        return !(o[0] == 100 && o[1] >= 64 && o[1] <= 127);
    }
}
