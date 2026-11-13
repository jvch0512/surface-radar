package dev.jvch.radar;

import dev.jvch.radar.Model.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** surface-radar never touches the network: it only reads nmap XML you already have. */
public final class Main {
    static final String USAGE = """
        surface-radar report [options] SCAN.xml
        surface-radar diff   [options] OLD.xml NEW.xml

        options:
          --format text|md|json     output format (default text for report, md for diff)
          --scope external|all      flag risky services only on public addresses (default) or everywhere
          --fail-on critical|high|medium|low|none
                                    exit 1 when a finding at or above this level exists (diff: only new ones). default critical
        """;

    public static void main(String[] args) {
        System.exit(run(args, System.out, System.err));
    }

    public static int run(String[] args, java.io.PrintStream out, java.io.PrintStream err) {
        if (args.length == 0 || args[0].equals("--help") || args[0].equals("-h")) {
            out.print(USAGE);
            return args.length == 0 ? 2 : 0;
        }
        String cmd = args[0];
        String format = null, failOn = "critical";
        Rules.Scope scope = Rules.Scope.EXTERNAL;
        List<String> files = new ArrayList<>();
        try {
            for (int i = 1; i < args.length; i++) {
                switch (args[i]) {
                    case "--format" -> format = need(args, ++i);
                    case "--scope" -> scope = need(args, ++i).equalsIgnoreCase("all") ? Rules.Scope.ALL
                        : need(args, i).equalsIgnoreCase("external") ? Rules.Scope.EXTERNAL : fail("scope must be external or all");
                    case "--fail-on" -> failOn = need(args, ++i).toLowerCase();
                    default -> { if (args[i].startsWith("--")) fail("unknown option " + args[i]); files.add(args[i]); }
                }
            }
            if (!failOn.equals("none")) Severity.parse(failOn);
            if (format != null && !List.of("text", "md", "json").contains(format)) fail("format must be text, md or json");
            if (cmd.equals("report") && files.size() == 1) {
                Scan s = load(files.get(0));
                List<Finding> fs = Rules.evaluate(s, scope);
                String f = format == null ? "text" : format;
                out.print(f.equals("json") ? Report.json(s, fs) : f.equals("md") ? Report.markdown(s, fs) : Report.text(s, fs));
                return exceeds(fs, failOn) ? 1 : 0;
            }
            if (cmd.equals("diff") && files.size() == 2) {
                Diff.Result d = Diff.compare(load(files.get(0)), load(files.get(1)), scope);
                String f = format == null ? "md" : format;
                out.print(f.equals("json") ? Report.diffJson(d) : Report.diffMarkdown(d));
                return exceeds(d.newFindings(), failOn) ? 1 : 0;
            }
            err.print(USAGE);
            return 2;
        } catch (IllegalArgumentException e) {
            err.println("error: " + e.getMessage());
            return 2;
        }
    }

    private static boolean exceeds(List<Finding> fs, String failOn) {
        if (failOn.equals("none")) return false;
        int min = Severity.parse(failOn).weight;
        return fs.stream().anyMatch(f -> f.severity().weight >= min);
    }

    private static Scan load(String path) {
        try {
            return NmapParser.parse(new String(Files.readAllBytes(Path.of(path)), StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new IllegalArgumentException("cannot read " + path + ": " + e.getMessage());
        }
    }

    private static String need(String[] a, int i) {
        if (i >= a.length) throw new IllegalArgumentException("missing value for " + a[i - 1]);
        return a[i];
    }

    private static <T> T fail(String m) { throw new IllegalArgumentException(m); }
}
