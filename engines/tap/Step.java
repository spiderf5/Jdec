import java.io.*;
import java.util.*;

/**
 * Initialises target classes one at a time so the tap can watch each class's
 * <clinit> run, and attributes new plaintext to the class that produced it.
 *
 * Why per-class attribution matters: ZKM 27 inlines a copy of the decryptor
 * into every class that carries encrypted strings, so doFinal fires from
 * inside whichever class is being initialised. StringsSpy sees only the
 * plaintext; the driver sees the timing. Everything recorded between the
 * start and the end of one Class.forName() belongs to that class.
 *
 * Crash protocol: a native crash kills the JVM without running any
 * shutdown hook. Two things keep the data alive:
 *   1. StringsSpy's append-on-record log (-Dstringspy.out) survives --
 *      plaintext without attribution.
 *   2. The attribution file (-Dstep.attrib) is appended per class as it
 *      completes, so at most the crashing class loses attribution.
 *
 * Usage:
 *   java -Dstep.classes=safe.txt -Dstep.attrib=attributed.tsv \
 *        -Dstep.log=step.log -Dstringspy.out=raw.tsv \
 *        -javaagent:stringspy.jar -cp target.jar;tap Step
 */
public class Step {

    public static void main(String[] args) throws Exception {
        List<String> classes = readClasses(args);
        String attribPath = System.getProperty("step.attrib");
        String logPath = System.getProperty("step.log");

        PrintWriter attrib = attribPath == null ? null
                : new PrintWriter(new OutputStreamWriter(
                        new FileOutputStream(attribPath, true), "UTF-8"), true);
        PrintStream log = logPath == null ? System.out
                : new PrintStream(new FileOutputStream(logPath, true), true);

        log.println("# begin " + classes.size() + " classes "
                + new java.util.Date());

        Set<String> seen = new HashSet<String>(StringsSpy.flat());
        int ok = 0, failed = 0, silent = 0;

        for (String cn : classes) {
            try {
                // class list uses internal names (pkg/A); forName wants dots
                Class.forName(cn.replace('/', '.'), true, Step.class.getClassLoader());
                ok++;
            } catch (Throwable t) {
                failed++;
                // A failed <clinit> may still have decrypted strings first --
                // the class is marked erroneous but the plaintext is real.
                log.println("failed\t" + cn + "\t" + t.getClass().getName()
                        + ": " + t.getMessage());
            }
            int fresh = attribute(cn, seen, attrib);
            if (fresh == 0) silent++;
            log.println("done\t" + cn + "\tfresh=" + fresh);
            log.flush();
        }

        log.println("# end ok=" + ok + " failed=" + failed
                + " silent=" + silent + " total=" + StringsSpy.total());
        log.flush();
        if (attrib != null) attrib.close();
    }

    /** Plaintext produced by this class = set difference, written out now. */
    private static int attribute(String cn, Set<String> seen, PrintWriter out) {
        if (out == null) return 0;
        int n = 0;
        for (String s : StringsSpy.flat()) {
            if (seen.add(s)) {
                out.println(cn + "\t" + s.replace("\t", " ")
                        .replace("\r", "\\r").replace("\n", "\\n"));
                n++;
            }
        }
        return n;
    }

    private static List<String> readClasses(String[] args) throws IOException {
        List<String> out = new ArrayList<String>();
        String listFile = System.getProperty("step.classes");
        if (listFile != null) {
            BufferedReader r = new BufferedReader(new InputStreamReader(
                    new FileInputStream(listFile), "UTF-8"));
            try {
                for (String line = r.readLine(); line != null; line = r.readLine()) {
                    line = line.trim();
                    if (!line.isEmpty() && !line.startsWith("#")) out.add(line);
                }
            } finally {
                r.close();
            }
        } else {
            for (String a : args) out.add(a);
        }
        return out;
    }
}
