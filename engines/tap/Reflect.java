import java.io.*;
import java.lang.reflect.*;
import java.util.*;

/**
 * Invokes the decryptor methods with their statically extracted arguments.
 *
 * Why this instead of just initialising classes: the decryptor is lazy.
 * Strings decrypt on first USE, inside whatever method uses them; class init
 * only builds the ciphertext tables (verified: 3 clean class inits captured
 * 0 plaintexts through the Cipher tap). Every use site, however, is a static
 * call with hard-coded constant arguments, extracted by tap_extract.py. So
 * replaying those exact arguments through reflection recovers every plaintext
 * the bytecode could ever ask for - without running any game logic.
 *
 * Input  (-Dtap.calls=calls.tsv):  class \t method \t descriptor \t args...
 * Output (-Dtap.out=decoded.tsv):  class \t method \t descriptor \t args \t result
 * Optional (-Dtap.classes=file): whitelist of classes worth initialising.
 * Optional (-Dtap.log=file): per-class progress and failures.
 *
 * Every result line is flushed immediately: a tamper check or unexpected
 * native call in some <clinit> can still kill the JVM, and the data written
 * before that must survive.
 */
public class Reflect {

    public static void main(String[] args) throws Exception {
        String callsPath = System.getProperty("tap.calls", "calls.tsv");
        String allowPath = System.getProperty("tap.classes");
        String outPath = System.getProperty("tap.out", "decoded.tsv");
        String logPath = System.getProperty("tap.log");

        Set<String> allow = allowPath == null ? null
                : new HashSet<String>(readLines(allowPath));

        // group call sites by class, preserving file order
        Map<String, List<String[]>> byClass = new LinkedHashMap<String, List<String[]>>();
        for (String line : readLines(callsPath)) {
            String[] p = line.split("\t", -1);
            if (p.length < 4) continue;
            if (allow != null && !allow.contains(p[0])) continue;
            List<String[]> list = byClass.get(p[0]);
            if (list == null) { list = new ArrayList<String[]>(); byClass.put(p[0], list); }
            list.add(p);
        }

        PrintWriter out = new PrintWriter(new OutputStreamWriter(
                new FileOutputStream(outPath, true), "UTF-8"), true);
        PrintStream log = logPath == null ? System.out
                : new PrintStream(new FileOutputStream(logPath, true), true);

        log.println("# begin " + byClass.size() + " classes " + new Date());

        int classesOk = 0, classesSkip = 0, ok = 0, failed = 0, strings = 0;

        for (Map.Entry<String, List<String[]>> en : byClass.entrySet()) {
            String cls = en.getKey();
            Class<?> c;
            try {
                c = Class.forName(cls.replace('/', '.'), true, Reflect.class.getClassLoader());
            } catch (Throwable t) {
                classesSkip++;
                log.println("skip\t" + cls + "\t" + t.getClass().getName()
                        + ": " + t.getMessage());
                log.flush();
                continue;
            }
            classesOk++;

            Map<String, Method> cache = new HashMap<String, Method>();
            for (String[] site : en.getValue()) {
                String mname = site[1], desc = site[2];
                String key = mname + desc;
                Method m = cache.get(key);
                if (m == null && !cache.containsKey(key)) {
                    try {
                        m = find(c, mname, desc);
                        m.setAccessible(true);
                    } catch (Throwable t) {
                        m = null;
                        log.println("nomethod\t" + cls + "\t" + mname + desc
                                + "\t" + t);
                    }
                    cache.put(key, m);
                }
                if (m == null) { failed++; continue; }

                String argText = joinArgs(site);
                try {
                    Object[] argv = buildArgs(desc, site);
                    Object r = m.invoke(null, argv);
                    ok++;
                    if (r instanceof String) {
                        strings++;
                        out.println(cls + "\t" + mname + "\t" + desc + "\t"
                                + argText + "\t" + esc((String) r));
                    } else if (r != null) {
                        out.println(cls + "\t" + mname + "\t" + desc + "\t"
                                + argText + "\t#const " + r);
                    }
                } catch (InvocationTargetException te) {
                    failed++;
                    Throwable cause = te.getCause() != null ? te.getCause() : te;
                    log.println("callfail\t" + cls + "\t" + mname + desc
                            + "\t" + argText + "\t" + cause);
                } catch (Throwable t) {
                    failed++;
                    log.println("callfail\t" + cls + "\t" + mname + desc
                            + "\t" + argText + "\t" + t);
                }
            }
            out.flush();
            log.println("class\t" + cls + "\tsites=" + en.getValue().size());
            log.flush();
        }

        log.println("# end classes_ok=" + classesOk + " classes_skip=" + classesSkip
                + " calls_ok=" + ok + " calls_failed=" + failed
                + " strings=" + strings);
        log.flush();
        out.close();
    }

    // ------------------------------------------------------------- reflection

    private static Method find(Class<?> c, String name, String desc)
            throws Exception {
        Class<?>[] params = paramClasses(desc);
        return c.getDeclaredMethod(name, params);
    }

    /** Descriptor -> parameter Classes; supports the primitive subset used here. */
    private static Class<?>[] paramClasses(String desc) throws ClassNotFoundException {
        List<Class<?>> out = new ArrayList<Class<?>>();
        int i = 1;
        while (desc.charAt(i) != ')') {
            char t = desc.charAt(i);
            if (t == 'I') out.add(int.class);
            else if (t == 'J') out.add(long.class);
            else if (t == 'Z') out.add(boolean.class);
            else if (t == 'B') out.add(byte.class);
            else if (t == 'C') out.add(char.class);
            else if (t == 'S') out.add(short.class);
            else if (t == 'F') out.add(float.class);
            else if (t == 'D') out.add(double.class);
            else if (t == 'L') {
                int end = desc.indexOf(';', i);
                String name = desc.substring(i + 1, end).replace('/', '.');
                out.add(Class.forName(name, false, Reflect.class.getClassLoader()));
                i = end;
            } else if (t == '[') {
                // not expected in decryptor signatures; fail loudly if seen
                throw new ClassNotFoundException("array parameter in " + desc);
            }
            i++;
        }
        return out.toArray(new Class<?>[0]);
    }

    private static Object[] buildArgs(String desc, String[] site) {
        Class<?>[] types;
        try {
            types = paramClasses(desc);
        } catch (Throwable t) {
            throw new RuntimeException(t);
        }
        Object[] out = new Object[types.length];
        for (int k = 0; k < types.length; k++) {
            String raw = site[3 + k];
            if (types[k] == int.class) out[k] = Integer.valueOf(raw);
            else if (types[k] == long.class) out[k] = Long.valueOf(raw);
            else throw new IllegalArgumentException("unsupported arg " + raw);
        }
        return out;
    }

    private static String joinArgs(String[] site) {
        StringBuilder b = new StringBuilder();
        for (int k = 3; k < site.length; k++) {
            if (b.length() > 0) b.append(',');
            b.append(site[k]);
        }
        return b.toString();
    }

    private static String esc(String v) {
        return v.replace("\t", " ").replace("\r", "\\r").replace("\n", "\\n");
    }

    // -------------------------------------------------------------------- io

    private static List<String> readLines(String path) throws IOException {
        List<String> out = new ArrayList<String>();
        BufferedReader r = new BufferedReader(new InputStreamReader(
                new FileInputStream(path), "UTF-8"));
        try {
            for (String line = r.readLine(); line != null; line = r.readLine()) {
                line = line.trim();
                if (!line.isEmpty() && !line.startsWith("#")) out.add(line);
            }
        } finally {
            r.close();
        }
        return out;
    }
}
