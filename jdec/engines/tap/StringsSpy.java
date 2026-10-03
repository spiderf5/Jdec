import java.io.*;
import java.lang.instrument.*;
import java.lang.reflect.Method;
import java.security.ProtectionDomain;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Captures string-decryption plaintext without re-implementing any obfuscator.
 *
 * Why an agent at all: ZKM 27 derives its session key inside an indy bootstrap
 * and rotates cipher setup per class. Any static re-implementation of the key
 * schedule breaks on the next build, and any "call the decryptor for me" approach
 * needs the bootstrap to have run first. So instead of understanding the key, we
 * let the obfuscator run its own code and watch the one JDK chokepoint every
 * variant funnels through -- Cipher.doFinal -- recording the plaintext on the way
 * out. The obfuscator does the work; this only watches.
 *
 * javax.crypto.Cipher is loaded by the bootstrap before most agents attach, so
 * premain retransforms it explicitly. If instrumentation is unavailable the tap
 * degrades to reporting nothing rather than failing the run.
 *
 * Usage:
 *   java -javaagent:stringspy.jar=<outfile> -cp <target.jar> <driver>
 * Then either let the target run and call StringsSpy.dump(path), or use the
 * bundled driver which initialises every class in the jar for us.
 */
public class StringsSpy implements ClassFileTransformer {

    private static final Map<String, Set<String>> PLAIN =
            new ConcurrentHashMap<String, Set<String>>();
    private static volatile boolean active = true;
    private static volatile String tapClass = "javax.crypto.Cipher";
    private static volatile String tapOwner = null;   // null = record for every caller
    private static final boolean VERBOSE =
            System.getProperty("stringspy.verbose") != null;

    // Append-on-record log (-Dstringspy.out=<file>). A crash in native code
    // kills the JVM without running shutdown hooks, so anything only held in
    // PLAIN is lost; writing each plaintext the moment it appears is the only
    // capture guarantee that survives myau.r-style native crashes.
    private static PrintWriter tapFile;
    private static final Object TAP_LOCK = new Object();

    /** Called from premain; opening the log there keeps record() lazy-free. */
    private static void openTapFile() {
        String path = System.getProperty("stringspy.out");
        if (path == null) return;
        try {
            tapFile = new PrintWriter(new OutputStreamWriter(
                    new FileOutputStream(path, true), "UTF-8"), true);
        } catch (Throwable t) {
            System.err.println("[stringspy] cannot open " + path + ": " + t);
        }
    }

    private static String esc(String v) {
        return v.replace("\t", " ").replace("\r", "\\r").replace("\n", "\\n");
    }

    /** Write one plaintext to the append log immediately. */
    private static void note(String text) {
        PrintWriter w = tapFile;
        if (w == null) return;
        synchronized (TAP_LOCK) {
            w.println("<decrypted>\t" + esc(text));
            w.flush();
        }
    }

    /** Called from instrumented doFinal. */
    public static void record(String text) {
        if (!active || text == null || text.isEmpty()) return;
        Set<String> set = PLAIN.get("<decrypted>");
        if (set == null) {
            set = Collections.newSetFromMap(new ConcurrentHashMap<String, Boolean>());
            Set<String> prev = PLAIN.putIfAbsent("<decrypted>", set);
            if (prev != null) set = prev;
        }
        set.add(text);
        note(text);
    }

    public static void setActive(boolean on) { active = on; }

    public static void setTap(String ownerClass) {
        tapOwner = ownerClass;
        tapClass = ownerClass == null ? "javax.crypto.Cipher" : ownerClass;
    }

    public static Map<String, Set<String>> snapshot() {
        return new LinkedHashMap<String, Set<String>>(PLAIN);
    }

    /** Total number of distinct plaintexts recorded so far. */
    public static int total() {
        int n = 0;
        for (Set<String> s : PLAIN.values()) n += s.size();
        return n;
    }

    /**
     * Flat list of everything recorded, in insertion order.
     *
     * The caller compares total() before and after initialising a class to
     * attribute new plaintext to it, so this has to be stable and cheap rather
     * than grouped by caller.
     */
    public static java.util.List<String> flat() {
        java.util.List<String> out = new java.util.ArrayList<String>();
        for (Set<String> s : PLAIN.values()) out.addAll(s);
        return out;
    }

    /** Write TSV: caller class, plaintext (tabs/newlines escaped). */
    public static void dump(String path) throws IOException {
        List<String> keys = new ArrayList<String>(PLAIN.keySet());
        Collections.sort(keys);
        PrintWriter w = new PrintWriter(new OutputStreamWriter(
                new FileOutputStream(path), "UTF-8"));
        try {
            w.println("# caller\tplaintext");
            for (String k : keys) {
                List<String> vals = new ArrayList<String>(PLAIN.get(k));
                Collections.sort(vals);
                for (String v : vals) {
                    w.println(k + "\t" + v.replace("\t", " ")
                                        .replace("\r", "\\r")
                                        .replace("\n", "\\n"));
                }
            }
        } finally {
            w.close();
        }
    }

    // ---------------------------------------------------------------- agent

    public static void premain(String args, Instrumentation inst) {
        install(args, inst);
    }

    public static void agentmain(String args, Instrumentation inst) {
        install(args, inst);
    }

    private static void install(String args, Instrumentation inst) {
        if (inst == null) {
            System.err.println("[stringspy] no Instrumentation; capture disabled");
            return;
        }

        // Register the transformer first, before touching anything else.
        //
        // The varargs ClassFileTransformer... overload is the only one available,
        // and calling it while the VM is still bootstrapping can pull in
        // MethodHandle machinery and throw ClassCircularityError. StringsSpy
        // itself is already loaded (premain runs inside it) and the
        // ClassFileTransformer interface is resolved by then, so this one call is
        // safe; everything after it must be too, so argument parsing comes second.
        inst.addTransformer(new StringsSpy());

        // Open the append-on-record log before any target code can run.
        openTapFile();

        // Agent arguments arrive as a plain String, parsed by hand: String.split
        // would load the regex machinery during bootstrap.
        if (args != null) {
            String key = null;
            StringBuilder val = new StringBuilder();
            for (int i = 0; i <= args.length(); i++) {
                char ch = i < args.length() ? args.charAt(i) : ',';
                if (ch == '=') {
                    key = val.toString();
                    val.setLength(0);
                } else if (ch == ',') {
                    if (key != null) {
                        if ("target".equals(key)) tapClass = val.toString();
                        else if ("owner".equals(key)) tapOwner = val.toString();
                    }
                    key = null;
                    val.setLength(0);
                } else {
                    val.append(ch);
                }
            }
        }

        // A target that is already loaded has to be retransformed explicitly.
        // Anything not yet loaded is caught by transform() on its way in.
        retransform(inst, tapClass);
    }

    private static void retransform(Instrumentation inst, String className) {
        // Kept deliberately minimal: this runs during premain, and anything that
        // needs classes the VM has not finished loading yet will fail. Failure
        // here is not fatal -- an unloaded target is simply instrumented when it
        // arrives, via transform().
        Class<?> target = null;
        try {
            Class<?>[] all = inst.getAllLoadedClasses();
            for (int i = 0; i < all.length; i++) {
                if (all[i].getName().equals(className)) { target = all[i]; break; }
            }
        } catch (Throwable t) {
            return;
        }
        if (target == null) {
            if (VERBOSE) System.err.println("[stringspy] target not loaded yet");
            return;
        }
        try {
            if (!inst.isModifiableClass(target)) {
                if (VERBOSE) System.err.println("[stringspy] target not modifiable");
                return;
            }
            inst.retransformClasses(target);
            if (VERBOSE) System.err.println("[stringspy] retransformed loaded target");
        } catch (Throwable t) {
            if (VERBOSE) System.err.println("[stringspy] retransform failed");
        }
    }

    public byte[] transform(ClassLoader loader, String className,
                            Class<?> beingRedefined, ProtectionDomain pd,
                            byte[] classfileBuffer) {
        if (VERBOSE) {
            System.err.println("[stringspy] transform requested for " + className);
        }
        if (!className.equals(tapClass)) return null;
        try {
            byte[] out = CipherTap.instrument(classfileBuffer, className);
            if (out == null) {
                if (VERBOSE) {
                    System.err.println("[stringspy] " + className + ": declined");
                }
            } else if (VERBOSE) {
                System.err.println("[stringspy] " + className + ": instrumented "
                        + classfileBuffer.length + " -> " + out.length + " bytes");
                // Ask the JVM's own parser to sanity-check before handing the
                // bytes back. A class the verifier rejects kills the whole run,
                // so it is far better to decline here and capture nothing than
                // to bring the process down.
                try {
                    // Verify in a throwaway loader. The bytes cannot simply be
                    // dropped into a child of the app loader: the class is
                    // already being defined from these very bytes, and doing it
                    // twice is a LinkageError rather than a useful verdict.
                    final byte[] bytes = out;
                    ClassLoader probe = new ClassLoader(null) {
                        @Override protected Class<?> findClass(String n)
                                throws ClassNotFoundException {
                            return defineClass(n, bytes, 0, bytes.length);
                        }
                    };
                    probe.loadClass(className);
                    if (VERBOSE) {
                        System.err.println("[stringspy] " + className + ": accepted");
                    }
                } catch (Throwable verify) {
                    System.err.println("[stringspy] " + className
                            + ": REJECTED by defineClass, leaving original: "
                            + verify);
                    return null;
                }
            }
            return out;
        } catch (Throwable t) {
            System.err.println("[stringspy] transform failed for " + className
                    + ": " + t);
            t.printStackTrace();
            return null;
        }
    }

    public static void main(String[] args) throws Exception {
        // standalone: dump whatever was collected, then exit
        String out = args.length > 0 ? args[0] : "strings.tsv";
        dump(out);
        System.out.println("[stringspy] wrote " + out + " ("
                + snapshot().size() + " caller classes)");
    }
}
