import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.Field;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * BVMTrace - stage-3 runtime trace logger for the BytecodeVM fixture jar.
 *
 * This class carries NO ASM dependency so it can be packed verbatim into the
 * instrumented jar. The bytecode rewriting lives in BVMTraceTransform.
 *
 * Injected call (per VM flavor dispatch loop, jar-verified invariants):
 *   iload 4   ; mapped opcode
 *   iload 49  ; physical slot index into the pool streams
 *   iload 62  ; loop-carried constant int (unknown role, logged for analysis)
 *   aload Lh  ; handler instance (a Flavor$Shard$N)
 *   invokestatic BVMTrace.mark (IIILjava/lang/Object;)V
 *
 * Trace TSV (tab separated), deterministic (no timestamps, single thread):
 *   E <seq> <set> <shard_ordinal> <semanticToken> <mapped> <slot> <aux62>
 */
public class BVMTrace {

    private static final Pattern SET_PAT =
            Pattern.compile("\\.BytecodeVM\\$(\\d+)\\$");
    private static final Pattern SHARD_PAT = Pattern.compile("Shard\\$(\\d+)$");

    private static PrintWriter out;
    private static long seq = 0;

    static {
        try {
            String p = System.getProperty("bvmw.trace", "bvmw_trace.tsv");
            out = new PrintWriter(new BufferedWriter(new FileWriter(p), 1 << 16),
                    false);
        } catch (IOException e) {
            System.err.println("[BVMTrace] cannot open trace file: " + e);
            out = null;
        }
        Runtime.getRuntime().addShutdownHook(new Thread(BVMTrace::flushTrace));
    }

    /** Injected before every inner-VM handler dispatch. */
    public static void mark(int mapped, int slot, int aux, Object handler) {
        PrintWriter w = out;
        if (w == null || handler == null) {
            return;
        }
        String cn = handler.getClass().getName();
        int set = -1;
        Matcher m = SET_PAT.matcher(cn);
        if (m.find()) {
            set = Integer.parseInt(m.group(1));
        }
        int shard = -1;
        Matcher ms = SHARD_PAT.matcher(cn);
        if (ms.find()) {
            shard = Integer.parseInt(ms.group(1));
        }
        int seed = Integer.MIN_VALUE;
        try {
            Field f = handler.getClass().getDeclaredField("semanticToken");
            f.setAccessible(true);
            seed = f.getInt(handler);
        } catch (Exception ignore) {
            // seed stays Integer.MIN_VALUE, visible in the TSV
        }
        w.println("E\t" + seq++ + "\t" + set + "\t" + shard + "\t" + seed
                + "\t" + mapped + "\t" + slot + "\t" + aux);
    }

    public static void flushTrace() {
        if (out != null) {
            out.flush();
        }
    }

    private static void runDriver() throws Exception {
        try {
            Class<?> calc = Class.forName("Calc");
            System.out.println("add(2,3)=" + calc.getMethod("add", int.class,
                    int.class).invoke(null, 2, 3));
            System.out.println("greet=" + calc.getMethod("greet",
                    String.class).invoke(null, "world"));
            System.out.println("mix=" + calc.getMethod("mix", long.class)
                    .invoke(null, 305419896L));
        } finally {
            flushTrace();
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 1 && args[0].equals("run")) {
            runDriver();
            return;
        }
        System.err.println("usage: BVMTrace run (-Dbvmw.trace=<tsv>)");
        System.exit(2);
    }
}
