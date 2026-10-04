import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.lang.reflect.Method;
import java.util.*;
import java.util.Base64;

/** String-pool replay driver (jdec pool subcommand).
 *  Spec: S\tfqcn\tmeth\tidx\tseed  (one line per call site)
 *  Out:  R\tfqcn\tmeth\tidx\tseed\tbase64(plaintext)   on success
 *        E\tfqcn\tmeth\tidx\tseed\trootCauseClass: msg  on failure
 *  Class-init failures are cached per class; E lines carry the deepest cause.
 *  idx/seed travel as long and are coerced to the accessor's real param types
 *  (int/long all four combinations). Force-exit: target code may leave
 *  non-daemon threads alive. */
public class PoolDriver {
    public static void main(String[] args) throws Exception {
        List<String[]> spec = new ArrayList<>();
        for (String line : Files.readAllLines(Paths.get(args[0]), StandardCharsets.UTF_8)) {
            if (line.isBlank() || line.startsWith("#") || !line.startsWith("S\t")) continue;
            spec.add(line.split("\t", -1));
        }
        spec.sort(Comparator.comparing((String[] f) -> f[1]).thenComparing(f -> f[2]));
        PrintStream out = new PrintStream(new BufferedOutputStream(
                new FileOutputStream(args[1]), 1 << 16), false, "UTF-8");
        Map<String, Class<?>> classes = new HashMap<>();
        Map<String, Method> methods = new HashMap<>();
        Set<String> failed = new HashSet<>();
        int ok = 0, err = 0;
        for (String[] f : spec) {
            String fqcn = f[1], meth = f[2];
            long idx = Long.parseLong(f[3]);
            long seed = Long.parseLong(f[4]);
            String ck = fqcn + "::" + meth;
            try {
                Class<?> c = classes.get(fqcn);
                if (c == null) {
                    if (failed.contains(fqcn)) throw new IllegalStateException("classInitFailed");
                    try {
                        c = Class.forName(fqcn, true, PoolDriver.class.getClassLoader());
                        classes.put(fqcn, c);
                    } catch (Throwable t) {
                        failed.add(fqcn);
                        Throwable cur = t;
                        while (cur.getCause() != null) cur = cur.getCause();
                        throw new IllegalStateException("classInitFailed: "
                                + cur.getClass().getName() + ": " + cur.getMessage());
                    }
                }
                Method m = methods.get(ck);
                if (m == null) {
                    for (Method mm : c.getDeclaredMethods()) {
                        if (mm.getName().equals(meth) && mm.getParameterCount() == 2
                                && mm.getReturnType() == String.class) { m = mm; break; }
                    }
                    if (m == null) throw new NoSuchMethodException(meth + "(2 params)->String");
                    m.setAccessible(true);
                    methods.put(ck, m);
                }
                Object r;
                Class<?> p0 = m.getParameterTypes()[0], p1 = m.getParameterTypes()[1];
                if (p0 == int.class && p1 == int.class) r = m.invoke(null, (int) idx, (int) seed);
                else if (p0 == long.class && p1 == long.class) r = m.invoke(null, idx, seed);
                else if (p0 == int.class && p1 == long.class) r = m.invoke(null, (int) idx, seed);
                else if (p0 == long.class && p1 == int.class) r = m.invoke(null, idx, (int) seed);
                else r = m.invoke(null, (int) idx, (int) seed);
                String s = (String) r;
                out.println("R\t" + fqcn + "\t" + meth + "\t" + idx + "\t" + seed + "\t"
                        + Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8)));
                ok++;
            } catch (Throwable t) {
                Throwable cur = t;
                while (cur.getCause() != null) cur = cur.getCause();
                String msg = cur.getClass().getName() + ": " + cur.getMessage();
                if (cur instanceof IllegalStateException) msg = cur.getMessage();
                out.println("E\t" + fqcn + "\t" + meth + "\t" + idx + "\t" + seed + "\t" + msg);
                err++;
            }
            if (((ok + err) & 0xFF) == 0) out.flush();
        }
        out.flush();
        System.err.println("ok=" + ok + " err=" + err + " failedClasses=" + failed.size());
        for (String s : failed) System.err.println("  FAILED " + s);
        out.close();
        System.exit(0);
    }
}
