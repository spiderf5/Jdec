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
        ClassLoader cl = new DynamicMockClassLoader(PoolDriver.class.getClassLoader());
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
                        c = Class.forName(fqcn, true, cl);
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

    static class DynamicMockClassLoader extends ClassLoader {
        private final Map<String, Class<?>> mockCache = new java.util.concurrent.ConcurrentHashMap<>();

        public DynamicMockClassLoader(ClassLoader parent) {
            super(parent);
        }

        @Override
        protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
            if (name.startsWith("java.") || name.startsWith("javax.") || name.startsWith("sun.") || name.startsWith("jdk.")
                    || name.equals("PoolDriver") || name.startsWith("PoolDriver$")) {
                return super.loadClass(name, resolve);
            }
            Class<?> c = findLoadedClass(name);
            if (c == null) {
                c = mockCache.get(name);
            }
            if (c == null) {
                try {
                    c = findClass(name);
                } catch (ClassNotFoundException e) {
                    c = super.loadClass(name, false);
                }
            }
            if (resolve) resolveClass(c);
            return c;
        }

        @Override
        protected Class<?> findClass(String name) throws ClassNotFoundException {
            if (name.startsWith("java.") || name.startsWith("javax.") || name.startsWith("sun.") || name.startsWith("jdk.")) {
                throw new ClassNotFoundException(name);
            }
            Class<?> cached = mockCache.get(name);
            if (cached != null) return cached;
            String resName = name.replace('.', '/') + ".class";
            try (java.io.InputStream in = getResourceAsStream(resName)) {
                if (in != null) {
                    byte[] b = in.readAllBytes();
                    Class<?> c = defineClass(name, b, 0, b.length);
                    mockCache.put(name, c);
                    return c;
                }
            } catch (Exception ignored) {}

            synchronized (this) {
                cached = mockCache.get(name);
                if (cached != null) return cached;
                try {
                    byte[] bytes = generateStubClass(name);
                    Class<?> c = defineClass(name, bytes, 0, bytes.length);
                    mockCache.put(name, c);
                    return c;
                } catch (Throwable t) {
                    throw new ClassNotFoundException(name, t);
                }
            }
        }
    }

    static byte[] generateStubClass(String className) {
        try {
            java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
            java.io.DataOutputStream out = new java.io.DataOutputStream(baos);
            String slashName = className.replace('.', '/');

            out.writeInt(0xCAFEBABE);
            out.writeShort(0);
            out.writeShort(52); // Java 8
            out.writeShort(22); // 21 constant pool items

            String typedDesc = "()L" + slashName + ";";
            String fieldDesc = "L" + slashName + ";";

            out.writeByte(1); out.writeUTF(slashName);                 // #1
            out.writeByte(7); out.writeShort(1);                      // #2
            out.writeByte(1); out.writeUTF("java/lang/Object");       // #3
            out.writeByte(7); out.writeShort(3);                      // #4
            out.writeByte(1); out.writeUTF("<init>");                 // #5
            out.writeByte(1); out.writeUTF("()V");                    // #6
            out.writeByte(1); out.writeUTF("Code");                   // #7
            out.writeByte(12); out.writeShort(5); out.writeShort(6);   // #8
            out.writeByte(10); out.writeShort(4); out.writeShort(8);   // #9
            out.writeByte(1); out.writeUTF("getInstance");            // #10
            out.writeByte(1); out.writeUTF("()Ljava/lang/Object;");   // #11
            out.writeByte(10); out.writeShort(2); out.writeShort(8);   // #12
            out.writeByte(1); out.writeUTF("get");                    // #13
            out.writeByte(1); out.writeUTF("instance");               // #14
            out.writeByte(1); out.writeUTF("getMinecraft");           // #15
            out.writeByte(1); out.writeUTF(typedDesc);                // #16
            out.writeByte(1); out.writeUTF("INSTANCE");               // #17
            out.writeByte(1); out.writeUTF(fieldDesc);                // #18
            out.writeByte(12); out.writeShort(17); out.writeShort(18); // #19
            out.writeByte(9); out.writeShort(2); out.writeShort(19);  // #20
            out.writeByte(1); out.writeUTF("<clinit>");               // #21

            out.writeShort(0x0001); // ACC_PUBLIC
            out.writeShort(2); out.writeShort(4);
            out.writeShort(0);

            // 1 field: public static final <slashName> INSTANCE
            out.writeShort(1);
            out.writeShort(0x0019); out.writeShort(17); out.writeShort(18); out.writeShort(0);

            // 7 methods: <init>, <clinit>, getInstance(typed), getInstance(Object), get(), instance(), getMinecraft()
            out.writeShort(7);

            // 1. <init>()V: aload_0, invokespecial Object.<init>, return
            byte[] initCode = new byte[] {0x2A, (byte) 0xB7, 0x00, 0x09, (byte) 0xB1};
            out.writeShort(0x0001); out.writeShort(5); out.writeShort(6);
            out.writeShort(1); out.writeShort(7); out.writeInt(initCode.length + 12);
            out.writeShort(1); out.writeShort(1); out.writeInt(initCode.length);
            out.write(initCode); out.writeShort(0); out.writeShort(0);

            // 2. <clinit>()V: new #2, dup, invokespecial #12, putstatic #20, return
            byte[] clinitCode = new byte[] {
                (byte) 0xBB, 0x00, 0x02, 0x59, (byte) 0xB7, 0x00, 0x0C,
                (byte) 0xB3, 0x00, 0x14, (byte) 0xB1
            };
            out.writeShort(0x0008); out.writeShort(21); out.writeShort(6);
            out.writeShort(1); out.writeShort(7); out.writeInt(clinitCode.length + 12);
            out.writeShort(2); out.writeShort(0); out.writeInt(clinitCode.length);
            out.write(clinitCode); out.writeShort(0); out.writeShort(0);

            // 3. getInstance() returning typed this
            byte[] singCode = new byte[] {
                (byte) 0xB2, 0x00, 0x14, (byte) 0xB0
            };
            out.writeShort(0x0009); out.writeShort(10); out.writeShort(16);
            out.writeShort(1); out.writeShort(7); out.writeInt(singCode.length + 12);
            out.writeShort(1); out.writeShort(0); out.writeInt(singCode.length);
            out.write(singCode); out.writeShort(0); out.writeShort(0);

            // 4..7 other singleton methods returning Object
            int[] methodNames = new int[] {10, 13, 14, 15};
            for (int mName : methodNames) {
                out.writeShort(0x0009); out.writeShort(mName); out.writeShort(11);
                out.writeShort(1); out.writeShort(7); out.writeInt(singCode.length + 12);
                out.writeShort(1); out.writeShort(0); out.writeInt(singCode.length);
                out.write(singCode); out.writeShort(0); out.writeShort(0);
            }

            out.writeShort(0); // attrs
            out.flush();
            return baos.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
