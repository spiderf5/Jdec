import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.security.ProtectionDomain;
import java.util.Collection;
import java.util.Map;

/**
 * Runs inside the real Forge 1.8.9 client. After the delay, walks every
 * loaded myau.* class: reads V's static registry map and each module's
 * name/settings, dumps everything, exits. Read-only - the mod's own
 * integrity checks must pass, so nothing here transforms classes.
 */
public class DumpAgent {

    static PrintWriter out;

    public static void premain(String args, final Instrumentation inst) {
        long delaySec = 90;
        String path = "dump_modules.tsv";
        if (args != null) {
            for (String kv : args.split(",")) {
                String[] p = kv.split("=", 2);
                if (p.length != 2) continue;
                if (p[0].equals("delay")) delaySec = Long.parseLong(p[1]);
                if (p[0].equals("out")) path = p[1];
            }
        }
        final long delay = delaySec;
        final String outPath = path;
        Thread t = new Thread(new Runnable() {
            public void run() {
                try {
                    Thread.sleep(delay * 1000L);
                    dump(inst, outPath);
                } catch (Throwable t2) {
                    try {
                        PrintWriter e = new PrintWriter(new OutputStreamWriter(
                                new FileOutputStream(outPath + ".err"), "UTF-8"), true);
                        e.println(t2);
                        e.close();
                    } catch (Exception ignored) { }
                }
                Runtime.getRuntime().halt(0);
            }
        }, "dump-agent");
        t.setDaemon(true);
        t.start();
    }

    static void dump(Instrumentation inst, String path) throws Exception {
        out = new PrintWriter(new OutputStreamWriter(
                new FileOutputStream(path), "UTF-8"), true);
        // 找 myau.V 与其所有已加载子类
        Class<?> vbase = null;
        java.util.List<Class<?>> mods = new java.util.ArrayList<Class<?>>();
        for (Class<?> c : inst.getAllLoadedClasses()) {
            String n = c.getName();
            if (!n.startsWith("myau.")) continue;
            if (n.equals("myau.V")) vbase = c;
            else if (c.getSuperclass() != null
                    && "myau.V".equals(c.getSuperclass().getName())) {
                mods.add(c);
            }
        }
        out.println("# vbase=" + vbase + " modules=" + mods.size());

        // 主路径：registry 有实例 → 名字 + 设置项；为空则主动构造
        int dumped = 0;
        java.util.Set<String> seen = new java.util.HashSet<String>();
        java.util.List<Object> insts = new java.util.ArrayList<Object>();
        if (vbase != null) {
            for (Field f : vbase.getDeclaredFields()) {
                if ((f.getModifiers() & 0x0008) == 0) continue;
                if (f.getType() != Map.class && f.getType() != Collection.class) continue;
                f.setAccessible(true);
                Object o = f.get(null);
                Collection<?> items = (o instanceof Map)
                        ? ((Map<?, ?>) o).values() : (Collection<?>) o;
                if (items == null) continue;
                for (Object m : items) {
                    if (m == null) continue;
                    insts.add(m);
                    seen.add(m.getClass().getName());
                }
            }
        }
        if (insts.isEmpty()) {
            // 主动构造（native 已就绪；构造失败就跳过）
            for (Class<?> c : mods) {
                try {
                    java.lang.reflect.Constructor<?> ctor =
                            c.getDeclaredConstructor();
                    ctor.setAccessible(true);
                    Object m = ctor.newInstance();
                    insts.add(m);
                } catch (Throwable t) {
                    out.println("ctorfail\t" + c.getName() + "\t" + t);
                }
            }
        }
        for (Object m : insts) {
            String cn = m.getClass().getName();
            String name = firstString(m);
            String settings = settingsOf(m);
            out.println(cn + "\t" + name + "\t" + settings);
            dumped++;
        }
        out.println("# registry-dumped=" + dumped);

        // 兜底：任何 V 子类的全部静态 String 字段（名字与密钥混在静态字段里，
        // 全量导出后再在 Python 端人工/启发式分拣）
        for (Class<?> c : mods) {
            for (Field f : c.getDeclaredFields()) {
                if ((f.getModifiers() & 0x0008) == 0) continue;
                if (f.getType() != String.class) continue;
                try {
                    f.setAccessible(true);
                    Object v = f.get(null);
                    if (v instanceof String && !((String) v).isEmpty()) {
                        out.println("static\t" + c.getName() + "." + f.getName()
                                + "\t" + v);
                    }
                } catch (Throwable ignored) { }
            }
            // 实例字段也全量：模块若已构造，static 引用或注册表里有实例
            // （由 registry 分支处理；此处不重复）
        }
        out.close();
    }

    /** 第一个非空 String 实例字段（V.i = 模块名）。 */
    static String firstString(Object o) {
        Class<?> k = o.getClass();
        while (k != null && !k.getName().equals("java.lang.Object")) {
            for (Field f : k.getDeclaredFields()) {
                if (f.getType() != String.class) continue;
                if ((f.getModifiers() & 0x0008) != 0) continue;
                try {
                    f.setAccessible(true);
                    Object v = f.get(o);
                    if (v instanceof String && !((String) v).isEmpty()) return (String) v;
                } catch (Throwable ignored) { }
            }
            k = k.getSuperclass();
        }
        return "?";
    }

    /** 实例里 myau.* 类型字段的 String 名（设置项名）。 */
    static String settingsOf(Object mod) {
        StringBuilder sb = new StringBuilder();
        try {
            Class<?> k = mod.getClass();
            while (k != null && !k.getName().equals("java.lang.Object")) {
                for (Field f : k.getDeclaredFields()) {
                    if ((f.getModifiers() & 0x0008) != 0) continue;
                    Object v;
                    try {
                        f.setAccessible(true);
                        v = f.get(mod);
                    } catch (Throwable t) { continue; }
                    if (v == null || !v.getClass().getName().startsWith("myau.")) continue;
                    String nm = firstString(v);
                    if (nm != null && !nm.equals("?")) {
                        if (sb.length() > 0) sb.append("; ");
                        sb.append(f.getName()).append("=").append(nm);
                    }
                }
                k = k.getSuperclass();
            }
        } catch (Throwable ignored) { }
        return sb.toString();
    }
}
