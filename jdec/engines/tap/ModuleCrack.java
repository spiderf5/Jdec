import java.io.*;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

/**
 * Instantiates module classes under the NoExit agent and reads the module
 * name that the constructor decrypts and passes to super(). Even a half
 * built instance carries the name: super(...) runs before everything else.
 *
 * args: <classListFile> <out.tsv>   lines: CLASS \t NAME-or-ERROR
 */
public class ModuleCrack {
    public static void main(String[] args) throws Exception {
        List<String> classes = Files.readAllLines(Paths.get(args[0]), StandardCharsets.UTF_8);
        PrintWriter out = new PrintWriter(new OutputStreamWriter(
                new FileOutputStream(args[1], true), StandardCharsets.UTF_8), true);
        for (String cn : classes) {
            if (cn.isEmpty()) continue;
            try {
                Class<?> c = Class.forName(cn.replace('/', '.'), true,
                        ModuleCrack.class.getClassLoader());
                Object inst = null;
                Throwable ctorErr = null;
                try {
                    Constructor<?> ctor = c.getDeclaredConstructor();
                    ctor.setAccessible(true);
                    inst = ctor.newInstance();
                } catch (Throwable t) {
                    ctorErr = t;
                }
                String name = readName(c, inst);
                String settings = readSettings(c, inst);
                out.println(cn + "\t" + (name == null ? "?" : name)
                        + "\t" + (ctorErr == null ? "ok" : "ctor:" + ctorErr.getClass().getSimpleName())
                        + (settings.isEmpty() ? "" : "\t" + settings));
            } catch (Throwable t) {
                out.println(cn + "\tERROR\t" + t);
            }
        }
    }

    /** 沿父类链找第一个 String 实例字段 = 模块名（V.i）。 */
    static String readName(Class<?> c, Object inst) {
        Class<?> k = c;
        while (k != null && k != Object.class) {
            for (Field f : k.getDeclaredFields()) {
                if (f.getType() == String.class && !Modifier_isStatic(f)) {
                    try {
                        f.setAccessible(true);
                        Object v = f.get(inst);
                        if (v instanceof String && !((String) v).isEmpty()) {
                            return (String) v;
                        }
                    } catch (Throwable ignored) { }
                }
            }
            k = k.getSuperclass();
        }
        return null;
    }

    static boolean Modifier_isStatic(Field f) {
        return (f.getModifiers() & 0x0008) != 0;
    }

    /** 收集设置项对象（类型为 myau/* 的实例字段）里的 String 名字。 */
    static String readSettings(Class<?> c, Object inst) {
        if (inst == null) return "";
        StringBuilder sb = new StringBuilder();
        try {
            for (Field f : c.getDeclaredFields()) {
                if (Modifier_isStatic(f)) continue;
                Object v;
                try {
                    f.setAccessible(true);
                    v = f.get(inst);
                } catch (Throwable t) { continue; }
                if (v == null) continue;
                String tn = v.getClass().getName();
                if (!tn.startsWith("myau.")) continue;
                String nm = readName(v.getClass(), v);
                if (nm != null) {
                    if (sb.length() > 0) sb.append("; ");
                    sb.append(f.getName()).append("=").append(nm);
                }
            }
        } catch (Throwable ignored) { }
        return sb.toString();
    }
}
