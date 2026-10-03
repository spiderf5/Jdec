import java.lang.reflect.*;
import java.util.*;
public class ProbeCtor {
    public static void main(String[] a) throws Exception {
        Class<?> c = Class.forName("myau.Jd", true, ProbeCtor.class.getClassLoader());
        Class<?> v = c.getSuperclass();
        System.out.println("V = " + v.getName());
        try {
            Constructor<?> ctor = c.getDeclaredConstructor();
            ctor.setAccessible(true);
            ctor.newInstance();
            System.out.println("ctor ok");
        } catch (Throwable t) {
            Throwable cause = t;
            int depth = 0;
            while (cause.getCause() != null && depth < 5) { cause = cause.getCause(); depth++; }
            System.out.println("ctor failed: " + cause);
            StackTraceElement[] st = cause.getStackTrace();
            for (int i = 0; i < Math.min(6, st.length); i++) System.out.println("  at " + st[i]);
        }
        // V 的静态 Map/List 注册表
        for (Field f : v.getDeclaredFields()) {
            if ((f.getModifiers() & 0x0008) == 0) continue;
            try {
                f.setAccessible(true);
                Object o = f.get(null);
                if (o instanceof Map) {
                    Map<?,?> m = (Map<?,?>) o;
                    System.out.println("V." + f.getName() + " Map size=" + m.size());
                    int n = 0;
                    for (Map.Entry<?,?> e : m.entrySet()) {
                        System.out.println("   key=" + e.getKey() + " val=" + e.getValue());
                        if (++n >= 5) break;
                    }
                } else if (o instanceof Collection) {
                    System.out.println("V." + f.getName() + " Coll size=" + ((Collection<?>) o).size());
                }
            } catch (Throwable t2) {
                System.out.println("V." + f.getName() + " err " + t2);
            }
        }
    }
}
