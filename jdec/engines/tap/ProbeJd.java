import java.lang.reflect.*;
public class ProbeJd {
    public static void main(String[] a) throws Exception {
        Class<?> c = Class.forName("myau.Jd", true, ProbeJd.class.getClassLoader());
        for (String fn : new String[]{"d", "e"}) {
            try {
                Field f = c.getDeclaredField(fn);
                f.setAccessible(true);
                Object v = f.get(null);
                if (v instanceof long[]) {
                    long[] arr = (long[]) v;
                    int nz = 0; long first = 0;
                    for (long x : arr) { if (x != 0) { nz++; if (first == 0) first = x; } }
                    System.out.println(fn + ": long[" + arr.length + "] nonzero=" + nz + " first=" + first);
                } else if (v instanceof Long[]) {
                    Long[] arr = (Long[]) v;
                    int nz = 0;
                    for (Long x : arr) if (x != null) nz++;
                    System.out.println(fn + ": Long[" + arr.length + "] nonnull=" + nz);
                } else {
                    System.out.println(fn + ": " + (v == null ? "null" : v.getClass().getName()));
                }
            } catch (Throwable t) { System.out.println(fn + ": " + t); }
        }
        Method m = c.getDeclaredMethod("a", int.class, long.class);
        m.setAccessible(true);
        Object r = m.invoke(null, 10362, 4746244320697286810L);
        System.out.println("a(10362, 4746244320697286810L) = " + r);
    }
}
