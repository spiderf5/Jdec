package demo.obf;

public class a {

    private static final int[] b = new int[16];

    public static int c(int d, int e) {
        int f = 0;
        for (int g = 0; g < d; g++) {
            switch (g % 4) {
                case 0:
                    f += e;
                    break;
                case 1:
                    f ^= g;
                    break;
                case 2:
                    f -= e >> 1;
                    break;
                default:
                    f = (f << 1) ^ 0x5f;
            }
        }
        return f ^ b[d & 15];
    }

    public static String d(byte[] e) {
        StringBuilder f = new StringBuilder();
        for (byte g : e) {
            f.append((char) ((g ^ 0x3f) & 0xff));
        }
        return f.toString();
    }

    public static long e(long f, long g) {
        long h = 0;
        while (f != 0) {
            if ((f & 1L) != 0) {
                h += g;
            }
            f >>>= 1;
            g <<= 1;
        }
        return h;
    }

    static class h {
        int i;
        String j;

        int k() {
            return i * 31 + (j == null ? 0 : j.hashCode());
        }
    }
}
