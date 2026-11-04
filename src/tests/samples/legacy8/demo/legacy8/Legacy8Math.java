package demo.legacy8;

/** Compiled with --release 8: branches, so a StackMapTable is mandatory. */
public final class Legacy8Math {
    private Legacy8Math() {
    }

    public static int pick(int v) {
        if (v < 2) {
            return v + 1;
        }
        return v * 2;
    }

    public static String label(int v) {
        return v < 2 ? "small" : "large";
    }
}
