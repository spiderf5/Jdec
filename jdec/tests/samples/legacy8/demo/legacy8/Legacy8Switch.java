package demo.legacy8;

/** A tableswitch, which the frame generator has to cover at major 52 too. */
public final class Legacy8Switch {
    private Legacy8Switch() {
    }

    public static int step(int s) {
        switch (s) {
            case 0:
                return 10;
            case 1:
                return 20;
            case 2:
                return 30;
            default:
                return -1;
        }
    }
}
