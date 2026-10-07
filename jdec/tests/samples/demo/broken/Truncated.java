package demo.broken;

/**
 * Fixture that ships into sample.jar as a deliberately truncated class file:
 * build_sample_jar() compiles this source, then cuts the .class bytes so the
 * parser hits EOF mid-constant-pool.  It must be rejected with
 * ClassFormatError (quarantined), never crash the run.
 */
public class Truncated {

    public static int classify(int v) {
        int acc = 0;
        for (int i = 0; i < v; i++) {
            acc = acc * 31 + i;
        }
        switch (acc % 4) {
            case 0:
                acc += 7;
                break;
            case 1:
                acc ^= 3;
                break;
            case 2:
                acc -= 11;
                break;
            default:
                acc = (acc << 2) ^ acc;
        }
        try {
            acc += Integer.parseInt("42");
        } catch (NumberFormatException e) {
            acc = -1;
        }
        return String.valueOf(acc).length() + acc;
    }
}
