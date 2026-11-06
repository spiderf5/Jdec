package demo.shapes;

/**
 * The opposite control-flow shape: javac's `switch(String)` lowering.
 *
 * javac compiles this into `s.hashCode()` + a lookupswitch, a state variable,
 * and a second tableswitch. That second switch has the same instruction shape
 * as an obfuscator dispatcher, so the rewrite pass must classify this method
 * as `switch`, not `unflatten`. Together with `Flattened`, this fixture pins
 * both directions of the classification.
 */
public final class StringSwitch {

    private StringSwitch() {
    }

    public static int pick(String s) {
        switch (s) {
            case "alpha":
                return 1;
            case "beta":
                return 2;
            case "gamma":
                return 3;
            case "delta":
                return 4;
            case "epsilon":
                return 5;
            case "zeta":
                return 6;
            default:
                return -1;
        }
    }
}
