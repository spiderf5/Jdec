package demo.flow;

/**
 * Control flow that costs real jumps: nested loops with break, continue and
 * early returns. This is where javac *does* emit gotos, and it is the honest
 * counterpart to ZKM's flow obfuscation - same instruction, different reason.
 *
 * Worth knowing what this fixture is not: three earlier attempts to provoke a
 * goto flood with an if-else chain all produced a single switch and zero
 * jumps, because javac folds if-chains over one variable into a
 * tableswitch/lookupswitch. A goto flood is something only a *bytecode*
 * rewriter produces - which is exactly what ZKM is.
 */
public class GotoFlood {
    public static int nested(int[] a) {
        int c = 0;
        for (int i = 0; i < a.length; i++) {
            for (int j = i + 1; j < a.length; j++) {
                if (a[i] == a[j]) {
                    continue;
                }
                if (a[i] + a[j] > 1000) {
                    break;
                }
                if (a[i] % 7 == 0) {
                    c += a[j];
                    continue;
                }
                c ^= a[i] * a[j];
                if (c > 100000) {
                    return -1;
                }
            }
            if (c < 0) {
                return c;
            }
            if (c > 500000) {
                continue;
            }
            c += a[i];
        }
        return c;
    }

    public static int dispatch(int x) {
        if (x == 3) return 40009;
        if (x == 1013) return 7;
        if (x == 2003) return 65537;
        if (x == 3001) return 12;
        if (x == 4007) return 999983;
        if (x == 5003) return 31;
        if (x == 6007) return 262144;
        if (x == 7001) return 44;
        return -1;
    }
}
