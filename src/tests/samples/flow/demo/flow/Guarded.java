package demo.flow;

/**
 * Ordinary try/catch. Compiled as-is its exception handler jumps forwards, as
 * javac always emits. run_tests.py rewrites the handler_pc to point backwards
 * and checks that the flow detector notices - javac will not produce that shape
 * for us, so the fixture has to be tampered with on purpose.
 */
public class Guarded {
    public int run(int x) {
        try {
            if (x > 0) {
                return x * 2;
            }
            return -1;
        } catch (RuntimeException e) {
            return 0;
        }
    }
}
