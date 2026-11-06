package demo.shapes;

/**
 * A hand-written stand-in for an obfuscator's control-flow flattening.
 *
 * `unflatten_dispatchers` used to have no fixture at all: the only shapes that
 * reached it in practice were javac's `switch(String)` lowering, which made
 * the pass look like it worked on obfuscated jars when it was really rewriting
 * compiler output. This class has the shape a flattener produces - a
 * `while (true)` around a `switch (state)`, with every case ending in
 * `state = N; break` - without any `String.hashCode` dispatch, so it must be
 * classified as `unflatten`, not `switch`.
 *
 * It is a unit fixture, not an independent corpus sample.
 */
public final class Flattened {

    private Flattened() {
    }

    public static int run(int x) {
        int state = 0;
        int acc = 0;
        while (true) {
            switch (state) {
                case 0:
                    if (x < 0) {
                        state = 4;
                    } else {
                        acc = 1;
                        state = 1;
                    }
                    break;
                case 1:
                    if ((x & 1) == 0) {
                        acc += 2;
                        state = 2;
                    } else {
                        state = 3;
                    }
                    break;
                case 2:
                    acc *= 3;
                    state = 5;
                    break;
                case 3:
                    acc -= 7;
                    state = 5;
                    break;
                case 4:
                    acc = -1;
                    state = 5;
                    break;
                case 5:
                    return acc + x;
                default:
                    return -999;
            }
        }
    }
}
