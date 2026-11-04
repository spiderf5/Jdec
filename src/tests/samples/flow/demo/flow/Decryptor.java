package demo.flow;

/**
 * Shaped like a ZKM string decryptor: a char array built in <clinit>, XORed in
 * a loop (a backwards goto), then interned into a String. This one javac will
 * produce honestly, which is what makes it a useful fixture.
 */
public class Decryptor {
    private static final String[] TABLE = new String[1];

    static {
        String src = "a rather ordinary literal";
        char[] chars = new char[src.length()];
        for (int i = 0; i < src.length(); i++) {
            chars[i] = (char) (src.charAt(i) ^ 0x5A);
        }
        TABLE[0] = new String(chars).intern();
    }

    public static String first() {
        return TABLE[0];
    }
}
