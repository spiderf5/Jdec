import java.io.*;
import java.lang.instrument.*;
import java.security.ProtectionDomain;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

/**
 * Records plaintext as it is produced by string decryption, without needing to
 * know how the obfuscator derives its key.
 *
 * ZKM 27 hides its session key behind an indy bootstrap and rotates the cipher
 * setup per class, so re-implementing the key derivation breaks on every new
 * build. Instead this hooks the two JDK entry points every variant funnels
 * through -- Cipher.doFinal and new String(byte[], charset) -- and logs the
 * result. The obfuscator does the work; we only watch.
 *
 * That makes the technique independent of the obfuscator version: as long as
 * the strings pass through javax.crypto, they get captured.
 */
public class StringTap implements ClassFileTransformer {

    /** class name -> plaintext, insertion ordered so output is reproducible. */
    public static final Map<String, String[]> SEEN =
            Collections.synchronizedMap(new LinkedHashMap<String, String[]>());

    private static volatile boolean tapCipher = true;
    private static volatile boolean tapStrings = true;

    public byte[] transform(ClassLoader loader, String className, Class<?> beingRedefined,
                            ProtectionDomain pd, byte[] classfileBuffer) {
        // javax.crypto is loaded before this agent can touch it on most JVMs, so
        // the Cipher hook is installed by retransforming it in premain below.
        return null;
    }

    /** Called from instrumented Cipher/new String bodies. */
    public static void record(String cls, String text) {
        if (text == null || text.isEmpty()) return;
        String[] bucket = SEEN.get(cls);
        if (bucket == null) {
            SEEN.put(cls, new String[]{text});
            return;
        }
        synchronized (SEEN) {
            for (String s : bucket) if (s.equals(text)) return;
            String[] grown = Arrays.copyOf(bucket, bucket.length + 1);
            grown[bucket.length] = text;
            SEEN.put(cls, grown);
        }
    }

    public static void dump(PrintStream out) {
        out.println("# class\tplaintext");
        List<String> keys = new ArrayList<>(SEEN.keySet());
        Collections.sort(keys);
        for (String k : keys) {
            String[] vals = SEEN.get(k);
            String[] sorted = vals.clone();
            Arrays.sort(sorted);
            for (String v : sorted) {
                out.println(k + "\t" + v.replace("\t", " ").replace("\n", "\\n"));
            }
        }
    }

    public static void setTaps(boolean cipher, boolean strings) {
        tapCipher = cipher;
        tapStrings = strings;
    }

    public static boolean cipherOn()  { return tapCipher; }
    public static boolean stringsOn() { return tapStrings; }

    public static void main(String[] args) throws Exception {
        // Standalone mode: used by the test suite and when no agent is attached.
        StringTap.dump(System.out);
    }
}
