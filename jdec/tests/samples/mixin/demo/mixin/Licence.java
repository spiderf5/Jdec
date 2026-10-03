package demo.mixin;

import java.io.IOException;

/**
 * Deliberately suspicious: a native method, a process launch, and a pile of
 * payload-looking string constants. Nothing here depends on names we choose,
 * so it stays detectable after an obfuscator renames everything.
 */
public class Licence {
    private static final String[] PAYLOAD = {
        "3q2+7wQkZmR0aGVuYXRpdmVseSBlbmNyeXB0ZWQgc3RyaW5ncw==",
        "9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281",
        "TG9va3MgZW5jcnlwdGVkIGJ1dCBpcyBub3QgcmVhbGx5IHNlY3JldA==",
        "0123456789abcdef0123456789abcdef01234567",
    };

    public static String decode(String s) {
        return s;
    }

    public native boolean validateNative(String token);

    public void check() throws IOException {
        Runtime.getRuntime().exec("whoami");
    }
}
