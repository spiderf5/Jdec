"""Generate the OPS-pattern fixture (blob/key/inv-switch) as a .java file.

Run from /tmp/ops_fix with the venv python:
    python gen_fixture.py
then: javac OpsPoolFixture.java && jar cf ops_fixture.jar OpsPoolFixture*.class
"""

import random
import sys

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1]))
from jdec import _des

STRINGS = ["alpha-secret-ONE", "bravo-secret-TWO", "charlie-secret-THREE"]
KEY = b"JdEcAlPh"


def esc(s: str) -> str:
    out = []
    for ch in s:
        c = ord(ch)
        if c == 0x5C:
            out.append("\\\\")
        elif c == 0x22:
            out.append('\\"')
        elif 0x20 <= c <= 0x7E:
            out.append(chr(c))
        else:
            out.append(f"\\u{c:04x}")
    return "".join(out)


def main() -> None:
    data = b""
    for s in STRINGS:
        b = s.encode("utf-8")
        data += bytes([len(b) & 0xFF, (len(b) >> 8) & 0xFF]) + b
    data += __import__("hashlib").sha256(data).digest()
    ct = _des.des_cbc_encrypt(KEY, data, b"\x00" * 8)

    rnd = random.Random(1234)
    swp = list(range(256))
    rnd.shuffle(swp)
    blob = bytes(swp[b & 0xFF] for b in ct)
    inv = {}
    for j, v in enumerate(swp):
        inv[v] = j

    cases = "\n".join(
        f"            case {i}: return {inv[i]};" for i in range(256))

    src = (
        "public class OpsPoolFixture {\n"
        "    private static Object pool;\n"
        "    private static Object pull(char idx) { return ((Object[]) pool)[idx]; }\n"
        "    static {\n"
        "        try {\n"
        f"            byte[] data = \"{esc(blob.decode('iso-8859-1'))}\".getBytes(\"ISO_8859_1\");\n"
        f"            byte[] key = \"{esc(KEY.decode('iso-8859-1'))}\".getBytes(\"ISO_8859_1\");\n"
        "            for (int i = 0; i < data.length; i++) data[i] = (byte) inv(data[i] & 0xFF);\n"
        "            javax.crypto.Cipher c = javax.crypto.Cipher.getInstance(\"DES/CBC/PKCS5Padding\");\n"
        "            c.init(javax.crypto.Cipher.DECRYPT_MODE,\n"
        "                javax.crypto.SecretKeyFactory.getInstance(\"DES\").generateSecret(new javax.crypto.spec.DESKeySpec(key)),\n"
        "                new javax.crypto.spec.IvParameterSpec(new byte[8]));\n"
        "            data = c.doFinal(data);\n"
        "            byte[] dg = java.security.MessageDigest.getInstance(\"SHA-256\").digest(java.util.Arrays.copyOf(data, data.length - 32));\n"
        "            for (int i = 0; i < 32; i++) if (dg[i] != data[data.length - 32 + i]) throw new RuntimeException(\"sha\");\n"
        "            java.util.ArrayList<Object> list = new java.util.ArrayList<>();\n"
        "            int pos = 0;\n"
        "            while (pos < data.length - 32) {\n"
        "                int len = (data[pos] & 0xFF) | ((data[pos + 1] & 0xFF) << 8);\n"
        "                byte[] buf = new byte[len];\n"
        "                System.arraycopy(data, pos + 2, buf, 0, len);\n"
        "                list.add(new String(buf, \"UTF-8\").intern());\n"
        "                pos += 2 + len;\n"
        "            }\n"
        "            pool = list.toArray(new Object[0]);\n"
        "        } catch (Exception e) { throw new RuntimeException(e); }\n"
        "    }\n"
        "    private static int inv(int b) {\n"
        "        switch (b) {\n"
        f"{cases}\n"
        "            default: return 0;\n"
        "        }\n"
        "    }\n"
        "    public static String s(int i) { return (String) pull((char) i); }\n"
        "    public static void main(String[] a) {\n"
        "        System.out.println(s(0));\n"
        "        System.out.println(s(1));\n"
        "        System.out.println(s(2));\n"
        "    }\n"
        "}\n"
    )
    with open("OpsPoolFixture.java", "w", encoding="ascii") as f:
        f.write(src)
    print(f"fixture written: blob={len(blob)}B, source is pure ASCII")


if __name__ == "__main__":
    main()
