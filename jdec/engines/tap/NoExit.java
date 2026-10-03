import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;

/**
 * Neuters the antiLeak native-protection layer at load time.
 *
 * Every "poison" class (myau.r, Jd, w, Jc, ...) registers natives and runs an
 * integrity check through antiLeak-.../Loader in <clinit>; on a bare JVM that
 * either hard-crashes (u9eOst.lib access violation, myau.r) or exits(127)
 * cleanly (Jd & friends). The string-decryption machinery those <clinit>s run
 * is pure Java and identical to s3's template, so we stub the whole antiLeak
 * package instead of touching the myau classes at all: every method that has a
 * Code attribute becomes "return" (max_locals preserved, no stack map frames
 * needed for a branch-free body). Native methods keep their flag but can never
 * be reached: the only call sites live in code that no longer runs.
 */
public class NoExit {

    public static void premain(String args, Instrumentation inst) {
        inst.addTransformer(new ClassFileTransformer() {
            @Override
            public byte[] transform(ClassLoader loader, String className,
                                    Class<?> beingRedefined,
                                    ProtectionDomain pd, byte[] bytes) {
                if (className == null) {
                    return null;
                }
                // antiLeak = 保护壳本体，全部方法桩化；myau = 业务类，
                // 只桩化 native（完整性校验），解密逻辑必须原样保留
                boolean stubAll = className.startsWith("antiLeak");
                if (!stubAll && !className.startsWith("myau/")) {
                    return null;
                }
                try {
                    return Stubber.stub(bytes, stubAll);
                } catch (Throwable t) {
                    System.err.println("[noexit] " + className + ": " + t);
                    return null;   // original bytes beat a broken patch
                }
            }
        });
    }
}

final class Stubber {

    // class-file tags we need to skip the constant pool
    private static final int TAG_UTF8 = 1, TAG_LONG = 5, TAG_DOUBLE = 6;

    static byte[] stub(byte[] src, boolean stubAll) {
        int p = 0;
        p += 4;                                   // magic
        p += 2 + 2;                               // minor, major
        int cpCount = u2(src, p); p += 2;
        for (int i = 1; i < cpCount; i++) {
            int tag = src[p]; p += 1;
            switch (tag) {
                case TAG_UTF8:  p += u2(src, p) + 2; break;
                case TAG_LONG: case TAG_DOUBLE: p += 8; i++; break;
                case 7: case 8: case 16: case 19: case 20: p += 2; break;
                case 15: p += 3; break;
                default: p += 4; break;           // int/float/fieldref/methodref/
                                                  // nat/dynamic/invokedynamic
            }
        }
        p += 2 + 2 + 2;                           // access, this, super
        int superIdx = u2(src, p - 2);            // super_class 的 cp 索引
        int ifaces = u2(src, p); p += 2 + 2 * ifaces;

        // fields: walk (copied verbatim later)
        int fieldsCount = u2(src, p);
        int fieldsStart = p;                      // fields_count 前的位置
        p += 2;
        for (int i = 0; i < fieldsCount; i++) {
            p += 6;                               // access, name, desc
            int ac = u2(src, p); p += 2;
            for (int k = 0; k < ac; k++) {
                int len = u4(src, p + 2); p += 6 + len;
            }
        }
        int methodsStart = p;                     // methods_count 的位置
        int methods = u2(src, p);
        int q = p + 2;
        ByteOut methodsOut = new ByteOut(src.length + 64);
        methodsOut.u2(methods);
        for (int i = 0; i < methods; i++) {
            int acc = u2(src, q), name = u2(src, q + 2), desc = u2(src, q + 4);
            int ac = u2(src, q + 6);
            boolean isNative = (acc & 0x0100) != 0;   // ACC_NATIVE
            if (isNative) {
                acc &= ~0x0100;                       // 去 native 化
                int qe = q + 8;
                for (int k = 0; k < ac; k++) {        // 走到方法尾
                    int alen = u4(src, qe + 2); qe += 6 + alen;
                }
                int codeIdx = findUtf8(src, "Code");
                methodsOut.u2(acc); methodsOut.u2(name); methodsOut.u2(desc);
                if (codeIdx > 0) {
                    // 整个属性区替换为唯一一个 Code 桩
                    methodsOut.u2(1);
                    String dstr = cpUtf8(src, desc);
                    int ml = maxLocalsFor(dstr, (acc & 0x0008) != 0);
                    byte[] minimal = minimalReturn(ml, dstr);
                    methodsOut.u2(codeIdx); methodsOut.u4(minimal.length);
                    methodsOut.copy(minimal, 0, minimal.length);
                } else {
                    // 找不到 "Code" 字面量就保留原属性（native 标志已去）
                    methodsOut.u2(ac);
                    methodsOut.copy(src, q + 8, qe - (q + 8));
                }
                q = qe;
                continue;
            }
            methodsOut.u2(acc); methodsOut.u2(name); methodsOut.u2(desc); methodsOut.u2(ac);
            q += 8;
            for (int k = 0; k < ac; k++) {
                int aname = u2(src, q);
                int alen = u4(src, q + 2);        // attribute_length 是 u4！
                int bodyStart = q + 6, bodyEnd = bodyStart + alen;
                boolean isCode = utf8At(src, aname, "Code");
                boolean isCtor = utf8At(src, name, "<init>");
                methodsOut.u2(aname);
                if (!stubAll) {
                    // myau 业务类：非 native 方法一律原样保留
                    methodsOut.u4(alen);
                    methodsOut.copy(src, bodyStart, alen);
                } else if (!isCode) {
                    methodsOut.u4(alen);
                    methodsOut.copy(src, bodyStart, alen);
                } else if (isCtor) {
                    methodsOut.u4(alen);
                    methodsOut.copy(src, bodyStart, alen);
                } else if (isCtor) {
                    // 构造器必须先调 super 构造，否则 VerifyError
                    int superInit = findSuperInit(src, superIdx);
                    if (superInit > 0) {
                        byte[] ctor = ctorStub(maxLocalsOf(src, bodyStart), superInit);
                        methodsOut.u4(ctor.length);
                        methodsOut.copy(ctor, 0, ctor.length);
                    } else {
                        methodsOut.u4(alen);      // 找不到 super<init> 就不动
                        methodsOut.copy(src, bodyStart, alen);
                    }
                } else {
                    String dstr = cpUtf8(src, desc);
                    byte[] minimal = minimalReturn(u2(src, bodyStart + 2), dstr);
                    methodsOut.u4(minimal.length);
                    methodsOut.copy(minimal, 0, minimal.length);
                }
                q = bodyEnd;
            }
        }
        // 输出 = [头+常量池+接口+字段 原样] + [重建的方法区] + [类属性 原样]
        ByteOut out = new ByteOut(src.length + 64);
        out.copy(src, 0, methodsStart);
        out.copy(methodsOut.buf, 0, methodsOut.len);
        out.copy(src, q, src.length - q);
        return out.toArray();
    }

    /** Code attribute: 返回零值（按描述符选 return 形态），无异常表、无属性
     *  （无分支体不需要 stack map）。 */
    private static byte[] minimalReturn(int maxLocals, String desc) {
        String ret = desc.substring(desc.indexOf(')') + 1);
        byte load, retOp;
        int stack, extra = 0;
        if (ret.equals("V"))                { load = 0;   retOp = (byte) 0xB1; stack = 0; }
        else if (ret.startsWith("L") || ret.startsWith("[")) { load = 0x01; retOp = (byte) 0xB0; stack = 1; } // aconst_null; areturn
        else if (ret.equals("J"))           { load = 0x0A; retOp = (byte) 0xAD; stack = 2; extra = 1; } // lconst_0; lreturn
        else if (ret.equals("D"))           { load = 0x0E; retOp = (byte) 0xAF; stack = 2; extra = 1; } // dconst_0; dreturn
        else if (ret.equals("F"))           { load = 0x0B; retOp = (byte) 0xAE; stack = 1; } // fconst_0; freturn
        else                                { load = 0x02; retOp = (byte) 0xAC; stack = 1; } // iconst_0; ireturn
        int codeLen = (load == 0 ? 1 : 2);
        byte[] b = new byte[8 + codeLen + 4];
        b[0] = (byte) (stack >> 8); b[1] = (byte) stack;      // max_stack
        b[2] = (byte) (maxLocals >> 8); b[3] = (byte) maxLocals;
        b[4] = 0; b[5] = 0; b[6] = 0; b[7] = (byte) codeLen;  // code_length
        int o = 8;
        if (load != 0) b[o++] = load;
        b[o++] = retOp;
        // 末尾 4 字节已是 0：exception_table_length=0, attributes_count=0
        return b;
    }

    /** 构造器桩：aload_0; invokespecial super.<init>()V; return。 */
    private static byte[] ctorStub(int maxLocals, int superInitRef) {
        return new byte[] {
            0, 1,                                 // max_stack = 1
            (byte) (maxLocals >> 8), (byte) maxLocals,
            0, 0, 0, 5,                           // code_length = 5
            (byte) 0x2A,                          // aload_0
            (byte) 0xB7, (byte) (superInitRef >> 8), (byte) superInitRef,
            (byte) 0xB1,                          // return
            0, 0,                                 // exception_table_length = 0
            0, 0,                                 // attributes_count = 0
        };
    }

    private static int maxLocalsOf(byte[] src, int codeBodyStart) {
        return u2(src, codeBodyStart + 2);
    }

    /** 描述符 -> max_locals（native 桩用；数组算 1 槽，long/double 算 2）。 */
    private static int maxLocalsFor(String desc, boolean isStatic) {
        int n = isStatic ? 0 : 1;
        String args = desc.substring(1, desc.indexOf(')'));
        int i = 0;
        while (i < args.length()) {
            char c = args.charAt(i);
            if (c == 'L') {
                n++;
                i = args.indexOf(';', i) + 1;
            } else if (c == '[') {
                n++;
                while (i < args.length() && args.charAt(i) == '[') i++;
                if (i < args.length() && args.charAt(i) == 'L') {
                    i = args.indexOf(';', i) + 1;
                } else {
                    i++;
                }
            } else {
                n++;
                if (c == 'J' || c == 'D') n++;
                i++;
            }
        }
        return n;
    }

    /** 在常量池里找 super 类 <init>()V 的 MethodRef；找不到返回 0。 */
    private static int findSuperInit(byte[] src, int superIdx) {
        int cpCount = u2(src, 8);
        int p = 10;
        for (int i = 1; i < cpCount; i++) {
            int tag = src[p]; p += 1;
            switch (tag) {
                case TAG_UTF8:  p += u2(src, p) + 2; break;
                case TAG_LONG: case TAG_DOUBLE: p += 8; i++; break;
                case 15: p += 3; break;
                case 7: case 8: case 16: case 19: case 20: p += 2; break;
                default:
                    // 9/10/11/3/4/12/17/18 都是 u2 载荷（10=Methodref 在此）
                    if (tag == 10) {
                        int clsIdx = u2(src, p);
                        int natIdx = u2(src, p + 2);
                        if (clsIdx == superIdx && isInitNat(src, natIdx)) {
                            return i;
                        }
                    }
                    p += 4; break;
            }
        }
        return 0;
    }

    private static boolean isInitNat(byte[] src, int natIdx) {
        // NameAndType(tag 12): name_index u2, desc_index u2
        int p = 10;
        int cpCount = u2(src, 8);
        for (int i = 1; i < cpCount; i++) {
            int tag = src[p]; p += 1;
            switch (tag) {
                case TAG_UTF8:  p += u2(src, p) + 2; break;
                case TAG_LONG: case TAG_DOUBLE: p += 8; i++; break;
                case 15: p += 3; break;
                case 7: case 8: case 16: case 19: case 20: p += 2; break;
                default:
                    if (tag == 12 && i == natIdx) {
                        String n = cpUtf8(src, u2(src, p));
                        String d = cpUtf8(src, u2(src, p + 2));
                        return n.equals("<init>") && d.equals("()V");
                    }
                    p += 4; break;
            }
        }
        return false;
    }

    /** 找 UTF8 常量 s 的 cp 索引；找不到返回 0。 */
    private static int findUtf8(byte[] src, String s) {
        int cpCount = u2(src, 8);
        int p = 10;
        for (int i = 1; i < cpCount; i++) {
            int tag = src[p]; p += 1;
            switch (tag) {
                case TAG_UTF8:
                    int len = u2(src, p);
                    if (len == s.length()
                            && new String(src, p + 2, len,
                                          java.nio.charset.StandardCharsets.UTF_8).equals(s)) {
                        return i;
                    }
                    p += 2 + len; break;
                case TAG_LONG: case TAG_DOUBLE: p += 8; i++; break;
                case 15: p += 3; break;
                case 7: case 8: case 16: case 19: case 20: p += 2; break;
                default: p += 4; break;
            }
        }
        return 0;
    }

    private static boolean utf8At(byte[] src, int cpIndex, String want) {
        // caller guarantees the entry is a CONSTANT_Utf8; find its bytes:
        // we do NOT have the cp map here, so scan: entries are referenced by
        // index — instead of walking, compare via a helper that re-walks.
        return cpUtf8(src, cpIndex).equals(want);
    }

    /** Walk the constant pool and return the string of a UTF8 entry. */
    private static String cpUtf8(byte[] src, int cpIndex) {
        int cpCount = u2(src, 8);                 // magic(4)+minor(2)+major(2)
        int p = 10;                               // first cp entry
        for (int i = 1; i < cpCount; i++) {
            int tag = src[p]; p += 1;
            int len;
            switch (tag) {
                case TAG_UTF8:  len = u2(src, p); p += 2;
                    if (i == cpIndex) {
                        return new String(src, p, len, java.nio.charset.StandardCharsets.UTF_8);
                    }
                    p += len; break;
                case TAG_LONG: case TAG_DOUBLE: p += 8; i++; break;
                case 7: case 8: case 16: case 19: case 20: p += 2; break;
                case 15: p += 3; break;
                default: p += 4; break;
            }
        }
        return "";
    }

    private static int u2(byte[] b, int p) {
        return ((b[p] & 0xFF) << 8) | (b[p + 1] & 0xFF);
    }

    private static int u4(byte[] b, int p) {
        return ((b[p] & 0xFF) << 24) | ((b[p + 1] & 0xFF) << 16)
                | ((b[p + 2] & 0xFF) << 8) | (b[p + 3] & 0xFF);
    }

    private static final class ByteOut {
        private byte[] buf;
        private int len;
        ByteOut(int cap) { buf = new byte[cap]; len = 0; }
        void u2(int v) { buf[len++] = (byte) (v >> 8); buf[len++] = (byte) v; }
        void u4(int v) {
            buf[len++] = (byte) (v >> 24); buf[len++] = (byte) (v >> 16);
            buf[len++] = (byte) (v >> 8); buf[len++] = (byte) v;
        }
        void copy(byte[] src, int off, int n) {
            if (len + n > buf.length) {
                byte[] nb = new byte[Math.max(buf.length * 2, len + n)];
                System.arraycopy(buf, 0, nb, 0, len);
                buf = nb;
            }
            System.arraycopy(src, off, buf, len, n);
            len += n;
        }
        byte[] toArray() {
            byte[] r = new byte[len];
            System.arraycopy(buf, 0, r, 0, len);
            return r;
        }
    }
}
