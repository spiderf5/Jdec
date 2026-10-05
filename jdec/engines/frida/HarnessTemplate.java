/*
 * HarnessTemplate.java — native 方法回填的 Java 侧打点模板。
 *
 * 原理：native 化家族（JNIC/MyJ2C/radioegor146/PhantomShield）把 Java 方法
 * 体翻译成 C，方法语义通过 JNIEnv 回调 JVM。jnitrace.js 按 *线程* 记录
 * JNI 调用序列；要让 trace 归属到具体方法，由 harness 在调用前后打
 * ENTER/EXIT 标记，trace2java.py 按标记切段。
 *
 * 用法：
 *   1. 把要采的 native 方法调用抄进 main()（反射或直接调用），
 *      每个调用点前后打印标记行（System.out 会被 wrapper 透传）。
 *   2. jdec/engines/frida/dump_mappings.py --script jt.js --jni-out t.tsv
 *      -- <你的启动参数>
 *   3. 把 stdout 存成 markers.txt，trace2java.py t.tsv --markers markers.txt
 *
 * 注意：必须先让目标自身的加载器跑完（JNIC 会解压 payload 并
 * RegisterNatives），再打点调用。
 */
public class HarnessTemplate {

    private static void enter(String tag) {
        System.out.println("===ENTER " + tag + "===");
        System.out.flush();
    }

    private static void exit(String tag) {
        System.out.println("===EXIT " + tag + "===");
        System.out.flush();
    }

    public static void main(String[] args) throws Exception {
        // 例：调用目标 jar 里的 native 方法（名字/签名按 report 或
        // regnatives TSV 来；regnatives dump 出的正是 全表）
        enter("com.example.Target.nativeFunc(int)");
        // Target.nativeFunc(42);
        exit("com.example.Target.nativeFunc(int)");

        enter("com.example.Target.decryptString(byte[])");
        // byte[] out = Target.decryptString(input);
        exit("com.example.Target.decryptString(byte[])");
    }
}
