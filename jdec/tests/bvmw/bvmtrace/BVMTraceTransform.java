import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.jar.JarEntry;
import java.util.jar.JarInputStream;
import java.util.jar.JarOutputStream;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.objectweb.asm.Opcodes.ALOAD;
import static org.objectweb.asm.Opcodes.ASTORE;
import static org.objectweb.asm.Opcodes.ILOAD;
import static org.objectweb.asm.Opcodes.INVOKEINTERFACE;
import static org.objectweb.asm.Opcodes.INVOKESTATIC;

/**
 * BVMTraceTransform - stage-3 bytecode rewriter (build-time only, needs ASM).
 *
 * Injects a BVMTrace.mark call before every inner-VM handler dispatch in the
 * four BytecodeVM main classes. See BVMTrace for the runtime side and the
 * invariant documentation (locals 4/49/62 + handler local found by scanning
 * back for the last ASTORE whose local is reloaded before the call).
 *
 * Frame safety: ASM tree API keeps StackMapTable as FrameNodes inside the
 * instruction list; pure stack-neutral insertion keeps frame content valid
 * and ClassWriter recomputes frame offsets on write, so no COMPUTE_FRAMES
 * (and no classpath resolution) is needed.
 *
 * usage: BVMTraceTransform transform <in.jar> <out.jar>
 */
public class BVMTraceTransform {

    private static final Pattern MAIN_NAME =
            Pattern.compile("^BytecodeVM/BytecodeVM\\$(\\d+)\\.class$");

    private static byte[] transformMain(byte[] cls) throws IOException {
        ClassNode cn = new ClassNode();
        new ClassReader(cls).accept(cn, 0);
        String self = cn.name;                       // BytecodeVM/BytecodeVM$N
        int injected = 0;
        for (MethodNode mn : cn.methods) {
            if (mn.instructions == null) {
                continue;
            }
            for (AbstractInsnNode ins : mn.instructions.toArray()) {
                if (!(ins instanceof MethodInsnNode)) {
                    continue;
                }
                MethodInsnNode mi = (MethodInsnNode) ins;
                if (mi.getOpcode() != INVOKEINTERFACE
                        || !mi.owner.startsWith(self + "$")
                        || !mi.owner.endsWith("$Handler")
                        || !mi.name.endsWith("$execute")) {
                    continue;
                }
                // handler local = last ASTORE before the call whose local is
                // reloaded between the store and the call (first execute arg)
                AbstractInsnNode p = mi.getPrevious();
                VarInsnNode hstore = null;
                int steps = 0;
                while (p != null && steps++ < 40) {
                    if (p instanceof VarInsnNode
                            && p.getOpcode() == ASTORE) {
                        hstore = (VarInsnNode) p;
                        break;
                    }
                    p = p.getPrevious();
                }
                if (hstore == null) {
                    throw new IllegalStateException(
                            "handler astore not found before execute in "
                            + self + "." + mn.name);
                }
                int lh = hstore.var;
                boolean reloads = false;
                for (AbstractInsnNode q = hstore.getNext();
                        q != null && q != mi; q = q.getNext()) {
                    if (q instanceof VarInsnNode
                            && q.getOpcode() == ALOAD
                            && ((VarInsnNode) q).var == lh) {
                        reloads = true;
                        break;
                    }
                }
                if (!reloads) {
                    throw new IllegalStateException(
                            "aload " + lh + " not found between astore and "
                            + "execute in " + self + "." + mn.name);
                }
                InsnList add = new InsnList();
                add.add(new VarInsnNode(ILOAD, 4));    // mapped opcode
                add.add(new VarInsnNode(ILOAD, 49));   // physical slot index
                add.add(new VarInsnNode(ILOAD, 62));   // loop-carried int
                add.add(new VarInsnNode(ALOAD, lh));   // handler instance
                add.add(new MethodInsnNode(INVOKESTATIC, "BVMTrace", "mark",
                        "(IIILjava/lang/Object;)V", false));
                mn.instructions.insert(hstore, add);
                injected++;
            }
        }
        if (injected != 1) {
            throw new IllegalStateException(self + ": expected exactly 1 "
                    + "dispatch site, found " + injected);
        }
        ClassWriter cw = new ClassWriter(0);
        cn.accept(cw);
        return cw.toByteArray();
    }

    private static void transform(String inJar, String outJar)
            throws IOException {
        try (JarInputStream jin = new JarInputStream(
                        Files.newInputStream(Paths.get(inJar)));
                JarOutputStream jout = new JarOutputStream(
                        Files.newOutputStream(Paths.get(outJar)))) {
            byte[] buf = new byte[1 << 16];
            JarEntry e;
            while ((e = jin.getNextJarEntry()) != null) {
                String name = e.getName();
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                int n;
                while ((n = jin.read(buf)) > 0) {
                    bos.write(buf, 0, n);
                }
                byte[] data = bos.toByteArray();
                if (MAIN_NAME.matcher(name).matches()) {
                    data = transformMain(data);
                    System.out.println("[BVMTrace] instrumented " + name);
                }
                jout.putNextEntry(new JarEntry(name));
                jout.write(data);
                jout.closeEntry();
            }
            // pack the runtime logger so the instrumented jar is standalone
            try (InputStream is = BVMTraceTransform.class.getResourceAsStream(
                    "/BVMTrace.class")) {
                if (is == null) {
                    throw new IOException("BVMTrace.class resource not found");
                }
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                int k;
                while ((k = is.read(buf)) > 0) {
                    bos.write(buf, 0, k);
                }
                jout.putNextEntry(new JarEntry("BVMTrace.class"));
                jout.write(bos.toByteArray());
                jout.closeEntry();
            }
        }
        System.out.println("[BVMTrace] wrote " + outJar);
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 3 && args[0].equals("transform")) {
            transform(args[1], args[2]);
            return;
        }
        System.err.println(
                "usage: BVMTraceTransform transform <in.jar> <out.jar>");
        System.exit(2);
    }
}
