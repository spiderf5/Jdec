import java.io.*;
import java.util.*;

/**
 * Minimal class-file rewriter that inserts a callback at the exit points of
 * javax.crypto.Cipher.doFinal.
 *
 * A full bytecode library would be overkill: Cipher is a JDK class we can rewrite
 * by hand at exactly one method. doFinal has several return paths, each ending in
 * xRETURN followed by the optional checkcast the compiler emits for the covariant
 * signature, so every return site gets the same two-instruction sequence spliced
 * in front of it:
 *
 *     <push local slot holding the plaintext String>
 *     invokestatic StringsSpy.record(Ljava/lang/String;)V
 *
 * The plaintext String is already on the stack at every return, so nothing has to
 * be re-read from locals; the slot number is found from the method descriptor.
 *
 * If anything about the class is not exactly what we expect -- an unexpected
 * method count, an unrecognised return, a descriptor we cannot read -- the whole
 * rewrite is abandoned and null is returned, leaving the original bytes in place.
 * A capture that silently does nothing is better than a JVM that will not start.
 */
final class CipherTap {

    private static final int CONSTANT_UTF8 = 1;
    private static final int CONSTANT_INTEGER = 3;
    private static final int CONSTANT_FLOAT = 4;
    private static final int CONSTANT_LONG = 5;
    private static final int CONSTANT_DOUBLE = 6;
    private static final int CONSTANT_CLASS = 7;
    private static final int CONSTANT_STRING = 8;
    private static final int CONSTANT_FIELDREF = 9;
    private static final int CONSTANT_METHODREF = 10;
    private static final int CONSTANT_INTERFACE_METHODREF = 11;
    private static final int CONSTANT_NAME_AND_TYPE = 12;
    private static final int CONSTANT_METHOD_HANDLE = 15;
    private static final int CONSTANT_METHOD_TYPE = 16;
    private static final int CONSTANT_DYNAMIC = 17;
    private static final int CONSTANT_INVOKE_DYNAMIC = 18;
    private static final int CONSTANT_MODULE = 19;
    private static final int CONSTANT_PACKAGE = 20;

    private static final int ACC_STATIC = 0x0008;

    private static final int OP_IRETURN = 0xAC;
    private static final int OP_ARETURN = 0xB0;
    private static final int OP_RETURN = 0xB1;

    static byte[] instrument(byte[] in, String className) {
        try {
            return rewrite(in);
        } catch (Throwable t) {
            if (DEBUG) System.err.println("[tap] " + className + " threw " + t);
            return null;
        }
    }

    private static final boolean DEBUG =
            System.getProperty("tap.debug") != null;

    /** Why a method was left alone; only printed when tap.debug is set. */
    private static byte[] decline(String why) {
        if (DEBUG) System.err.println("[tap] declined: " + why);
        return null;
    }

    private static byte[] rewrite(byte[] src) throws java.io.IOException {
        Cursor c = new Cursor(src);
        c.u4();                       // magic
        int minor = c.u2();
        int major = c.u2();
        int cpCount = c.u2();

        // --- read the constant pool so we can append entries at the end --------
        Object[] cp = new Object[cpCount];
        int[] tags = new int[cpCount];
        for (int i = 1; i < cpCount; i++) {
            int tag = c.u1();
            tags[i] = tag;
            switch (tag) {
                case CONSTANT_UTF8: {
                    int len = c.u2();
                    cp[i] = c.bytes(len);
                    break;
                }
                case CONSTANT_INTEGER:
                case CONSTANT_FLOAT:
                    cp[i] = c.u4();
                    break;
                case CONSTANT_LONG:
                case CONSTANT_DOUBLE:
                    cp[i] = c.u4(); c.u4();
                    i++;                              // occupies two slots
                    // The second half of a long/double is not an entry of its
                    // own. Leaving a stale tag there makes serialise() emit a
                    // bogus constant, so mark it explicitly as unused.
                    tags[i] = 0;
                    cp[i] = null;
                    break;
                case CONSTANT_CLASS:
                case CONSTANT_STRING:
                case CONSTANT_METHOD_TYPE:
                case CONSTANT_MODULE:
                case CONSTANT_PACKAGE:
                    cp[i] = c.u2();
                    break;
                case CONSTANT_FIELDREF:
                case CONSTANT_METHODREF:
                case CONSTANT_INTERFACE_METHODREF:
                case CONSTANT_NAME_AND_TYPE:
                case CONSTANT_DYNAMIC:
                case CONSTANT_INVOKE_DYNAMIC:
                    cp[i] = new int[]{c.u2(), c.u2()};
                    break;
                case CONSTANT_METHOD_HANDLE:
                    cp[i] = new int[]{c.u1(), c.u2()};
                    break;
                default:
                    throw new IllegalStateException("unknown cp tag " + tag);
            }
        }

        // Reserve headroom for the entries we are about to add. cp_count is
        // written as the array length, so the surplus is carried as tag-0 slots
        // that serialise() skips.
        Object[] cpOrig = cp;
        int[] tagsOrig = tags;
        cp = Arrays.copyOf(cpOrig, cpOrig.length + HEADROOM);
        tags = Arrays.copyOf(tagsOrig, tagsOrig.length + HEADROOM);

        int accessFlags = c.u2();
        int thisClass = c.u2();
        int superClass = c.u2();
        int ifaceCount = c.u2();
        int[] ifaces = new int[ifaceCount];
        for (int i = 0; i < ifaceCount; i++) ifaces[i] = c.u2();

        // --- fields: copied verbatim ------------------------------------------
        // --- constants we need, added before any method is patched -----------
        int utf8RecordDesc = addUtf8(cp, tags, "(Ljava/lang/String;)V");
        int utf8Record = addUtf8(cp, tags, "record");
        int utf8Spy = addUtf8(cp, tags, "StringsSpy");
        int classSpy = addClass(cp, tags, utf8Spy);
        int natRecord = addNameAndType(cp, tags, utf8Record, utf8RecordDesc);
        int refRecord = addMethodRef(cp, tags, classSpy, natRecord);

        int fieldCount = c.u2();
        List<byte[]> fieldAttrs = new ArrayList<byte[]>();
        for (int i = 0; i < fieldCount; i++) {
            c.u2(); c.u2(); c.u2();                    // access, name, desc
            int n = c.u2();
            for (int k = 0; k < n; k++) fieldAttrs.add(readAttr(c));
        }

        // --- methods -----------------------------------------------------------
        int methodCount = c.u2();
        List<byte[]> outMethods = new ArrayList<byte[]>();
        boolean touched = false;

        for (int i = 0; i < methodCount; i++) {
            int mAcc = c.u2();
            int mName = c.u2();
            int mDesc = c.u2();
            int attrCount = c.u2();
            List<byte[]> attrs = new ArrayList<byte[]>();
            for (int k = 0; k < attrCount; k++) attrs.add(readAttr(c));

            String name = utf8(cp, mName);
            String desc = utf8(cp, mDesc);
            // Cipher exposes doFinal as both static and instance overloads; the
            // tap cares about any of them that hand back a String.
            if ("doFinal".equals(name) && desc.endsWith(")Ljava/lang/String;")) {
                if (DEBUG) {
                    System.err.println("[tap] candidate doFinal" + desc);
                }
                byte[] rewritten = patchMethod(cp, tags, attrs, refRecord);
                if (rewritten != null) {
                    // Keep every attribute except the old Code; the rebuilt Code
                    // carries its own exception table and nested attributes.
                    List<byte[]> merged = new ArrayList<byte[]>();
                    for (byte[] a : attrs) {
                        if (!utf8(cp, be16(a, 0)).equals("Code")) merged.add(a);
                    }
                    merged.add(rewritten);
                    attrs = merged;
                    touched = true;
                }
            }
            outMethods.add(buildMethod(mAcc, mName, mDesc, attrs));
        }

        if (!touched) return decline("no static doFinal matched");

        int classAttrCount = c.u2();
        List<byte[]> classAttrs = new ArrayList<byte[]>();
        for (int i = 0; i < classAttrCount; i++) classAttrs.add(readAttr(c));

        // --- serialise ----------------------------------------------------------
        // cp_count counts real entries plus one, and a long/double occupies two
        // slots -- so the count is derived from what is actually emitted, not
        // from the array length. Emitting the padded length is what produces
        // "Unknown constant tag 0" in the verifier.
        int highest = 0;
        for (int i = 1; i < cp.length; i++) {
            if (tags[i] != 0) highest = i;
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream(src.length + 4096);
        writeU4(out, 0xCAFEBABE);
        // The original version is preserved: rewriting a class to a different
        // major version can change which attributes the verifier expects.
        writeU2(out, minor);
        writeU2(out, major);
        writeU2(out, highest + 1);
        for (int i = 1; i <= highest; i++) {
            if (tags[i] == 0) {
                // A hole: the second slot of a long/double, or unused headroom.
                // It occupies an index but carries no bytes of its own, and
                // writing anything here (a zero tag is not valid) would make the
                // class unparseable. Indices of later entries still line up
                // because the hole is skipped, not shrunk.
                continue;
            }
            writeU1(out, tags[i]);
            Object v = cp[i];
            switch (tags[i]) {
                case CONSTANT_UTF8:
                    byte[] b = (byte[]) v;
                    writeU2(out, b.length); out.write(b, 0, b.length);
                    break;
                case CONSTANT_INTEGER:
                case CONSTANT_FLOAT:
                    writeU4(out, (Integer) v); break;
                case CONSTANT_LONG:
                case CONSTANT_DOUBLE:
                    writeU4(out, (Integer) v); writeU4(out, 0); i++; break;
                case CONSTANT_CLASS:
                case CONSTANT_STRING:
                case CONSTANT_METHOD_TYPE:
                case CONSTANT_MODULE:
                case CONSTANT_PACKAGE:
                    writeU2(out, (Integer) v); break;
                case CONSTANT_METHOD_HANDLE:
                    writeU1(out, ((int[]) v)[0]); writeU2(out, ((int[]) v)[1]); break;
                case CONSTANT_FIELDREF:
                case CONSTANT_METHODREF:
                case CONSTANT_INTERFACE_METHODREF:
                case CONSTANT_NAME_AND_TYPE:
                case CONSTANT_DYNAMIC:
                case CONSTANT_INVOKE_DYNAMIC:
                    writeU2(out, ((int[]) v)[0]); writeU2(out, ((int[]) v)[1]); break;
                default:
                    throw new IllegalStateException("unhandled cp tag " + tags[i]);
            }
        }
        writeU2(out, accessFlags);
        writeU2(out, thisClass);
        writeU2(out, superClass);
        writeU2(out, ifaceCount);
        for (int v : ifaces) writeU2(out, v);
        writeU2(out, fieldCount);
        for (byte[] a : fieldAttrs) out.write(a, 0, a.length);
        writeU2(out, outMethods.size());
        for (byte[] m : outMethods) out.write(m, 0, m.length);
        // Class-level attributes (SourceFile, BootstrapMethods, ...) are copied
        // verbatim. Dropping BootstrapMethods would break every indy call site
        // in the class, so they must survive.
        writeU2(out, classAttrs.size());
        for (byte[] a : classAttrs) out.write(a, 0, a.length);
        return out.toByteArray();
    }

    /**
     * Insert the record() call before each areturn in the single Code attribute.
     *
     * doFinal returns the plaintext String in a register that the compiler
     * allocated, so rather than tracking the verifier's slot allocation we store
     * the returned reference into a fresh local (astore/aload) and pass that.
     * The extra local is why max_locals is bumped; max_stack gets +1 because the
     * invokestatic needs the reference pushed again.
     *
     * Returns the rebuilt attribute bytes, or null to signal "leave this method".
     */
    private static byte[] patchMethod(Object[] cp, int[] tags, List<byte[]> attrs,
                                      int methodRef) throws java.io.IOException {
        byte[] raw = null;
        int codeNameIdx = -1;
        for (byte[] a : attrs) {
            if (utf8(cp, be16(a, 0)).equals("Code")) {
                int len = be32(a, 2);
                codeNameIdx = be16(a, 0);          // the attribute's own name index
                raw = Arrays.copyOfRange(a, 6, 6 + len);
                break;
            }
        }
        if (raw == null) return decline("no Code attribute");

        int maxStack = be16(raw, 0);
        int maxLocals = be16(raw, 2);
        int codeLen = be32(raw, 4);
        if (8 + codeLen > raw.length) return null;
        byte[] body = Arrays.copyOfRange(raw, 8, 8 + codeLen);

        // Exception table: entries are (start_pc, end_pc, handler_pc, catch_type).
        int excCount = be16(raw, 8 + codeLen);
        int[][] exc = new int[excCount][4];
        for (int i = 0; i < excCount; i++) {
            int base = 10 + codeLen + i * 8;
            for (int k = 0; k < 4; k++) exc[i][k] = be16(raw, base + k * 2);
        }

        // A StackMapTable records frame offsets that any insertion invalidates.
        // The frames themselves stay valid here -- astore/aload/invokestatic on
        // a fresh slot introduces no branch target and so needs no new frame --
        // so the table is rewritten with shifted offsets rather than abandoned.
        int tailStart = 10 + codeLen + excCount * 8;
        int attrCount2 = be16(raw, tailStart);
        if (DEBUG) {
            System.err.println("[tap] codeLen=" + codeLen + " excCount=" + excCount
                    + " rawLen=" + raw.length + " tailStart=" + tailStart
                    + " attrCount2=" + attrCount2);
        }
        int p = tailStart + 2;
        byte[] smt = null;                 // StackMapTable payload, if present
        int smtSlot = -1;
        for (int i = 0; i < attrCount2; i++) {
            int nameIdx = be16(raw, p);
            int alen = be32(raw, p + 2);
            String an = utf8(cp, nameIdx);
            if ("StackMapTable".equals(an)) {
                smt = Arrays.copyOfRange(raw, p + 6, p + 6 + alen);
                smtSlot = i;
            }
            if ("StackMap".equals(an)) return decline("legacy StackMap");
            p += 6 + alen;
        }

        int[] pcs = instructionOffsets(body);
        if (pcs.length == 0) return decline("no instructions decoded");

        int newMaxLocals = maxLocals;      // dup needs no new local slot
        int newMaxStack = maxStack + 1;    // the duplicated value sits on the stack

        // old pc -> new pc. -1 means "not an instruction boundary"; defaulting to
        // 0 would silently retarget a branch at the top of the method.
        int[] map = new int[body.length + 1];
        Arrays.fill(map, -1);
        ByteArrayOutputStream nb = new ByteArrayOutputStream(body.length + 512);
        boolean sawAreturn = false;

        // Pass 1: work out where every instruction lands. A branch's own
        // position does not depend on its target's position, so a single
        // forward sweep is enough to fill the whole map.
        for (int idx = 0; idx < pcs.length; idx++) {
            int pc = pcs[idx];
            int op = body[pc] & 0xFF;
            map[pc] = nb.size();
            if (op == OP_ARETURN) {
                sawAreturn = true;
                for (int k = 0; k < INSERT_WIDTH; k++) nb.write(0);
            } else {
                int end = (idx + 1 < pcs.length) ? pcs[idx + 1] : body.length;
                nb.write(body, pc, end - pc);
            }
        }
        if (!sawAreturn) return decline("no areturn in doFinal");
        map[body.length] = nb.size();

        // Pass 2: emit for real, now that every target position is known.
        nb.reset();
        for (int idx = 0; idx < pcs.length; idx++) {
            int pc = pcs[idx];
            int end = (idx + 1 < pcs.length) ? pcs[idx + 1] : body.length;
            int op = body[pc] & 0xFF;

            if (op == OP_ARETURN) {
                // The value being returned is already on the stack. Duplicate it,
                // hand one copy to the recorder, and return the other. Using dup
                // rather than a temporary local matters: a new local would have
                // to be declared in every stack map frame after this point, and
                // getting that wrong is a VerifyError.
                nb.write(0x59);                              // dup
                nb.write(0xB8); writeU2(nb, methodRef);      // invokestatic record
                nb.write(0xB0);                              // areturn
            } else if (isBranch(op)) {
                // Re-encode the branch against the shifted target. The relative
                // operand is only correct if the bytes before the target moved by
                // the same amount as the bytes before this instruction; when they
                // did not -- which is exactly what inserting a call at an
                // areturn does -- the raw copy below would leave the branch
                // pointing into the middle of an instruction.
                int rel = (short) be16(body, pc + 1);
                int oldT = pc + rel;
                int newT = (oldT >= 0 && oldT < map.length) ? map[oldT] : -1;
                if (newT < 0) return decline("branch target " + oldT + " unmappable");
                int newRel = newT - map[pc];
                if (newRel < Short.MIN_VALUE || newRel > Short.MAX_VALUE) {
                    return decline("branch offset out of range after patch");
                }
                nb.write(op);
                writeU2(nb, newRel & 0xFFFF);
                for (int k = 3; k < end - pc; k++) nb.write(body[pc + k]);
            } else {
                nb.write(body, pc, end - pc);
            }
        }

        // Shift every exception-table offset to its new position. start_pc and
        // handler_pc must name an instruction; end_pc is allowed to equal
        // code_length, which is one past the last instruction, so it maps to the
        // end of the new code array.
        for (int[] e : exc) {
            for (int k = 0; k < 3; k++) {
                int oldPc = e[k];
                int newPc;
                if (k == 1 && oldPc == codeLen) {
                    newPc = nb.size();                 // end of the method
                } else {
                    newPc = (oldPc >= 0 && oldPc < map.length) ? map[oldPc] : -1;
                }
                if (newPc < 0) {
                    if (DEBUG) {
                        StringBuilder sb = new StringBuilder();
                        for (int q = 0; q < pcs.length; q++) sb.append(pcs[q]).append(",");
                        System.err.println("[tap] exc entry " + java.util.Arrays.toString(e)
                                + " field " + k + " oldPc=" + oldPc
                                + " codeLen=" + codeLen + " mapLen=" + map.length
                                + " decodedPcs=" + sb);
                    }
                    return decline("exception offset " + oldPc + " unmappable");
                }
                e[k] = newPc;
            }
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeU2(out, newMaxStack);
        writeU2(out, newMaxLocals);
        byte[] newBody = nb.toByteArray();
        writeU4(out, newBody.length);
        out.write(newBody, 0, newBody.length);
        writeU2(out, excCount);
        for (int[] e : exc) {
            writeU2(out, e[0]); writeU2(out, e[1]);
            writeU2(out, e[2]); writeU2(out, e[3]);
        }

        // The Code attribute carries its own attributes_count after the
        // exception table. It has to be written even when unchanged, otherwise
        // the first nested attribute's name_index is read as the count and the
        // class is rejected.
        writeU2(out, attrCount2);

        // Copy the method's nested attributes (LineNumberTable, StackMapTable,
        // LocalVariableTable, ...) rewriting the frame offsets in the latter.
        int q = tailStart + 2;
        for (int i = 0; i < attrCount2; i++) {
            int nameIdx = be16(raw, q);
            int alen = be32(raw, q + 2);
            byte[] payload = Arrays.copyOfRange(raw, q + 6, q + 6 + alen);
            if (i == smtSlot) {
                byte[] sp = shiftStackMap(payload, map, pcs);
                if (sp == null) return decline("StackMapTable offset unmappable");
                payload = sp;
            }
            writeU2(out, nameIdx);
            writeU4(out, payload.length);
            out.write(payload, 0, payload.length);
            q += 6 + alen;
        }

        // Wrap the rebuilt payload as a complete attribute_info (name_index,
        // length, bytes) so it can replace the old Code entry in the method's
        // attribute list alongside the attributes that were left alone.
        ByteArrayOutputStream wrapped = new ByteArrayOutputStream();
        writeU2(wrapped, codeNameIdx);
        writeU4(wrapped, out.size());
        out.writeTo(wrapped);
        return wrapped.toByteArray();
    }

    /**
     * Rewrite every frame_offset_delta in a StackMapTable so it points at the
     * same instruction in the patched code.
     *
     * The format is a u2 count followed by that many frames; each begins with a
     * u2 offset_delta from the previous frame (the first is absolute). Because
     * the deltas are relative they must be recomputed from the absolute new
     * positions, not shifted in place.
     *
     * Returns null when an offset cannot be mapped, which makes the caller skip
     * the method rather than emit a table the verifier would reject.
     */
    private static byte[] shiftStackMap(byte[] smt, int[] map, int[] pcs) {
        if (smt == null || smt.length < 2) return null;
        int count = be16(smt, 0);
        if (DEBUG) System.err.println("[tap] StackMapTable frames=" + count);

        int[] absolute = new int[count];
        int[] tagsSeen = new int[count];
        int p = 2;
        for (int i = 0; i < count; i++) {
            if (p >= smt.length) return decline("smt truncated at frame " + i);
            int tag = smt[p] & 0xFF;
            tagsSeen[i] = tag;

            // JVMS 4.7.4: every frame carries an offset_delta, and the frame's
            // bytecode offset is the previous frame's offset plus this delta
            // plus one (the first frame is measured from 0). For the two compact
            // forms the delta is packed INTO the tag byte: 0..63 is same_frame,
            // 64..127 is same_locals_1_stack_item_frame (delta = tag - 64, plus
            // one verification_type_info). The compact deltas are relative too,
            // not absolute -- treating tag 16 as an offset is wrong.
            if (tag <= 127) {
                int delta = (tag <= 63) ? tag : tag - 64;
                absolute[i] = (i == 0) ? delta : absolute[i - 1] + delta + 1;
                p += (tag <= 63) ? 1 : 2;
            } else {
                // 128..246 reserved. 247..255 carry an explicit u2 offset_delta
                // AFTER the tag byte, so it is read at p+1.
                if (p + 3 > smt.length) return decline("smt truncated at frame " + i);
                int delta = be16(smt, p + 1);
                absolute[i] = (i == 0) ? delta : absolute[i - 1] + delta + 1;
                p += 1 + 2 + frameSize(smt, p + 3, tag);
            }
            if (DEBUG) {
                System.err.println("[tap]   frame " + i + " absOffset=" + absolute[i]
                        + " tag=" + tag);
            }
            if (p > smt.length) return decline("smt overruns at frame " + i);
        }
        int[] moved = new int[count];
        for (int i = 0; i < count; i++) {
            int old = absolute[i];
            int newPos = (old >= 0 && old < map.length) ? map[old] : -1;
            if (newPos < 0) return null;
            moved[i] = newPos;
        }
        byte[] out = Arrays.copyOf(smt, smt.length);
        p = 2;
        for (int i = 0; i < count; i++) {
            int tag = tagsSeen[i];
            // Every delta is relative to the PREVIOUS FRAME'S NEW offset, not to
            // the previous frame's old one. Using the old value here silently
            // pushes later frames past the end of the code array.
            int delta = (i == 0) ? moved[i] : moved[i] - moved[i - 1] - 1;

            if (tag <= 63) {
                if (delta < 0 || delta > 63) return null;
                out[p] = (byte) delta;
                p += 1;
            } else if (tag <= 127) {
                if (delta < 0 || delta > 63) return null;
                out[p] = (byte) (delta + 64);
                p += 2;                                // tag + verification info
            } else {
                if (delta < 0 || delta > 0xFFFF) return null;
                out[p + 1] = (byte) ((delta >>> 8) & 0xFF);
                out[p + 2] = (byte) (delta & 0xFF);
                p += 1 + 2 + frameSize(smt, p + 3, tag);
            }
        }
        return out;
    }

    /** inserted bytes: dup, invokestatic record, areturn */
    private static final int INSERT_WIDTH = 1 + 3 + 1;

    /**
     * Bytes of frame body that follow the u2 offset_delta, for tags >= 247.
     * `p` points just past the delta, i.e. at the first verification_type_info.
     */
    private static int frameSize(byte[] b, int p, int tag) {
        switch (tag) {
            case 247: return 2;                      // same_locals_1_stack_item_ext
            case 248: case 249: case 250: return 0;   // chop
            case 251: return 0;                      // same_frame_ext
            case 252: case 253: case 254: return 2 * (tag - 251);
            case 255: {
                // full_frame: u2 number_of_locals, that many, u2 stack count, that many
                int nl = be16(b, p);
                int ns = be16(b, p + 2 + nl * 2);
                return 2 + nl * 2 + 2 + ns * 2;
            }
            default:
                if (tag < 247) throw new IllegalStateException("bad tag " + tag);
                return 0;                            // 128..246 are reserved
        }
    }

    /**
     * Writes an xload/xstore whose operand is a local slot index.
     *
     * Slots 0-3 have one-byte opcodes (aload_0 .. aload_3); slot 4 and above use
     * the plain index opcode with a single index byte. Only above 255 is the
     * `wide` prefix needed, and then it comes BEFORE the opcode -- emitting it
     * after produces a stray astore_0 that silently clobbers the argument.
     */
    private static void writeIndex(ByteArrayOutputStream o, int opcode, int slot)
            throws IOException {
        if (slot > 0xFF) {
            writeU1(o, 0xC4);            // wide prefix precedes the opcode
        }
        writeU1(o, opcode);
        if (slot > 0xFF) {
            writeU2(o, slot);
        } else {
            writeU1(o, slot);
        }
    }

    private static byte[] buildMethod(int acc, int name, int desc, List<byte[]> attrs)
            throws java.io.IOException {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        writeU2(o, acc); writeU2(o, name); writeU2(o, desc);
        writeU2(o, attrs.size());
        for (byte[] a : attrs) o.write(a, 0, a.length);
        return o.toByteArray();
    }

    private static byte[] readAttr(Cursor c) throws java.io.IOException {
        int nameIdx = c.u2();
        int len = c.u4();
        byte[] payload = c.bytes(len);
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        writeU2(o, nameIdx); writeU4(o, len); o.write(payload, 0, payload.length);
        return o.toByteArray();
    }

    private static int[] instructionOffsets(byte[] code) {
        int[] tmp = new int[code.length];
        int n = 0;
        int i = 0;
        while (i < code.length) {
            tmp[n++] = i;
            int op = code[i] & 0xFF;
            int len = Insn.length(op, code, i);
            if (len <= 0) break;
            i += len;
        }
        int[] out = Arrays.copyOf(tmp, n);
        return out;
    }

    // constant pool appends -----------------------------------------------------
    // cp_count is stored as the array length, so the pool is over-allocated up
    // front (headroom) and unused slots keep tag 0, which serialise() skips.

    private static final int HEADROOM = 8;

    private static int addUtf8(Object[] cp, int[] tags, String s) {
        byte[] b = utf8Bytes(s);
        for (int i = 1; i < cp.length; i++) {
            if (tags[i] == CONSTANT_UTF8 && cp[i] != null
                    && Arrays.equals((byte[]) cp[i], b)) return i;
        }
        return append(cp, tags, CONSTANT_UTF8, b);
    }

    // Storage shape per tag, fixed here once so the parser and the append
    // helpers cannot disagree: UTF8 -> byte[], everything with one u2 payload ->
    // Integer, everything with two -> int[].  A mismatch shows up as a
    // ClassCastException deep inside append, which is why it is centralised.
    private static int addClass(Object[] cp, int[] tags, int nameIdx) {
        return append(cp, tags, CONSTANT_CLASS, Integer.valueOf(nameIdx));
    }

    private static int addNameAndType(Object[] cp, int[] tags, int n, int d) {
        return append(cp, tags, CONSTANT_NAME_AND_TYPE, new int[]{n, d});
    }

    private static int addMethodRef(Object[] cp, int[] tags, int cls, int nat) {
        return append(cp, tags, CONSTANT_METHODREF, new int[]{cls, nat});
    }

    private static int append(Object[] cp, int[] tags, int tag, Object v) {
        for (int i = 1; i < cp.length; i++) {
            if (tags[i] != tag || cp[i] == null) continue;
            if (v instanceof byte[]) {
                if (cp[i] instanceof byte[]
                        && Arrays.equals((byte[]) cp[i], (byte[]) v)) return i;
            } else if (v instanceof int[]) {
                if (cp[i] instanceof int[]
                        && Arrays.equals((int[]) cp[i], (int[]) v)) return i;
            } else {
                if (cp[i] instanceof Integer && cp[i].equals(v)) return i;
            }
        }
        for (int i = 1; i < cp.length; i++) {
            if (tags[i] == 0) {          // free slot
                cp[i] = v;
                tags[i] = tag;
                return i;
            }
        }
        throw new IllegalStateException("constant pool out of headroom");
    }

    private static String utf8(Object[] cp, int i) {
        if (i <= 0 || i >= cp.length) return "";
        Object v = cp[i];
        if (!(v instanceof byte[])) return "";
        try { return new String((byte[]) v, "UTF-8"); } catch (Exception e) { return ""; }
    }

    private static byte[] utf8Bytes(String s) {
        try { return s.getBytes("UTF-8"); } catch (Exception e) { return s.getBytes(); }
    }

    static int be16(byte[] b, int o) { return ((b[o] & 0xFF) << 8) | (b[o + 1] & 0xFF); }
    static int be32(byte[] b, int o) {
        return ((b[o] & 0xFF) << 24) | ((b[o+1] & 0xFF) << 16)
             | ((b[o+2] & 0xFF) << 8) | (b[o+3] & 0xFF);
    }

    static void writeU1(OutputStream o, int v) throws IOException { o.write(v & 0xFF); }
    static void writeU2(OutputStream o, int v) throws IOException {
        o.write((v >>> 8) & 0xFF); o.write(v & 0xFF);
    }
    static void writeU4(OutputStream o, int v) throws IOException {
        o.write((v >>> 24) & 0xFF); o.write((v >>> 16) & 0xFF);
        o.write((v >>> 8) & 0xFF); o.write(v & 0xFF);
    }

    static final class Cursor {
        private final byte[] b; private int p;
        Cursor(byte[] b) { this.b = b; }
        int u1() { return b[p++] & 0xFF; }
        int u2() { int v = ((b[p] & 0xFF) << 8) | (b[p+1] & 0xFF); p += 2; return v; }
        int u4() { int v = ((b[p] & 0xFF) << 24) | ((b[p+1] & 0xFF) << 16)
                       | ((b[p+2] & 0xFF) << 8) | (b[p+3] & 0xFF); p += 4; return v; }
        byte[] bytes(int n) { byte[] r = Arrays.copyOfRange(b, p, p + n); p += n; return r; }
    }

    /**
     * True for opcodes whose operand is a signed 2-byte branch offset relative to
     * the instruction itself.
     *
     * ifeq..if_acmpne occupy 0x99-0xA6, goto is 0xA7 and jsr is 0xA8 -- but
     * ifnull/ifnonnull are 0xC6/0xC7, well outside that run. Leaving them out is
     * easy to miss and produces a class that parses but sends control into the
     * middle of an instruction.
     */
    private static boolean isBranch(int op) {
        return (op >= 0x99 && op <= 0xA8) || op == 0xC6 || op == 0xC7;
    }

    /** opcode lengths, including the padded switch forms */
    static final class Insn {
        static int length(int op, byte[] code, int pc) {
            switch (op) {
                case 0xAA: { // tableswitch
                    int p = pc + 1; p += (4 - (p % 4)) % 4;
                    int lo = be32(code, p + 4); int hi = be32(code, p + 8);
                    return (p + 12 + (hi - lo + 1) * 4) - pc;
                }
                case 0xAB: { // lookupswitch
                    int p = pc + 1; p += (4 - (p % 4)) % 4;
                    int npairs = be32(code, p + 4);
                    return (p + 8 + npairs * 8) - pc;
                }
                case 0xC4: { // wide
                    int op2 = code[pc + 1] & 0xFF;
                    return op2 == 0x84 ? 6 : 4;
                }
                default:
                    return LEN[op];
            }
        }
        private static final int[] LEN = new int[256];
        static {
            for (int i = 0; i < 256; i++) LEN[i] = 1;
            int[] two = {0x10,0x12,0x15,0x16,0x17,0x18,0x19,0x36,0x37,0x38,0x39,0x3A,
                         0xA9,0xBC};
            for (int i : two) LEN[i] = 2;
            int[] three = {0x11,0x13,0x14,0xB2,0xB3,0xB4,0xB5,0xB6,0xB7,0xB8,0xBB,
                           0xBD,0xC0,0xC1,0xC6,0xC7,0x84};
            for (int i : three) LEN[i] = 3;
            // ifeq..if_acmpne and goto/jsr all carry a signed 2-byte offset, so
            // they are three bytes total. Leaving these at the default of 1
            // desynchronises every offset after the first branch -- which is
            // exactly the kind of bug that only shows up on real bytecode.
            for (int op = 0x99; op <= 0xA8; op++) LEN[op] = 3;
            LEN[0xC5] = 4;                              // multianewarray
            LEN[0xB9] = 5;                              // invokeinterface
            LEN[0xBA] = 5;                              // invokedynamic
            LEN[0xC8] = 5;                              // goto_w
            LEN[0xC9] = 5;                              // jsr_w
            // variable-length forms are handled by length(), not the table
            LEN[0xAA] = 0; LEN[0xAB] = 0; LEN[0xC4] = 0;
        }
    }
}
