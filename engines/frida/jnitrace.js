'use strict';

/*
 * jnitrace.js — trace the JNI "IO skeleton" of native methods (bridge-free).
 *
 * Native-obfuscator family (JNIC / MyJ2C / radioegor146 / PhantomShield)
 * translates Java bytecode into C that calls back through JNIEnv for every
 * class / field / method / string access. Tracing those table slots per
 * thread reconstructs the original method's semantic skeleton — pair the
 * trace with a Java-side harness that prints ENTER/EXIT markers per method
 * invocation to attribute segments.
 *
 * Env acquisition note: frida-java-bridge refuses to initialize on modern
 * JDKs (missing Hotspot internal symbols), so we acquire JNIEnv through
 * jvm.dll's JNI_GetCreatedJavaVMs + vm->GetEnv instead. See regnatives.js.
 *
 * Traced slots (JNINativeInterface_ indices):
 *    6  FindClass           arg1 = char* name
 *    33 GetMethodID         arg2 = char* name, arg3 = char* sig
 *    94 GetFieldID          arg2 = char* name, arg3 = char* sig
 *    113 GetStaticMethodID  arg2 = char* name, arg3 = char* sig
 *    167 NewStringUTF       arg1 = char* bytes  (string constant!)
 *    169 GetStringUTFChars  arg1 = jstring      (reads via table call)
 */

const PS = Process.pointerSize;
const SLOT_FIND_CLASS = 6;
const SLOT_GET_METHOD_ID = 33;
const SLOT_GET_FIELD_ID = 94;
const SLOT_GET_STATIC_METHOD_ID = 113;
const SLOT_NEW_STRING_UTF = 167;
const SLOT_GET_STRING_UTF_CHARS = 169;
const SLOT_RELEASE_STRING_UTF_CHARS = 170;
const VMSLOT_ATTACH_THREAD = 4;
const JNI_VERSION_1_6 = 0x00010006;

const SLOTS = [
    [SLOT_FIND_CLASS, 'FindClass', [1]],
    [SLOT_GET_METHOD_ID, 'GetMethodID', [2, 3]],
    [SLOT_GET_FIELD_ID, 'GetFieldID', [2, 3]],
    [SLOT_GET_STATIC_METHOD_ID, 'GetStaticMethodID', [2, 3]],
    [SLOT_NEW_STRING_UTF, 'NewStringUTF', [1]],
    [SLOT_GET_STRING_UTF_CHARS, 'GetStringUTFChars', []],
];

let installed = false;

function tableFn(table, slot, retType, argTypes) {
    return new NativeFunction(table.add(slot * PS).readPointer(),
                              retType, argTypes);
}

function jstringToUtf8(env, jstr) {  // env = caller's JNIEnv*
    if (jstr.isNull()) return '<null>';
    const get = tableFn(env, SLOT_GET_STRING_UTF_CHARS, 'pointer',
                        ['pointer', 'pointer', 'pointer']);
    const c = get(env, jstr, NULL);
    let s = '';
    if (!c.isNull()) {
        s = c.readUtf8String();
        const rel = tableFn(env, SLOT_RELEASE_STRING_UTF_CHARS, 'void',
                            ['pointer', 'pointer', 'pointer']);
        rel(env, jstr, c);
    }
    return s;
}

function safeUtf8(p) {
    try { return p.isNull() ? '<null>' : p.readUtf8String(); }
    catch (e) { return '<unreadable>'; }
}

function install(env) {
    if (installed) return;
    installed = true;
    // env is the per-thread JNIEnv*; the static table is one deref away
    const table = env.readPointer();

    for (const [slot, name, strArgs] of SLOTS) {
        const fnPtr = table.add(slot * PS).readPointer();
        Interceptor.attach(fnPtr, {
            onEnter(args) {
                const parts = [];
                for (const ai of strArgs) {
                    parts.push(safeUtf8(args[ai]));
                }
                if (slot === SLOT_GET_STRING_UTF_CHARS) {
                    parts.push(jstringToUtf8(args[0], args[1]));
                }
                send({ type: 'jni', tid: Process.getCurrentThreadId(),
                       fn: name, args: parts });
            }
        });
    }
    send({ type: 'info', msg: 'jnitrace installed (' + SLOTS.length + ' slots)' });
}

function acquireEnv() {
    // Fully defensive: during VM boot the module exists but the VM object
    // is half-initialized (garbage functions field -> access violation).
    // Any doubt = return null and retry on the next tick; NEVER fault.
    try {
        const m = Process.enumerateModules().find(
            m => m.name.toLowerCase() === 'jvm.dll');
        if (!m) return null;
        const getCreated = new NativeFunction(
            Module.getExportByName('jvm.dll', 'JNI_GetCreatedJavaVMs'),
            'int', ['pointer', 'int', 'pointer']);
        const vmBuf = Memory.alloc(PS);
        const cntBuf = Memory.alloc(4);
        getCreated(vmBuf, 1, cntBuf);
        if (cntBuf.readInt() < 1) return null;
        const vm = vmBuf.readPointer();
        if (vm.isNull()) return null;
        // vm is a C++ JavaVM object whose FIRST FIELD is the
        // JNIInvokeInterface_ table pointer (verified on Zulu 21: reading
        // slots from vm directly yields shifted/null pointers)
        const functions = vm.readPointer();
        if (functions.isNull()) return null;
        // table sanity: slots 3..7 (Destroy/Attach/Detach/GetEnv/AttachAsDaemon)
        // must all be non-null before we dare call anything
        for (let i = 3; i <= 7; i++) {
            if (functions.add(i * PS).readPointer().isNull()) return null;
        }
        const attachThread = new NativeFunction(
            functions.add(4 * PS).readPointer(), 'int',
            ['pointer', 'pointer', 'pointer']);
        const envBuf = Memory.alloc(PS);
        const r = attachThread(vm, envBuf, NULL);
        if (r !== 0) return null;
        const env = envBuf.readPointer();
        if (env.isNull()) return null;
        // one more sanity: JNIEnv slot 215 must be a code pointer
        const rn = env.add(215 * PS).readPointer();
        if (rn.isNull()) return null;
        return env;
    } catch (e) {
        return null;
    }
}

// NOTE: no setInterval here — JS timers are unreliable in these targets
// (verified: top-level + python-driven rpc ticks work, timers never fire).
// The python wrapper pumps rpc.exports.try_install() instead.
rpc.exports = {
    tryinstall: function () {
        if (installed) return true;
        const env = acquireEnv();
        if (env === null) return false;
        install(env);
        return installed;
    }
};
