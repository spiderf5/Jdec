'use strict';

/*
 * regnatives.js — dump every RegisterNatives call the JVM makes.
 *
 * Bridge-free (frida-java-bridge refuses to initialize on modern JDKs:
 * "Java API only partially available ... Missing: VMThread::execute ...").
 * We acquire a JNIEnv through jvm.dll's JNI_GetCreatedJavaVMs +
 * AttachCurrentThread and hook JNIEnv table slot 215 (RegisterNatives).
 *
 * Pointer discipline (the source of every crash so far):
 *   - AttachCurrentThread writes a `JNIEnv *env` into *penv.
 *   - `env` (the JNIEnv value) is a pointer to a per-thread JNIEnv VARIABLE
 *     (Hotspot embeds it in JavaThread), NOT the function table itself.
 *   - The static JNINativeInterface_ function table = env.readPointer()
 *     (one deref). All threads share one static table.
 *   - Table functions take `env` (the per-thread JNIEnv*) as first arg.
 *
 * Output messages:
 *   { type: 'regnatives', cls, method, sig, ptr }
 *   { type: 'info' | 'error', msg }
 *
 * NOTE: no setInterval — JS timers never fire in these targets (verified);
 * the python wrapper pumps rpc.exports.tryInstall() instead.
 */

const PS = Process.pointerSize;
const SLOT_FIND_CLASS = 6;
const SLOT_GET_METHOD_ID = 33;
const SLOT_CALL_OBJECT_METHOD = 34;
const SLOT_GET_STRING_UTF_CHARS = 169;
const SLOT_RELEASE_STRING_UTF_CHARS = 170;
const SLOT_REGISTER_NATIVES = 215;
const VMSLOT_ATTACH_THREAD = 4;   // JavaVM (JNIInvokeInterface_) slot

let installed = false;

function tableFn(table, slot, retType, argTypes) {
    return new NativeFunction(table.add(slot * PS).readPointer(),
                              retType, argTypes);
}

function jstringToUtf8(env, table, jstr) {
    if (jstr.isNull()) return '<null>';
    const get = tableFn(table, SLOT_GET_STRING_UTF_CHARS, 'pointer',
                        ['pointer', 'pointer', 'pointer']);
    const c = get(env, jstr, NULL);
    let s = '';
    if (!c.isNull()) {
        s = c.readUtf8String();
        const rel = tableFn(table, SLOT_RELEASE_STRING_UTF_CHARS, 'void',
                            ['pointer', 'pointer', 'pointer']);
        rel(env, jstr, c);
    }
    return s;
}

function install(env) {
    if (installed) return;
    installed = true;

    // env is the per-thread JNIEnv*; the static table is one deref away
    const table = env.readPointer();

    const rnPtr = table.add(SLOT_REGISTER_NATIVES * PS).readPointer();
    let getNameID = NULL;   // resolved lazily on a live Java thread

    Interceptor.attach(rnPtr, {
        onEnter(args) {
            const env = args[0];          // caller's JNIEnv*
            const clazz = args[1];
            const methods = args[2];
            const count = args[3].toInt32();

            if (getNameID.isNull()) {
                try {
                    const findClass = tableFn(table, SLOT_FIND_CLASS,
                                              'pointer', ['pointer', 'pointer']);
                    const getMethodID = tableFn(table, SLOT_GET_METHOD_ID,
                                                'pointer',
                                                ['pointer', 'pointer', 'pointer', 'pointer']);
                    const classClass = findClass(env,
                        Memory.allocUtf8String('java/lang/Class'));
                    getNameID = getMethodID(env, classClass,
                        Memory.allocUtf8String('getName'),
                        Memory.allocUtf8String('()Ljava/lang/String;'));
                } catch (e) { /* retry on next call */ }
            }

            let clsName = '<unknown>';
            if (!getNameID.isNull()) {
                try {
                    const callObjectMethod = tableFn(table,
                        SLOT_CALL_OBJECT_METHOD, 'pointer',
                        ['pointer', 'pointer', 'pointer']);
                    const nameObj = callObjectMethod(env, clazz, getNameID);
                    clsName = jstringToUtf8(env, table, nameObj);
                } catch (e) {
                    clsName = '<name error: ' + e + '>';
                }
            }
            for (let i = 0; i < count; i++) {
                const m = methods.add(i * 3 * PS);
                let name = '?', sig = '?', fn = NULL, base = NULL, mod = '?';
                try {
                    name = m.readPointer().readUtf8String();
                    sig = m.add(PS).readPointer().readUtf8String();
                    fn = m.add(2 * PS).readPointer();
                    const range = Process.findRangeByAddress(fn);
                    if (range) {
                        base = range.base;
                        if (range.file && range.file.path) mod = range.file.path;
                    }
                } catch (e) { }
                send({ type: 'regnatives', cls: clsName, method: name,
                       sig: sig, ptr: fn.toString(),
                       base: base === NULL ? '?' : base.toString(), mod: mod });
            }
        }
    });
    send({ type: 'info', msg: 'regnatives installed @ ' + rnPtr });
}

function acquireEnv() {
    // Fully defensive: during VM boot the module exists but the VM object
    // is half-initialized — any doubt = return null, retry next tick.
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
        // JNIInvokeInterface_ table pointer (verified on Zulu 21)
        const functions = vm.readPointer();
        if (functions.isNull()) return null;
        for (let i = 3; i <= 7; i++) {
            if (functions.add(i * PS).readPointer().isNull()) return null;
        }
        const attachThread = new NativeFunction(
            functions.add(VMSLOT_ATTACH_THREAD * PS).readPointer(), 'int',
            ['pointer', 'pointer', 'pointer']);
        const envBuf = Memory.alloc(PS);
        const r = attachThread(vm, envBuf, NULL);
        if (r !== 0) return null;
        const env = envBuf.readPointer();
        if (env.isNull()) return null;
        // table sanity: deref once, slot 215 must be a code pointer
        const table = env.readPointer();
        if (table.isNull()) return null;
        if (table.add(SLOT_REGISTER_NATIVES * PS).readPointer().isNull()) {
            return null;
        }
        return env;
    } catch (e) {
        return null;
    }
}

rpc.exports = {
    tryinstall: function () {
        if (installed) return true;
        const env = acquireEnv();
        if (env === null) return false;
        install(env);
        return installed;
    }
};
