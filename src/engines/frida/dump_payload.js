'use strict';

/*
 * dump_payload.js — catch the native library that JNIC-style loaders
 * decrypt and drop to disk at startup.
 *
 * The JNIC/MyJ2C payload ships as an encrypted .dat resource inside the jar
 * (static unpack requires the loader algorithm), but the loader WRITES the
 * decompressed library to a temp file before System.load. Hook
 * CreateFileW/CreateFileA and record every path that looks like a native
 * library — after the run, the wrapper copies whatever still exists.
 *
 * Usage (python side): see dump_mappings.py --mode attach with this script;
 * or standalone: frida -f java.exe -l dump_payload.js -- <args>
 */

const CREATE_FILE_W = Module.getExportByName('kernel32.dll', 'CreateFileW');
const CREATE_FILE_A = Module.getExportByName('kernel32.dll', 'CreateFileA');
const GENERIC_WRITE = 0x40000000;
const seen = {};

function report(path) {
    const lower = path.toLowerCase();
    if (!(lower.endsWith('.dll') || lower.endsWith('.so') ||
          lower.endsWith('.dat'))) {
        return;
    }
    if (seen[path]) return;
    seen[path] = true;
    send({ type: 'payload', path: path });
}

Interceptor.attach(CREATE_FILE_W, {
    onEnter(args) {
        try {
            this.path = args[0].readUtf16String();
            this.write = (args[1].toUInt32() & GENERIC_WRITE) !== 0;
        } catch (e) { }
    },
    onLeave(retval) {
        if (this.write && this.path && retval.toInt32() > 0) {
            report(this.path);
        }
    }
});

Interceptor.attach(CREATE_FILE_A, {
    onEnter(args) {
        try {
            this.path = args[0].readAnsiString();
            this.write = (args[1].toUInt32() & GENERIC_WRITE) !== 0;
        } catch (e) { }
    },
    onLeave(retval) {
        if (this.write && this.path && retval.toInt32() > 0) {
            report(this.path);
        }
    }
});

send({ type: 'info', msg: 'payload watcher installed' });
