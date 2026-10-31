"""Deterministic models for the world outside the method.

A model is *not* an attempt to reimplement the JDK: it exists so that both
sides of a differential run see the same deterministic world, and so that the
run never touches the real filesystem, network, clock or threads. Anything the
table does not cover is an `Opaque` value, and the engine turns any outcome
that depends on one into `inconclusive`.
"""

from __future__ import annotations

from .values import Arr, JavaThrow, Obj, Opaque, Unsupported, as_int, jstr

_DIR = "dir"


class Models:
    def invoke(self, engine, cls: str, name: str, desc: str,
               receiver, args: list):
        """Return (handled, value). May raise JavaThrow / Unsupported."""
        heap = engine.heap
        if name == "<init>" and isinstance(receiver, Obj):
            base = None
            from .values import make_model
            base = make_model(cls, heap)
            if base is not None:
                receiver.fields = dict(base.fields)
                receiver.cls = cls
                return True, None
            if cls == "java/lang/Thread":
                receiver.fields = {"target": args[0] if args else None}
                return True, None
            # an unmodelled constructor is a no-op: both sides see the same
            # default state, which is all the differential run needs
            return True, None
        key = (cls, name)

        if cls == "java/lang/String" and isinstance(receiver, str):
            return True, self._string(name, receiver, args, engine)
        if cls in ("java/lang/StringBuilder", "java/lang/StringBuffer") \
                and isinstance(receiver, Obj):
            return True, self._string_builder(name, receiver, args)
        if cls == "java/lang/Object" and name == "toString" and receiver is not None:
            return True, jstr(receiver) if isinstance(receiver, str) \
                else _to_text(receiver)
        if cls in ("java/lang/Integer", "java/lang/Long", "java/lang/Short",
                   "java/lang/Byte", "java/lang/Boolean",
                   "java/lang/Character") and receiver is None:
            return True, self._boxing(cls, name, args, heap)
        if cls in ("java/lang/Math", "java/lang/StrictMath"):
            return True, self._math(name, args)
        if cls == "java/lang/System":
            return True, self._system(engine, name, args)
        if cls == "java/util/Objects" and name in ("equals", "hashCode",
                                                   "requireNonNull"):
            return True, self._objects(engine, name, args)
        if cls.startswith("java/nio/file/") or cls == "java/io/File":
            return True, self._files(engine, cls, name, args, receiver)
        if cls.startswith("java/net/") or cls in ("java/io/InputStream",
                                                  "java/io/OutputStream"):
            raise JavaThrow("java/net/ConnectException", "Connection refused")
        if cls == "java/lang/Thread" or cls == "java/lang/Runnable":
            return True, self._thread(engine, name, receiver, args)
        if cls.startswith("java/util/") and isinstance(receiver, Obj):
            return True, self._collections(engine, cls, name, receiver, args)
        if cls == "java/lang/Class" and isinstance(receiver, Obj):
            return True, (receiver.fields.get("name") if name == "getName"
                          else None) or False
        return False, None

    # -- strings ---------------------------------------------------------

    def _string(self, name: str, text: str, args, engine):
        if name == "length":
            return len(text)
        if name == "isEmpty":
            return 1 if not text else 0
        if name == "charAt":
            idx = as_int(args[0])
            if not 0 <= idx < len(text):
                raise JavaThrow(
                    "java/lang/StringIndexOutOfBoundsException", str(idx))
            return ord(text[idx])
        if name == "substring":
            begin = as_int(args[0])
            end = as_int(args[1]) if len(args) > 1 else len(text)
            if not 0 <= begin <= end <= len(text):
                raise JavaThrow(
                    "java/lang/StringIndexOutOfBoundsException",
                    f"{begin}, {end}")
            return engine.heap.intern(text[begin:end])
        if name == "equals":
            other = args[0]
            return 1 if isinstance(other, str) and other == text else 0
        if name == "hashCode":
            h = 0
            for ch in text:
                h = (h * 31 + ord(ch)) & 0xFFFFFFFF
            return h - 0x100000000 if h >= 0x80000000 else h
        if name == "indexOf":
            return text.find(jstr(args[0]) if args else "")
        if name == "startsWith":
            return 1 if text.startswith(jstr(args[0])) else 0
        if name == "endsWith":
            return 1 if text.endswith(jstr(args[0])) else 0
        if name == "toUpperCase":
            return engine.heap.intern(text.upper())
        if name == "toLowerCase":
            return engine.heap.intern(text.lower())
        if name == "trim" or name == "strip":
            return engine.heap.intern(text.strip())
        if name == "concat":
            return engine.heap.intern(text + jstr(args[0]))
        if name == "replace":
            return engine.heap.intern(
                text.replace(jstr(args[0]), jstr(args[1])))
        if name == "toString":
            return text
        if name == "compareTo":
            other = jstr(args[0])
            return (text > other) - (text < other)
        if name == "split":
            return Arr("java/lang/String",
                       [engine.heap.intern(part)
                        for part in text.split(jstr(args[0]))])
        if name == "toString":
            return text
        raise Unsupported(f"String.{name} is not modelled")

    def _string_builder(self, name: str, receiver: Obj, args):
        if name == "append":
            receiver.fields["buf"] = receiver.fields.get("buf", "") + \
                _append_text(args[0])
            return receiver
        if name == "toString":
            return receiver.fields.get("buf", "")
        if name == "length":
            return len(receiver.fields.get("buf", ""))
        if name == "charAt":
            buf = receiver.fields.get("buf", "")
            idx = as_int(args[0])
            if not 0 <= idx < len(buf):
                raise JavaThrow("java/lang/StringIndexOutOfBoundsException",
                                str(idx))
            return ord(buf[idx])
        if name == "reverse":
            receiver.fields["buf"] = receiver.fields.get("buf", "")[::-1]
            return receiver
        raise Unsupported(f"StringBuilder.{name} is not modelled")

    # -- boxing / math / system -----------------------------------------

    def _boxing(self, cls: str, name: str, args, heap):
        if name == "parseInt" or name == "parseLong":
            try:
                value = int(jstr(args[0]))
            except ValueError:
                raise JavaThrow("java/lang/NumberFormatException",
                                "For input string: "
                                f"\"{jstr(args[0])}\"") from None
            return value
        if name == "valueOf":
            raw = args[0]
            if isinstance(raw, str):
                try:
                    value = int(raw)
                except ValueError:
                    raise JavaThrow("java/lang/NumberFormatException",
                                    f"For input string: \"{raw}\"") from None
            else:
                value = as_int(raw)
            return Obj(cls, {"value": value})
        if name == "toString":
            return str(as_int(args[0]))
        if name == "compare":
            a, b = as_int(args[0]), as_int(args[1])
            return (a > b) - (a < b)
        raise Unsupported(f"{cls}.{name} is not modelled")

    def _math(self, name: str, args):
        a = args[0] if args else None
        b = args[1] if len(args) > 1 else None
        if name == "abs":
            return abs(a) if isinstance(a, float) else as_int(a) \
                if a >= 0 else -as_int(a)
        if name == "max":
            return a if a >= b else b
        if name == "min":
            return a if a <= b else b
        raise Unsupported(f"Math.{name} is not modelled")

    def _system(self, engine, name: str, args):
        heap = engine.heap
        if name == "arraycopy":
            src, src_pos, dst, dst_pos, length = args
            if not isinstance(src, Arr) or not isinstance(dst, Arr):
                raise Unsupported("arraycopy on non-arrays")
            for k in range(as_int(length)):
                dst.items[as_int(dst_pos) + k] = \
                    src.items[as_int(src_pos) + k]
            return None
        if name in ("currentTimeMillis", "nanoTime"):
            return heap.opaque("clock")
        if name == "identityHashCode":
            return heap.opaque("identityHashCode")
        if name == "getProperty" or name == "getenv":
            return heap.opaque("environment")
        if name == "lineSeparator":
            return heap.intern("\n")
        raise Unsupported(f"System.{name} is not modelled")

    def _objects(self, engine, name: str, args):
        if name == "equals":
            a, b = args[0], args[1]
            if isinstance(a, str) and isinstance(b, str):
                return 1 if a == b else 0
            if isinstance(a, Obj) and isinstance(b, Obj):
                return 1 if a is b else 0
            return 1 if a is b else 0
        if name == "hashCode":
            return engine.heap.opaque("identityHashCode")
        if name == "requireNonNull":
            if args[0] is None:
                raise JavaThrow("java/lang/NullPointerException",
                                "requireNonNull")
            return args[0]
        raise Unsupported(f"Objects.{name} is not modelled")

    # -- files -----------------------------------------------------------

    def _files(self, engine, cls: str, name: str, args, receiver):
        heap = engine.heap
        if cls == "java/nio/file/Paths" and name == "get":
            return Obj("java/nio/file/Path", {"path": jstr(args[0])})
        if cls == "java/nio/file/Files":
            path = _path_text(args[0])
            if name == "exists":
                return 1 if path in heap.vfs else 0
            if name == "notExists":
                return 0 if path in heap.vfs else 1
            if name == "isDirectory":
                return 1 if heap.vfs.get(path) == _DIR else 0
            if name == "isRegularFile":
                return 1 if isinstance(heap.vfs.get(path), (bytes, bytearray)) \
                    else 0
            if name == "size":
                data = heap.vfs.get(path)
                if data is None:
                    raise JavaThrow("java/nio/file/NoSuchFileException", path)
                return len(data)
            if name == "readString" or name == "readAllBytes":
                data = heap.vfs.get(path)
                if data is None:
                    raise JavaThrow("java/nio/file/NoSuchFileException", path)
                if isinstance(data, bytes):
                    return data.decode("utf-8") if name == "readString" else data
                raise JavaThrow("java/io/IOException", "is a directory")
            if name == "writeString":
                heap.vfs[path] = jstr(args[1]).encode("utf-8")
                return path
            if name == "createDirectories" or name == "createDirectory":
                heap.vfs[path] = _DIR
                return path
            if name == "deleteIfExists":
                return 1 if heap.vfs.pop(path, None) is not None else 0
            if name == "delete":
                if heap.vfs.pop(path, None) is None:
                    raise JavaThrow("java/nio/file/NoSuchFileException", path)
                return None
            if name == "move" or name == "copy":
                data = heap.vfs.get(path)
                if data is None:
                    raise JavaThrow("java/nio/file/NoSuchFileException", path)
                heap.vfs[_path_text(args[1])] = data
                if name == "move":
                    heap.vfs.pop(path, None)
                return args[1]
        if cls == "java/nio/file/Path" and isinstance(receiver, Obj):
            base = receiver.fields.get("path", "")
            if name == "resolve":
                return Obj("java/nio/file/Path",
                           {"path": base.rstrip("/") + "/" + jstr(args[0])})
            if name == "getParent":
                return Obj("java/nio/file/Path",
                           {"path": base.rsplit("/", 1)[0] or "/"})
            if name == "toString":
                return receiver.fields.get("path", "")
            if name == "getFileName":
                text = receiver.fields.get("path", "")
                return Obj("java/nio/file/Path",
                           {"path": text.rsplit("/", 1)[-1]})
        raise Unsupported(f"{cls}.{name} is not modelled")

    # -- threads ---------------------------------------------------------

    def _thread(self, engine, name: str, receiver, args):
        if name == "start" and isinstance(receiver, Obj):
            target = receiver.fields.get("target")
            if isinstance(target, Obj):
                engine._call(target.cls, "run", "()V", target, [],
                             exact=False)
                return None
            return engine.heap.opaque("thread-without-modelled-body")
        if name == "run":
            return None
        if name in ("join", "sleep", "yield", "interrupt", "currentThread"):
            return None
        raise Unsupported(f"Thread.{name} is not modelled")

    # -- collections -----------------------------------------------------

    def _collections(self, engine, cls: str, name: str, receiver: Obj, args):
        if cls.endswith("ArrayList") or cls.endswith("LinkedHashSet"):
            items = receiver.fields.setdefault("items", [])
            if name == "add":
                items.append(args[0]); return 1
            if name == "get":
                idx = as_int(args[0])
                if not 0 <= idx < len(items):
                    raise JavaThrow("java/lang/IndexOutOfBoundsException",
                                    f"Index {idx}, length {len(items)}")
                return items[idx]
            if name == "size":
                return len(items)
            if name == "isEmpty":
                return 1 if not items else 0
            if name == "contains":
                needle = args[0]
                return 1 if any(_value_equal(x, needle) for x in items) else 0
            if name == "set":
                idx = as_int(args[0])
                old = items[idx]; items[idx] = args[1]; return old
        if cls.endswith("HashMap") or cls.endswith("TreeMap"):
            entries = receiver.fields.setdefault("entries", {})
            key = jstr(args[0]) if args else ""
            if name == "put":
                old = entries.get(key); entries[key] = args[1]; return old
            if name == "get":
                return entries.get(key)
            if name == "containsKey":
                return 1 if key in entries else 0
            if name == "size":
                return len(entries)
        raise Unsupported(f"{cls}.{name} is not modelled")


def _value_equal(a, b) -> bool:
    if isinstance(a, str) and isinstance(b, str):
        return a == b
    if isinstance(a, Obj) and isinstance(b, Obj):
        return a is b
    return a is b


def _to_text(obj: Obj) -> str:
    return f"{obj.cls}@model"


def _path_text(arg) -> str:
    if isinstance(arg, Obj):
        return arg.fields.get("path", "")
    return jstr(arg)
