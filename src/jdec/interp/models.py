"""Deterministic models for the world outside the method.

A model is *not* an attempt to reimplement the JDK: it exists so that both
sides of a differential run see the same deterministic world, and so that the
run never touches the real filesystem, network, clock or threads. Anything the
table does not cover is an `Opaque` value, and the engine turns any outcome
that depends on one into `inconclusive`.
"""

from __future__ import annotations

import math

from .values import (Arr, JavaThrow, Obj, Unsupported, _append_text,
                     _to_text, as_int, jstr,
                     make_model)

_DIR = "dir"

#: methods of the common functional interfaces (java/util/function and
#: java/lang/Runnable et al.) that a lambda instance may be invoked through
_SAM_METHODS = {"run", "get", "accept", "test", "apply", "compare", "call",
                "getAsInt", "getAsLong", "getAsDouble", "getAsBoolean"}


def _f2i_clamp(v: float, lo: int, hi: int) -> int:
    if v != v:
        return 0
    if v >= hi:
        return hi
    if v <= lo:
        return lo
    return int(v)


class Models:
    def invoke(self, engine, cls: str, name: str, desc: str,
               receiver, args: list):
        """Return (handled, value). May raise JavaThrow / Unsupported."""
        heap = engine.heap
        if name == "<init>" and isinstance(receiver, Obj):
            base = make_model(cls, heap)
            if base is not None:
                receiver.fields = dict(base.fields)
                receiver.cls = cls
                if cls in ("java/lang/StringBuilder",
                           "java/lang/StringBuffer") and args \
                        and isinstance(args[0], str):
                    receiver.fields["buf"] = args[0]
                return True, None
            if cls == "java/lang/Thread":
                receiver.fields = {"target": args[0] if args else None}
                return True, None
            if cls == "java/util/StringTokenizer":
                receiver.fields = {"text": jstr(args[0]),
                                   "delim": jstr(args[1]) if len(args) > 1
                                   else None, "pos": 0}
                return True, None
            if cls == "java/lang/String":
                # `new String(x)` must end up as a real str, not a hollow Obj:
                # every later String.* dispatch keys off isinstance(str)
                if args and isinstance(args[0], Arr) \
                        and args[0].component == "C":
                    return True, engine.heap.intern(
                        "".join(chr(as_int(c)) for c in args[0].items))
                return True, engine.heap.intern(
                    _append_text(args[0]) if args else "")
            # an unmodelled constructor is a no-op: both sides see the same
            # default state, which is all the differential run needs
            return True, None
        # functional-interface dispatch: a lambda produced by `_lambda_site`
        # carries its implementation in `_jdec_*` fields
        if isinstance(receiver, Obj) and "_jdec_method" in receiver.fields \
                and name in _SAM_METHODS:
            return True, self._sam(engine, receiver, args)


        # unboxing accessors on boxed values: `Integer.intValue()` and friends
        # are everywhere and the value is already in the model
        if name in ("intValue", "longValue", "doubleValue", "floatValue",
                    "shortValue", "byteValue", "charValue", "booleanValue") \
                and isinstance(receiver, Obj) and "value" in receiver.fields:
            return True, receiver.fields["value"]
        if cls == "java/lang/String" and receiver is None \
                and name == "valueOf":
            return True, _append_text(args[0])

        if cls == "java/lang/String" and isinstance(receiver, str):
            return True, self._string(name, receiver, args, engine, desc)
        if cls == "java/lang/String" and receiver is None:
            if name == "valueOf":
                if desc == "(C)Ljava/lang/String;":
                    return True, chr(as_int(args[0]))
                if len(args) == 1 and isinstance(args[0], Arr) \
                        and args[0].component == "C":
                    return True, "".join(chr(as_int(c))
                                         for c in args[0].items)
                return True, _append_text(args[0])
            if name == "join":
                raise Unsupported("String.join is not modelled")
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
        if cls in ("java/io/BufferedReader", "java/io/BufferedWriter",
                   "java/io/InputStreamReader", "java/io/OutputStreamWriter"):
            return True, self._buffered(engine, cls, name, receiver, args)
        if cls.startswith("java/net/") or cls in ("java/io/InputStream",
                                                  "java/io/OutputStream"):
            raise JavaThrow("java/net/ConnectException", "Connection refused")
        if cls == "java/lang/Thread" or cls == "java/lang/Runnable":
            return True, self._thread(engine, name, receiver, args)
        if cls == "java/util/Arrays" and receiver is None:
            if name == "asList":
                arr = args[0]
                if isinstance(arr, Arr):
                    return True, Obj("java/util/ArrayList",
                                     {"items": list(arr.items)})
            if name == "stream":
                arr = args[0]
                return True, Obj("java/util/stream/Stream",
                                 {"items": list(arr.items)
                                  if isinstance(arr, Arr) else []})
        if cls in ("java/util/stream/IntStream", "java/util/stream/LongStream",
                   "java/util/stream/DoubleStream") and receiver is None:
            if name == "of":
                arr = args[0]
                return True, Obj("java/util/stream/Stream",
                                 {"items": list(arr.items)
                                  if isinstance(arr, Arr) else []})
            if name == "range":
                lo, hi = as_int(args[0]), as_int(args[1])
                return True, Obj("java/util/stream/Stream",
                                 {"items": list(range(lo, hi))})
        if cls.startswith("java/util/stream/Stream") \
                or cls.startswith("java/util/stream/IntStream") \
                or cls.startswith("java/util/stream/LongStream") \
                or cls.startswith("java/util/stream/DoubleStream"):
            return True, self._stream(engine, cls, name, receiver, args)
        if cls == "java/util/Optional" and (
                receiver is None or isinstance(receiver, Obj)):
            return True, self._optional(engine, cls, name, receiver, args)
        if cls == "java/util/stream/Collectors" and receiver is None:
            if name == "toList":
                return True, Obj("java/util/stream/Collectors",
                                 {"_jdec_collector": "toList"})
            if name == "toSet":
                return True, Obj("java/util/stream/Collectors",
                                 {"_jdec_collector": "toSet"})
            if name == "counting":
                return True, Obj("java/util/stream/Collectors",
                                 {"_jdec_collector": "counting"})
            if name == "joining":
                return True, Obj("java/util/stream/Collectors",
                                 {"_jdec_collector": "joining",
                                  "sep": jstr(args[0]) if args else ""})
            raise Unsupported(f"Collectors.{name} is not modelled")
        if cls.startswith("java/util/regex/"):
            return True, self._regex(engine, cls, name, receiver, args)
        if cls.startswith("java/util/") and isinstance(receiver, Obj):
            return True, self._collections(engine, cls, name, receiver, args)
        if cls == "java/lang/Class" and isinstance(receiver, Obj):
            return True, (receiver.fields.get("name") if name == "getName"
                          else None) or False
        return False, None

    # -- strings ---------------------------------------------------------

    def _string(self, name: str, text: str, args, engine, desc: str = ""):
        if name == "length":
            return len(text)
        if name == "isEmpty":
            return 1 if not text else 0
        if name == "isBlank":
            return 1 if not text.strip() else 0
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
            if args and isinstance(args[0], int):
                return text.find(chr(as_int(args[0])))   # indexOf(char)
            return text.find(jstr(args[0]) if args else "")
        if name == "lastIndexOf":
            if args and isinstance(args[0], int):
                return text.rfind(chr(as_int(args[0])))
            return text.rfind(jstr(args[0]) if args else "")
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
            if len(args) == 2 and all(isinstance(a, int) for a in args):
                # the (char, char) overload
                return engine.heap.intern(
                    text.replace(chr(as_int(args[0])), chr(as_int(args[1]))))
            return engine.heap.intern(
                text.replace(jstr(args[0]), jstr(args[1])))
        if name == "toString":
            return text
        if name == "compareTo":
            other = jstr(args[0])
            return (text > other) - (text < other)
        if name == "equalsIgnoreCase":
            other = args[0]
            return 1 if isinstance(other, str) and other.lower() == text.lower() \
                else 0
        if name == "contains":
            return 1 if jstr(args[0]) in text else 0
        if name == "matches":
            return 1 if self._compile_py(jstr(args[0])).fullmatch(text) \
                else 0
        if name == "codePointAt":
            idx = as_int(args[0])
            if not 0 <= idx < len(text):
                raise JavaThrow("java/lang/StringIndexOutOfBoundsException",
                                str(idx))
            return ord(text[idx])
        if name == "split":
            return Arr("java/lang/String",
                       [engine.heap.intern(part)
                        for part in text.split(jstr(args[0]))])
        if name == "repeat":
            return engine.heap.intern(text * as_int(args[0]))
        if name == "chars":
            raise Unsupported("String.chars is not modelled")
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
        if name == "parseBoolean":
            text = jstr(args[0]).lower()
            if text == "true":
                return 1
            if text == "false":
                return 0
            raise JavaThrow("java/lang/NumberFormatException",
                            f"For input string: \"{jstr(args[0])}\"")
        if name == "parseByte" or name == "parseShort":
            try:
                return int(jstr(args[0]))
            except ValueError:
                raise JavaThrow("java/lang/NumberFormatException",
                                f"For input string: \"{jstr(args[0])}\"") \
                from None
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
        if name == "sum" and cls in ("java/lang/Integer", "java/lang/Long"):
            return as_int(args[0]) + as_int(args[1])
        if name == "compare":
            a, b = as_int(args[0]), as_int(args[1])
            return (a > b) - (a < b)
        raise Unsupported(f"{cls}.{name} is not modelled")

    def _math(self, name: str, args):
        a = args[0] if args else None
        b = args[1] if len(args) > 1 else None
        if name == "abs":
            if isinstance(a, float):
                return abs(a)
            v = as_int(a)
            return v if v >= 0 else -v
        if name == "max":
            return a if a >= b else b
        if name == "min":
            return a if a <= b else b
        if name == "floor":
            return float(math.floor(a)) if math.isfinite(a) else a
        if name == "ceil":
            return float(math.ceil(a)) if math.isfinite(a) else a
        if name == "sqrt":
            if a < 0:
                return float("nan")
            return math.sqrt(a)
        if name == "pow":
            try:
                r = math.pow(a, b)
            except (ValueError, OverflowError):
                return float("nan") if a < 0 else \
                    (float("inf") if a > 0 else float("nan"))
            return r
        if name == "round":
            if isinstance(a, float):
                return _f2i_clamp(math.floor(a + 0.5), -0x80000000,
                                  0x7FFFFFFF)
            return a
        if name == "signum":
            if isinstance(a, float):
                return math.copysign(1.0, a) if a != 0 else a
            return 0 if a == 0 else (1 if a > 0 else -1)
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
            if name == "readAllLines":
                data = heap.vfs.get(path)
                if data is None:
                    raise JavaThrow("java/nio/file/NoSuchFileException", path)
                text = data.decode("utf-8") if isinstance(data, bytes) else ""
                return Arr("java/lang/String",
                           [heap.intern(line)
                            for line in text.splitlines() or [""]])
            if name == "newInputStream":
                data = heap.vfs.get(path)
                if data is None:
                    raise JavaThrow("java/nio/file/NoSuchFileException", path)
                if not isinstance(data, bytes):
                    raise JavaThrow("java/io/IOException",
                                    "is a directory: " + path)
                return Obj("java/io/BufferedReader",
                           {"text": data.decode("utf-8", "replace"), "pos": 0})
            if name == "newBufferedReader":
                data = heap.vfs.get(path)
                if data is None:
                    raise JavaThrow("java/nio/file/NoSuchFileException", path)
                if not isinstance(data, bytes):
                    raise JavaThrow("java/io/IOException",
                                    "is a directory: " + path)
                return Obj("java/io/BufferedReader",
                           {"text": data.decode("utf-8"), "pos": 0})
            if name == "newBufferedWriter":
                if path not in heap.vfs and \
                        not any(k.startswith(path) for k in heap.vfs):
                    parent = path.rsplit("/", 1)[0]
                    if parent and parent not in heap.vfs:
                        raise JavaThrow("java/nio/file/NoSuchFileException",
                                        parent)
                return Obj("java/io/BufferedWriter",
                           {"path": path, "lines": []})
            if name == "newDirectoryStream":
                if path not in heap.vfs:
                    raise JavaThrow("java/nio/file/NoSuchFileException", path)
                if heap.vfs[path] != _DIR:
                    raise JavaThrow("java/io/IOException",
                                    "not a directory: " + path)
                prefix = path.rstrip("/") + "/"
                children = [Obj("java/nio/file/Path", {"path": k})
                            for k in heap.vfs if k.startswith(prefix)]
                return Obj("java/nio/file/DirectoryStream",
                           {"items": children})
            if name == "list" or name == "walk":
                if path not in heap.vfs:
                    raise JavaThrow("java/nio/file/NoSuchFileException", path)
                if heap.vfs[path] != _DIR:
                    raise JavaThrow("java/io/IOException",
                                    "not a directory: " + path)
                prefix = path.rstrip("/") + "/"
                found = []
                for k in heap.vfs:
                    if not k.startswith(prefix):
                        continue
                    found.append(Obj("java/nio/file/Path", {"path": k}))
                    if name == "walk" and heap.vfs[k] == _DIR:
                        # one nesting level is enough for a differential run:
                        # deeper trees would need recursive VFS expansion
                        inner = k + "/"
                        found.extend(Obj("java/nio/file/Path", {"path": n})
                                     for n in heap.vfs
                                     if n.startswith(inner))
                found.sort(key=lambda p: p.fields["path"])
                return Obj("java/util/stream/Stream", {"items": found})
            if name == "readAttributes" or name == "readBasicFileAttributes":
                data = heap.vfs.get(path)
                if data is None:
                    raise JavaThrow("java/nio/file/NoSuchFileException", path)
                return Obj("java/nio/file/attribute/BasicFileAttributes",
                           {"size": len(data) if isinstance(data, bytes) else 0,
                            "isDirectory": 1 if data == _DIR else 0,
                            "isRegularFile": 1 if isinstance(data, bytes)
                            else 0})
            if name == "getAttribute":
                data = heap.vfs.get(path)
                if data is None:
                    raise JavaThrow("java/nio/file/NoSuchFileException", path)
                attr = jstr(args[1]) if len(args) > 1 else "size"
                if attr.endswith("size"):
                    return len(data) if isinstance(data, bytes) else 0
                if attr.endswith("isDirectory"):
                    return 1 if data == _DIR else 0
                if attr.endswith("isRegularFile"):
                    return 1 if isinstance(data, bytes) else 0
                return 0
            if name == "getLastModifiedTime":
                if path not in heap.vfs:
                    raise JavaThrow("java/nio/file/NoSuchFileException", path)
                return Obj("java/nio/file/attribute/FileTime",
                           {"millis": 0})
            if name == "isSymbolicLink" or name == "isHidden":
                return 0
            if name == "createTempDirectory" or name == "createTempFile":
                base = "/tmp/jdec-temp"
                n = heap.temp_counter
                heap.temp_counter = n + 1
                full = (f"{base}{n}" if name == "createTempDirectory"
                        else f"{base}{n}.tmp")
                heap.vfs[full] = _DIR if name == "createTempDirectory" \
                    else b""
                return Obj("java/nio/file/Path", {"path": full})
            if name == "walk" or name == "list" or name == "find" \
                    or name == "walkFileTree":
                raise Unsupported(f"Files.{name} is not modelled")
        if cls == "java/lang/Iterable" and isinstance(receiver, Obj) \
                and name == "iterator":
            return Obj("java/util/Iterator",
                       {"items": list(receiver.fields.get("items", [])),
                        "pos": 0})
        if cls == "java/nio/file/Path" and isinstance(receiver, Obj):
            base = receiver.fields.get("path", "")
            if name == "resolve":
                return Obj("java/nio/file/Path",
                           {"path": base.rstrip("/") + "/" + jstr(args[0])})
            if name == "resolveSibling":
                return Obj("java/nio/file/Path",
                           {"path": base.rsplit("/", 1)[0] + "/" + jstr(args[0])})
            if name == "toAbsolutePath":
                absolute = base if base.startswith("/") else "/case/" + base
                return Obj("java/nio/file/Path", {"path": absolute})
            if name == "normalize":
                parts = []
                for seg in base.split("/"):
                    if seg == ".." and parts and parts[-1] not in ("", ".."):
                        parts.pop()
                    elif seg not in (".", ""):
                        parts.append(seg)
                return Obj("java/nio/file/Path",
                           {"path": "/" + "/".join(parts)})
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

    def _sam(self, engine, receiver: Obj, args):
        """Run a lambda/method-reference instance synchronously.

        The instance was built by `_lambda_site`: `_jdec_kind` 6 means a
        static impl taking `captured + sam args`; 5/7 means an instance
        method whose receiver is captured[0] — or, when nothing was captured,
        the SAM call's first argument (`String::length`).
        """
        captured = list(receiver.fields.get("_jdec_captured") or [])
        kind = receiver.fields.get("_jdec_kind", 6)
        recv = receiver.fields.get("_jdec_ref")
        if kind in (5, 7) and recv is None:
            if not args:
                raise Unsupported("method reference with no receiver")
            recv, call_args = args[0], list(args[1:])
        else:
            call_args = captured + list(args)
        return engine._call(receiver.fields["_jdec_cls"],
                            receiver.fields["_jdec_method"],
                            receiver.fields.get("_jdec_desc", "()V"),
                            recv, call_args, exact=True)

    # -- streams / optional ----------------------------------------------

    def _stream(self, engine, cls: str, name: str, receiver: Obj, args):
        """A deterministic pipeline over an ordered item list.

        Both sides run this exact model, so only determinism matters — but a
        pipeline stage whose lambda is an Opaque still taints the result
        through the normal `_call` path, which is the discipline that keeps
        `same` meaningful.
        """
        if receiver is None:
            raise Unsupported("stream factory dispatch is handled in invoke")
        items = receiver.fields.setdefault("items", [])

        def call_fn(fn, xs):
            if not (isinstance(fn, Obj) and "_jdec_method" in fn.fields):
                raise Unsupported("pipeline stage without a modelled lambda")
            return self._sam(engine, fn, list(xs))

        def call1(fn, x):
            return call_fn(fn, [x])

        def is_fn(v):
            return isinstance(v, Obj) and "_jdec_method" in v.fields

        def as_stream(xs):
            return Obj("java/util/stream/Stream", {"items": list(xs)})

        if name == "filter":
            pred = args[0]
            if not is_fn(pred):
                raise Unsupported("filter without a lambda is not modelled")
            out = [x for x in items if as_int(call1(pred, x)) != 0]
            return as_stream(out)
        if name == "map":
            fn = args[0]
            return as_stream([call1(fn, x) for x in items])
        if name == "flatMap":
            fn = args[0]
            out = []
            for x in items:
                r = call1(fn, x)
                if isinstance(r, Obj) and "items" in r.fields:
                    out.extend(r.fields["items"])
                elif isinstance(r, Arr):
                    out.extend(r.items)
                else:
                    raise Unsupported("flatMap must produce a stream/array")
            return as_stream(out)
        if name == "limit":
            return as_stream(items[:max(0, as_int(args[0]))])
        if name == "skip":
            return as_stream(items[max(0, as_int(args[0])):])
        if name == "peek":
            for x in items:
                if is_fn(args[0]):
                    call1(args[0], x)
            return receiver
        if name == "distinct":
            out = []
            for x in items:
                if not any(_value_equal(x, y) for y in out):
                    out.append(x)
            return as_stream(out)
        if name == "sorted":
            def key_text(v):
                return _append_text(v)
            return as_stream(sorted(items, key=key_text))
        if name == "forEach" or name == "forEachOrdered":
            for x in items:
                if is_fn(args[0]):
                    call1(args[0], x)
            return None
        if name == "count":
            return len(items)
        if name == "findFirst":
            return Obj("java/util/Optional",
                       {"value": items[0] if items else None})
        if name in ("anyMatch", "allMatch", "noneMatch"):
            pred = args[0]
            flags = [as_int(call1(pred, x)) != 0 for x in items] \
                if is_fn(pred) else [False] * len(items)
            if name == "anyMatch":
                return 1 if any(flags) else 0
            if name == "allMatch":
                return 1 if all(flags) else 0
            return 1 if not any(flags) else 0
        if name == "collect":
            coll = args[0]
            op = coll.fields.get("_jdec_collector", "toList") \
                if isinstance(coll, Obj) else "toList"
            if op == "toList":
                return Obj("java/util/ArrayList", {"items": list(items)})
            if op == "toSet":
                out = []
                for x in items:
                    if not any(_value_equal(x, y) for y in out):
                        out.append(x)
                return Obj("java/util/LinkedHashSet", {"items": out})
            if op == "joining":
                sep = coll.fields.get("sep", "")
                return engine.heap.intern(
                    sep.join(_append_text(x) for x in items))
            if op == "counting":
                return len(items)
            raise Unsupported(f"Collectors.{op} is not modelled")
        if name == "toArray":
            return Arr("java/lang/Object", list(items))
        if name == "sum" or name == "average":
            nums = [as_int(x) for x in items]
            if name == "sum":
                return sum(nums)
            return sum(nums) / len(nums) if nums else 0.0
        if name == "reduce":
            # reduce(identity, accumulator)
            acc = args[0]
            fn = args[1] if len(args) > 1 else None
            if not is_fn(fn):
                raise Unsupported("reduce without an accumulator lambda")
            for x in items:
                acc = call_fn(fn, [acc, x])
            # `Stream<T>.reduce` returns a boxed T: the caller's bytecode
            # follows with `intValue()`, which needs a receiver with `value`
            if not isinstance(acc, Obj):
                return Obj("java/lang/Integer", {"value": acc})
            return acc
        raise Unsupported(f"{cls}.{name} is not modelled")

    def _optional(self, engine, cls: str, name: str, receiver, args):
        if receiver is None:                        # static factories
            if name == "of" or name == "ofNullable":
                return Obj("java/util/Optional", {"value": args[0]})
            if name == "empty":
                return Obj("java/util/Optional", {"value": None})
            raise Unsupported(f"Optional.{name} is not modelled")
        if not isinstance(receiver, Obj):
            # the receiver came out of an unmodelled call: the taint rule
            # handles it upstream, here it just must not crash the engine
            raise Unsupported("Optional receiver depends on an unmodelled "
                              "call")
        value = receiver.fields.get("value")
        if name == "isPresent" or name == "nonEmpty":
            return 0 if value is None else 1
        if name == "isEmpty":
            return 1 if value is None else 0
        if name == "get":
            if value is None:
                raise JavaThrow("java/util/NoSuchElementException",
                                "No value present")
            return value
        if name == "orElse" or name == "orElseGet":
            return value if value is not None else args[0]
        if name == "ifPresent":
            if value is None:
                return None
            fn = args[0]
            if isinstance(fn, Obj) and "_jdec_method" in fn.fields:
                self._sam(engine, fn, [value])
            return None
        if name == "map":
            if value is None:
                return Obj("java/util/Optional", {"value": None})
            fn = args[0]
            return Obj("java/util/Optional",
                       {"value": self._sam(engine, fn, [value])})
        raise Unsupported(f"Optional.{name} is not modelled")

    # -- regex -----------------------------------------------------------

    # Java-only syntax -> Python re. Anything not in this table stays
    # Unsupported: a guessed translation could turn into a wrong verdict.
    _JAVA_CHAR_CLASSES = {
        "XDigit": "[0-9a-fA-F]", "Alpha": "[a-zA-Z]", "Alnum": "[a-zA-Z0-9]",
        "Digit": "[0-9]", "Lower": "[a-z]", "Upper": "[A-Z]",
        "Space": "\\s", "Blank": "[ \\t]", "Punct": "[!-/:-@\\[-`{-~]",
    }

    @classmethod
    def _translate_regex(cls, java: str) -> str:
        import re as _re
        out = _re.sub(r"(?<![?<])\(\?<([A-Za-z][A-Za-z0-9_]*)>",
                      r"(?P<\1>", java)
        for name, repl in cls._JAVA_CHAR_CLASSES.items():
            out = out.replace(f"\\p{{{name}}}", repl)
            out = out.replace(f"\\P{{{name}}}", f"[^{repl[1:-1]}]")
        out = out.replace("\\R", "(?:\\r\\n|\\r|\\n)")
        if _re.search(r"[?*+{]\+", out):        # possessive quantifiers
            raise Unsupported("possessive quantifier is not translatable")
        if "&&" in out:                          # class intersection
            raise Unsupported("character-class intersection is not "
                              "translatable")
        if "\\p{" in out or "\\P{" in out:       # any other Unicode class
            raise Unsupported("unicode class is not translatable")
        return out

    def _compile_py(self, java_pattern: str):
        import re as _re
        text = self._translate_regex(java_pattern)
        try:
            return _re.compile(text)
        except _re.error:
            raise Unsupported("pattern not translatable to Python re") \
                from None

    def _regex(self, engine, cls: str, name: str, receiver, args):
        """A thin, deterministic bridge to Python's `re`.

        Both sides run the same bridge, so only determinism is required — but
        a pattern Python cannot compile is `Unsupported`, never a guessed
        answer, so exotic Java-only syntax stays inconclusive instead of
        turning into a wrong verdict.
        """
        if cls == "java/util/regex/Pattern" and receiver is None:
            if name == "compile":
                self._compile_py(jstr(args[0]))
                return Obj("java/util/regex/Pattern",
                           {"regex": jstr(args[0])})
            if name == "matches":
                pat, text = jstr(args[0]), jstr(args[1])
                return 1 if self._compile_py(pat).fullmatch(text) else 0
        if cls == "java/util/regex/Pattern" and isinstance(receiver, Obj):
            regex = receiver.fields.get("regex", "")
            if name == "matcher":
                return Obj("java/util/regex/Matcher",
                           {"regex": regex, "text": jstr(args[0]), "pos": 0,
                            "groups": None})
            if name == "pattern":
                return receiver
            if name == "split":
                parts = self._compile_py(regex).split(jstr(args[0]))
                return Arr("java/lang/String",
                           [engine.heap.intern(p) for p in parts])
        if cls == "java/util/regex/Matcher" and isinstance(receiver, Obj):
            regex = receiver.fields.get("regex", "")
            text = receiver.fields.get("text", "")
            compiled = self._compile_py(regex)
            if name == "matches":
                m = compiled.fullmatch(text)
                receiver.fields["groups"] = m.groups() if m else None
                receiver.fields["matched"] = m.group(0) if m else ""
                return 1 if m else 0
            if name == "find":
                pos = receiver.fields.get("pos", 0)
                m = compiled.search(text, pos)
                if m:
                    receiver.fields["groups"] = m.groups()
                    receiver.fields["matched"] = m.group(0)
                    receiver.fields["pos"] = m.end()
                    return 1
                return 0
            if name == "group":
                groups = receiver.fields.get("groups")
                if groups is None:
                    raise JavaThrow("java/lang/IllegalStateException",
                                    "no match available")
                if not args or as_int(args[0]) == 0:
                    return engine.heap.intern(
                        receiver.fields.get("matched", "") or "")
                idx = as_int(args[0])
                value = groups[idx - 1] if idx <= len(groups) else None
                return value if value is None else engine.heap.intern(value)
            if name == "groupCount":
                return compiled.groups
            if name == "replaceAll":
                return engine.heap.intern(
                    compiled.sub(jstr(args[0]), text))
            if name == "reset":
                receiver.fields["pos"] = 0
                return receiver
            if name == "lookingAt":
                return 1 if compiled.match(text) else 0
        raise Unsupported(f"{cls}.{name} is not modelled")

    # -- buffered IO -----------------------------------------------------

    def _buffered(self, engine, cls: str, name: str, receiver, args):
        heap = engine.heap
        if name == "newBufferedReader":
            # called as Files.newBufferedReader — handled in _files, but the
            # class check lands here when dispatched by prefix
            raise Unsupported("newBufferedReader is dispatched in _files")
        if isinstance(receiver, Obj) and "text" in receiver.fields:
            text = receiver.fields["text"]
            pos = receiver.fields.setdefault("pos", 0)
            if name == "readLine":
                if pos >= len(text):
                    return None
                end = text.find("\n", pos)
                if end < 0:
                    receiver.fields["pos"] = len(text)
                    return engine.heap.intern(text[pos:])
                receiver.fields["pos"] = end + 1
                return engine.heap.intern(text[pos:end])
            if name == "close" or name == "flush":
                return None
        if isinstance(receiver, Obj) and "path" in receiver.fields \
                and name == "write":
            lines = receiver.fields.setdefault("lines", [])
            lines.append(_append_text(args[0]))
            return receiver
        if isinstance(receiver, Obj) and "path" in receiver.fields \
                and name == "close":
            data = "\n".join(receiver.fields.get("lines", []))
            heap.vfs[receiver.fields["path"]] = data.encode("utf-8")
            return None
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
        if name == "currentThread":
            return Obj("java/lang/Thread", {})
        if name in ("join", "sleep", "yield", "interrupt"):
            return None
        raise Unsupported(f"Thread.{name} is not modelled")

    # -- collections -----------------------------------------------------

    # Interface names map onto the model implementation so that a receiver
    # built from a descriptor (`Ljava/util/Map;` -> a bare Obj) still works.
    _MAP_TYPES = ("java/util/Map", "java/util/HashMap",
                  "java/util/LinkedHashMap", "java/util/TreeMap")
    _LIST_TYPES = ("java/util/List", "java/util/Collection",
                   "java/util/ArrayList", "java/util/LinkedList")
    _SET_TYPES = ("java/util/Set", "java/util/HashSet",
                  "java/util/LinkedHashSet", "java/util/TreeSet")

    def _collections(self, engine, cls: str, name: str, receiver: Obj, args):
        if cls in self._LIST_TYPES or cls.endswith("ArrayList") \
                or cls.endswith("LinkedHashSet"):
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
                return 1 if any(_value_equal(x, needle) for x in items) \
                    else 0
            if name == "set":
                idx = as_int(args[0])
                old = items[idx]; items[idx] = args[1]; return old
            if name == "iterator":
                return Obj("java/util/Iterator",
                           {"items": list(items), "pos": 0})
            if name == "stream":
                return Obj("java/util/stream/Stream", {"items": list(items)})
            if name == "toArray":
                if args and isinstance(args[0], Arr):
                    out = Arr(args[0].component, list(items))
                    return out
                return Arr("java/lang/Object", list(items))
            if name == "toString":
                return "[" + ", ".join(_append_text(x) for x in items) + "]"
        if cls in self._MAP_TYPES or cls.endswith("HashMap") \
                or cls.endswith("TreeMap"):
            entries = receiver.fields.setdefault("entries", {})
            key = jstr(args[0]) if args else ""
            if name == "put":
                old = entries.get(key); entries[key] = args[1]; return old
            if name == "get":
                return entries.get(key)
            if name == "getOrDefault":
                return entries.get(key, args[1])
            if name == "containsKey":
                return 1 if key in entries else 0
            if name == "containsValue":
                return 1 if any(_value_equal(v, args[0])
                                for v in entries.values()) else 0
            if name == "size":
                return len(entries)
            if name == "isEmpty":
                return 1 if not entries else 0
            if name == "keySet":
                return Obj("java/util/LinkedHashSet",
                           {"items": list(entries.keys())})
            if name == "values":
                return Obj("java/util/ArrayList",
                           {"items": list(entries.values())})
            if name == "entrySet":
                return Obj("java/util/LinkedHashSet",
                           {"items": [Obj("java/util/HashMap$Node",
                                          {"key": k, "value": v})
                                      for k, v in entries.items()]})
            if name == "remove":
                return entries.pop(key, None)
        if cls in self._SET_TYPES or cls.endswith("HashSet") \
                or cls.endswith("TreeSet"):
            items = receiver.fields.setdefault("items", [])
            if name == "add":
                if any(_value_equal(x, args[0]) for x in items):
                    return 0
                items.append(args[0]); return 1
            if name == "contains":
                return 1 if any(_value_equal(x, args[0]) for x in items) else 0
            if name == "size":
                return len(items)
            if name == "isEmpty":
                return 1 if not items else 0
            if name == "iterator":
                return Obj("java/util/Iterator",
                           {"items": list(items), "pos": 0})
        if cls == "java/util/Iterator" and isinstance(receiver, Obj):
            items = receiver.fields.setdefault("items", [])
            pos = receiver.fields.setdefault("pos", 0)
            if name == "hasNext":
                return 1 if pos < len(items) else 0
            if name == "next":
                if pos >= len(items):
                    raise JavaThrow("java/util/NoSuchElementException",
                                    "iterator exhausted")
                receiver.fields["pos"] = pos + 1
                return items[pos]
        if cls.endswith("$Node") or cls.endswith("Entry"):
            if name == "getKey":
                return receiver.fields.get("key")
            if name == "getValue":
                return receiver.fields.get("value")
        if cls == "java/lang/Iterable" and name == "iterator" \
                and isinstance(receiver, Obj):
            return self._collections(engine, receiver.cls, "iterator",
                                     receiver, args)
        if cls.endswith("BlockingQueue") or cls.endswith("ArrayBlockingQueue"):
            items = receiver.fields.setdefault("items", [])
            if name in ("add", "put", "offer"):
                items.append(args[0])
                return 1 if name != "put" else None
            if name == "take" or name == "poll" or name == "remove":
                if not items:
                    if name == "take":
                        # a blocking queue with no producer is a deadlock in
                        # synchronous execution — deterministic both sides
                        raise Unsupported("take from an empty queue blocks")
                    return None
                return items.pop(0)
            if name == "peek":
                return items[0] if items else None
            if name == "size":
                return len(items)
            if name == "isEmpty":
                return 1 if not items else 0
        if cls.endswith("Deque") or cls == "java/util/Queue" \
                or cls.endswith("ArrayDeque"):
            items = receiver.fields.setdefault("items", [])
            if name == "push" or name == "addFirst":
                items.insert(0, args[0]); return None
            if name == "addLast" or name == "add" or name == "offer":
                items.append(args[0]); return 1
            if name == "pop" or name == "poll" or name == "removeFirst":
                if not items:
                    return None if name in ("pop", "poll") else \
                        (_ for _ in ()).throw(
                            JavaThrow("java/util/NoSuchElementException",
                                      "deque empty"))
                return items.pop(0)
            if name == "peek" or name == "peekFirst":
                return items[0] if items else None
            if name == "isEmpty":
                return 1 if not items else 0
            if name == "size":
                return len(items)
            if name == "iterator":
                return Obj("java/util/Iterator",
                           {"items": list(items), "pos": 0})
        if cls == "java/util/StringTokenizer" and isinstance(receiver, Obj):
            tokens = receiver.fields.setdefault("tokens", None)
            if tokens is None:
                text = receiver.fields.get("text", "")
                sep = receiver.fields.get("delim") or " "
                tokens = receiver.fields["tokens"] = text.split(sep)
            if name == "hasMoreTokens" or name == "hasMoreElements":
                return 1 if receiver.fields.get("pos", 0) < len(tokens) else 0
            if name == "nextToken" or name == "nextElement":
                pos = receiver.fields.get("pos", 0)
                if pos >= len(tokens):
                    raise JavaThrow("java/util/NoSuchElementException",
                                    "no more tokens")
                receiver.fields["pos"] = pos + 1
                return tokens[pos]
            if name == "countTokens":
                return len(tokens) - receiver.fields.get("pos", 0)
        if cls == "java/util/Timer" or cls == "java/util/TimerTask":
            if cls == "java/util/Timer" and name == "schedule":
                task = args[0]
                if isinstance(task, Obj):
                    # the queue runs synchronously: same ordering both sides,
                    # no wall clock, no threads
                    engine._call(task.cls, "run", "()V", task, [],
                                 exact=False)
                    return None
                return engine.heap.opaque("timer-without-modelled-task")
            if cls == "java/util/TimerTask" and name == "run":
                return None
        if cls.startswith("java/util/concurrent/atomic/Atomic"):
            value = receiver.fields.setdefault("value", None)
            if name in ("get", "getPlain", "getAcquire", "getOpaque"):
                return value
            if name in ("set", "setRelease", "setOpaque", "lazySet"):
                receiver.fields["value"] = args[0]; return None
            if name == "getAndSet":
                receiver.fields["value"] = args[0]; return value
            if name == "compareAndSet" or name == "compareAndExchange":
                if value is args[0]:
                    receiver.fields["value"] = args[1]
                    return 1 if name == "compareAndSet" else args[0]
                return 0 if name == "compareAndSet" else value
            if cls == "java/util/concurrent/atomic/AtomicInteger" \
                    and name == "incrementAndGet":
                receiver.fields["value"] = as_int(value) + 1
                return receiver.fields["value"]
            if cls == "java/util/concurrent/atomic/AtomicLong" \
                    and name in ("incrementAndGet", "addAndGet"):
                receiver.fields["value"] = as_int(value) + as_int(args[0]) \
                    if name == "addAndGet" else as_int(value) + 1
                return receiver.fields["value"]
        if cls == "java/security/AccessController" and name == "doPrivileged":
            action = args[0]
            if isinstance(action, Obj):
                return engine._call(action.cls, "run", "()V", action, [],
                                    exact=False)
            return engine.heap.opaque("doPrivileged-without-modelled-body")
        raise Unsupported(f"{cls}.{name} is not modelled")


def _value_equal(a, b) -> bool:
    if isinstance(a, str) and isinstance(b, str):
        return a == b
    if isinstance(a, Obj) and isinstance(b, Obj):
        return a is b
    return a is b


def _path_text(arg) -> str:
    if isinstance(arg, Obj):
        return arg.fields.get("path", "")
    return jstr(arg)
