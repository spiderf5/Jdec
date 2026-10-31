"""Lightweight web workbench for interactive deobfuscation and reverse engineering audit.

Zero external dependencies (pure Python http.server + HTML5/CSS3/vanilla JS).
Features:
- Package & class hierarchy navigation with live filtering;
- Multi-engine source code comparison (unified diff between CFR, Vineflower, Procyon, and Final);
- Interactive audit annotations & notes (suspect, core, net, threat, hook, benign) persisted to disk;
- One-click LLM semantic rename prompt generator for AI-assisted deobfuscation;
- Integrated Mixin hook target inspector;
- JNI native library C pseudo-code viewer;
- Threat string constants browser with tag filtering.
"""

from __future__ import annotations

import datetime
import difflib
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.parse
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import webbrowser

from . import engines as EN
from . import rename as RN
from . import callgraph as CG

_CG_CACHE: dict[str, tuple[CG.CallGraph, CG.ReachabilityReport]] = {}
_CG_FAIL: set[str] = set()

_WEB_ASSETS = Path(__file__).with_name("web_assets")
HTML_TEMPLATE = (
    (_WEB_ASSETS / "index.html").read_text(encoding="utf-8")
    .replace("/*__INLINE_CSS__*/", (_WEB_ASSETS / "app.css").read_text(encoding="utf-8"))
    .replace("/*__INLINE_JS__*/", (_WEB_ASSETS / "app.js").read_text(encoding="utf-8"))
)


def _report_classes(data: dict) -> dict:
    """Per-class map out of report.json, under the key the writer uses.

    `decompile.write_report` stores it as `"classes"`; every reader here asked
    for `"outcomes"` and therefore always got {} - which silently disabled the
    rel reverse-lookup for percent-encoded twin classes and made the diff view
    re-decompile classes whose winning engine actually matched. Accept both so
    old report.json files keep working.
    """
    if not isinstance(data, dict):
        return {}
    return data.get("classes") or data.get("outcomes") or {}


def _class_tags(data: dict) -> dict:
    """Badge data for the class tree: quality status, native count, engine.

    Only classes that need a badge are included; a clean class costs no
    payload. Keys are the tree keys (`rel` minus `.java` when report.json
    carries one, otherwise the internal class name).
    """
    tags = {}
    for cls, info in _report_classes(data).items():
        if not isinstance(info, dict):
            continue
        status = info.get("status")
        native = info.get("native_methods") or 0
        if status not in ("failed", "partial") and not native:
            continue
        rel = info.get("rel") or (cls + ".java")
        key = rel[:-5] if isinstance(rel, str) and rel.endswith(".java") else rel
        item = {}
        if status in ("failed", "partial"):
            item["status"] = status
        if native:
            item["native"] = int(native)
        engine = info.get("engine")
        if engine and status in ("failed", "partial"):
            item["engine"] = str(engine)
        score = info.get("score")
        if isinstance(score, (int, float)):
            item["score"] = round(float(score), 1)
        tags[str(key)] = item
    return tags


def _analysis_input(work_dir: Path) -> Path | None:
    """The original jar recorded by the decompiler/pipeline report, if any."""
    if work_dir.is_file() and work_dir.suffix.lower() in (".jar", ".exe"):
        return work_dir
    candidates = [work_dir / "report.json",
                  work_dir.parent / (work_dir.name + "_decompile") / "report.json"]
    for rep in candidates:
        if not rep.is_file():
            continue
        try:
            data = json.loads(rep.read_text(encoding="utf-8"))
        except Exception:
            continue
        raw = data.get("input")
        if not raw:
            continue
        path = Path(raw)
        if not path.is_absolute():
            for base in (work_dir, work_dir.parent):
                cand = base / path
                if cand.is_file():
                    return cand
        if path.is_file():
            return path
    return None


def _javap_bin() -> str | None:
    java = EN.find_java()
    if java:
        exe = Path(java).with_name("javap" + Path(java).suffix)
        if exe.is_file():
            return str(exe)
    return shutil.which("javap")


def _engine_key(engine: str) -> str | None:
    """Map a UI engine label to a known engine key, or None.

    The label arrives in a query string and is joined into a path below, so
    an unknown one must never become a directory name.
    """
    key = (engine or "").strip().lower()
    if key in ("", "final", "current"):
        return ""
    return key if key in EN.ENGINES else None


def _get_source_for_engine(work_dir: Path, cls: str, engine: str) -> str:
    """Retrieve Java source code for a class produced by a specific decompiler engine."""
    if not cls:
        return "// No class specified"

    rel_name = cls + ".java"
    rep_json = work_dir / "report.json"
    if rep_json.is_file():
        try:
            r_data = json.loads(rep_json.read_text(encoding="utf-8"))
            outcomes = _report_classes(r_data)
            if cls in outcomes and outcomes[cls].get("rel"):
                rel_name = outcomes[cls]["rel"]
        except Exception:
            pass

    src_dir = (work_dir / "src").resolve()
    target_path = (src_dir / rel_name).resolve()

    eng_key = _engine_key(engine)
    if eng_key is None:
        return f"// Unknown engine: {engine}"
    if eng_key == "":
        if target_path.is_relative_to(src_dir) and target_path.is_file():
            try:
                return target_path.read_text(encoding="utf-8", errors="replace")
            except Exception as e:
                return f"// Error reading file: {e}"
        return f"// Source not found for {cls} in src/"

    # 1. Check existing engine directory: engines/<engine>/<rel_name>
    eng_dir = (work_dir / "engines" / eng_key).resolve()
    eng_target = (eng_dir / rel_name).resolve()
    if eng_target.is_relative_to(eng_dir) and eng_target.is_file():
        try:
            return eng_target.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            return f"// Error reading {engine} source: {e}"

    # 2. Check engine cache: _engines_cache/<engine>/<rel_name>
    cache_dir = (work_dir / "_engines_cache" / eng_key).resolve()
    cache_target = (cache_dir / rel_name).resolve()
    if cache_target.is_relative_to(cache_dir) and cache_target.is_file():
        try:
            return cache_target.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            return f"// Error reading cached {engine} source: {e}"

    # 3. Check pass 2 work directories: _work/out2_<engine>...
    work_sub = work_dir / "_work"
    if work_sub.is_dir():
        work_root = work_sub.resolve()
        for d in work_sub.glob(f"out*_{eng_key}*"):
            f = (d / rel_name).resolve()
            if f.is_relative_to(work_root) and f.is_file():
                try:
                    return f.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    pass

    # 4. Check if the winning engine in report.json happens to match this engine
    if rep_json.is_file():
        try:
            r_data = json.loads(rep_json.read_text(encoding="utf-8"))
            outcomes = _report_classes(r_data)
            if cls in outcomes and (outcomes[cls].get("engine") or "").lower() == eng_key:
                if target_path.is_relative_to(src_dir) and target_path.is_file():
                    return target_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            pass

    # 5. On-demand single class decompilation if input archive is available
    input_jar = None
    if work_dir.is_file() and work_dir.suffix.lower() == ".jar":
        input_jar = work_dir
    elif rep_json.is_file():
        try:
            r_data = json.loads(rep_json.read_text(encoding="utf-8"))
            inp = r_data.get("input")
            if inp and Path(inp).is_file():
                input_jar = Path(inp)
        except Exception:
            pass

    if input_jar and eng_key in EN.ENGINES:
        try:
            class_entry = cls.replace("\\", "/").strip("/") + ".class"
            import zipfile
            with zipfile.ZipFile(input_jar) as z:
                matching = [n for n in z.namelist() if n == class_entry or n.endswith("/" + Path(class_entry).name)]
                if matching:
                    exact = matching[0]
                    temp_dir = cache_dir / "_temp"
                    temp_dir.mkdir(parents=True, exist_ok=True)
                    target_class_file = temp_dir / exact
                    target_class_file.parent.mkdir(parents=True, exist_ok=True)
                    target_class_file.write_bytes(z.read(exact))

                    engines_dir = Path(__file__).resolve().parent.parent / "engines"
                    if not engines_dir.exists():
                        engines_dir = work_dir.parent / "engines"

                    if EN.ENGINES[eng_key].available(engines_dir):
                        res = EN.run_engine(EN.ENGINES[eng_key], engines_dir, target_class_file.parent, cache_dir, timeout=15)
                        if res.ok and cache_target.is_file():
                            return cache_target.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            return f"// Attempted on-demand decompile with {engine} but encountered: {e}"

    return (
        f"// Engine '{engine}' output is not available for {cls}.\n"
        f"// (Run multi-engine decompilation or ensure the original archive is accessible)\n"
    )


class WorkbenchHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, work_dir: Path, **kwargs):
        self.work_dir = work_dir
        super().__init__(*args, **kwargs)

    def _get_notes_file(self) -> Path:
        if self.work_dir.is_file():
            return self.work_dir.parent / (self.work_dir.name + "_notes.json")
        return self.work_dir / "audit_notes.json"

    def _get_cached_callgraph(self) -> tuple[CG.CallGraph, CG.ReachabilityReport] | None:
        # None ≠ 合法空数据：配合 self._cg_error 区分"无目标"与"构建失败"
        self._cg_error: str | None = None
        target = None
        if self.work_dir.is_file() and self.work_dir.suffix.lower() == ".jar":
            target = self.work_dir
        else:
            rep_json = self.work_dir / "report.json"
            if rep_json.is_file():
                try:
                    r_data = json.loads(rep_json.read_text(encoding="utf-8"))
                    inp = r_data.get("input")
                    if inp and Path(inp).exists():
                        target = Path(inp)
                except Exception:
                    pass
            if target is None:
                pipe_json = self.work_dir / "pipeline_summary.json"
                if pipe_json.is_file():
                    try:
                        p_data = json.loads(pipe_json.read_text(encoding="utf-8"))
                        tgt = p_data.get("target")
                        if tgt and Path(tgt).exists():
                            target = Path(tgt)
                    except Exception:
                        pass
            if target is None and (self.work_dir / "src").is_dir():
                target = self.work_dir

        if not target:
            self._cg_error = ("no analysis target found (need a .jar, "
                              "report.json, pipeline_summary.json or src/ "
                              "in the work dir)")
            return None

        cache_key = str(target.resolve())
        if cache_key in _CG_CACHE:
            return _CG_CACHE[cache_key]
        if cache_key in _CG_FAIL:
            self._cg_error = ("callgraph build failed for this target "
                              "(see server stderr for the original error)")
            return None

        try:
            cg = CG.build_callgraph(target)
            rep = CG.compute_reachability(cg)
            _CG_CACHE[cache_key] = (cg, rep)
            return (cg, rep)
        except Exception as exc:
            # 构建失败 ≠ 无数据：留痕到失败缓存（避免每个请求重复重建+刷屏），
            # stderr 告警一次，处理器负责把它变成结构化错误而不是假数据
            _CG_FAIL.add(cache_key)
            print(f"[callgraph] build failed for {target}: "
                  f"{type(exc).__name__}: {exc}", file=sys.stderr)
            self._cg_error = f"callgraph build failed: {type(exc).__name__}: {exc}"
            return None

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/annotations":
            content_len = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_len) if content_len > 0 else b"{}"
            try:
                payload = json.loads(body.decode("utf-8"))
            except Exception:
                self.send_error(400, "Invalid JSON payload")
                return

            cls = payload.get("class", "").strip()
            tag = payload.get("tag", "").strip()
            note = payload.get("note", "").strip()
            status = payload.get("status", "").strip()

            if not cls:
                self.send_error(400, "Missing 'class' field")
                return

            notes_file = self._get_notes_file()
            notes = {}
            if notes_file.is_file():
                try:
                    notes = json.loads(notes_file.read_text(encoding="utf-8"))
                except Exception:
                    notes = {}

            if not tag and not note:
                notes.pop(cls, None)
            else:
                notes[cls] = {
                    "tag": tag,
                    "note": note,
                    "status": status or ("flagged" if tag in ("suspect", "threat") else "reviewed"),
                    "updated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                }

            try:
                notes_file.parent.mkdir(parents=True, exist_ok=True)
                notes_file.write_text(json.dumps(notes, indent=2, ensure_ascii=False), encoding="utf-8")
            except Exception as e:
                self.send_error(500, f"Failed to save notes: {e}")
                return

            self.send_json({"ok": True, "annotations": notes})
            return

        self.send_error(404, "Not Found")

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if path in ("", "/"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_TEMPLATE.encode("utf-8"))
            return

        if path == "/api/tree":
            classes = []
            if self.work_dir.is_file() and self.work_dir.suffix.lower() == ".jar":
                import zipfile
                try:
                    with zipfile.ZipFile(self.work_dir) as z:
                        for n in z.namelist():
                            if n.endswith(".class") and not n.startswith("META-INF/"):
                                classes.append(n[:-6])
                except Exception:
                    pass
            else:
                src_dir = self.work_dir / "src"
                if src_dir.is_dir():
                    for f in src_dir.rglob("*.java"):
                        rel = f.relative_to(src_dir).as_posix()
                        classes.append(rel.replace(".java", ""))
            # src/ stems are percent-encoded for case twins; send a display
            # name alongside so the tree reads `pkg/A` while requests keep the
            # exact stem the file system (and report.json rel) uses
            names = {}
            for rel in classes:
                if "%" in rel:
                    names[rel] = "/".join(
                        urllib.parse.unquote(seg) for seg in rel.split("/"))
            tags = {}
            rep_json = self.work_dir / "report.json"
            if rep_json.is_file():
                try:
                    tags = _class_tags(json.loads(
                        rep_json.read_text(encoding="utf-8")))
                except Exception:
                    tags = {}
            self.send_json({"target": self.work_dir.name,
                            "classes": sorted(classes), "names": names,
                            "tags": tags})
            return

        if path == "/api/annotations":
            notes_file = self._get_notes_file()
            notes = {}
            if notes_file.is_file():
                try:
                    notes = json.loads(notes_file.read_text(encoding="utf-8"))
                except Exception:
                    notes = {}
            self.send_json(notes)
            return

        if path == "/api/source":
            cls = query.get("class", [""])[0]
            code = "// Source not found for: " + cls
            rel_name = cls + ".java"
            rep_json = self.work_dir / "report.json"
            if rep_json.is_file():
                try:
                    r_data = json.loads(rep_json.read_text(encoding="utf-8"))
                    outcomes = _report_classes(r_data)
                    if cls in outcomes and outcomes[cls].get("rel"):
                        rel_name = outcomes[cls]["rel"]
                except Exception:
                    pass

            src_dir = (self.work_dir / "src").resolve()
            target_path = (self.work_dir / "src" / rel_name).resolve()
            if target_path.is_relative_to(src_dir) and target_path.is_file():
                try:
                    code = target_path.read_text(encoding="utf-8", errors="replace")
                except Exception as e:
                    code = f"// Error reading file: {e}"
            self.send_text(code)
            return

        if path == "/api/diff":
            cls = query.get("class", [""])[0]
            e1 = query.get("e1", ["final"])[0]
            e2 = query.get("e2", ["cfr"])[0]

            src1 = _get_source_for_engine(self.work_dir, cls, e1)
            src2 = _get_source_for_engine(self.work_dir, cls, e2)

            lines1 = src1.splitlines(keepends=True)
            lines2 = src2.splitlines(keepends=True)
            diff_lines = list(difflib.unified_diff(
                lines1, lines2,
                fromfile=f"{cls} ({e1})",
                tofile=f"{cls} ({e2})",
            ))
            diff_text = "".join(diff_lines)
            added = sum(1 for line in diff_lines if line.startswith("+") and not line.startswith("+++"))
            removed = sum(1 for line in diff_lines if line.startswith("-") and not line.startswith("---"))

            self.send_json({
                "class": cls,
                "e1": e1,
                "e2": e2,
                "identical": src1.strip() == src2.strip(),
                "diff": diff_text,
                "stats": {"added": added, "removed": removed},
                "lines_count": len(diff_lines),
            })
            return

        if path == "/api/llm_prompt":
            cls = query.get("class", [""])[0]
            if not cls:
                self.send_error(400, "Missing 'class' parameter")
                return

            rel_name = cls + ".java"
            rep_json = self.work_dir / "report.json"
            if rep_json.is_file():
                try:
                    r_data = json.loads(rep_json.read_text(encoding="utf-8"))
                    outcomes = _report_classes(r_data)
                    if cls in outcomes and outcomes[cls].get("rel"):
                        rel_name = outcomes[cls]["rel"]
                except Exception:
                    pass

            src_dir = (self.work_dir / "src").resolve()
            src_file = (src_dir / rel_name).resolve()
            code = ""
            if src_file.is_relative_to(src_dir) and src_file.is_file():
                try:
                    code = src_file.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    code = ""

            candidates = []
            if src_file.is_relative_to(src_dir) and src_file.is_file():
                try:
                    candidates = RN.scan_source_file(src_file)
                except Exception:
                    candidates = []

            # Strings
            strings_list = []
            s_json = self.work_dir / "strings.json"
            if not s_json.is_file():
                s_json = self.work_dir.parent / (self.work_dir.name + "_strings") / "strings.json"
            if s_json.is_file():
                try:
                    s_data = json.loads(s_json.read_text(encoding="utf-8"))
                    strings_list = s_data.get("strings", {}).get(cls.replace(".", "/"), [])
                except Exception:
                    pass

            # Hooks
            hooks_list = []
            for line in code.splitlines():
                if "@Inject" in line or "@Overwrite" in line or "@Redirect" in line:
                    hooks_list.append(line.strip())

            dotted = cls.replace("/", ".")
            prompt_lines = [
                "You are an expert Java reverse engineer and deobfuscation specialist.",
                f"Analyze the decompiled class '{dotted}' and provide meaningful semantic names for all obfuscated entities.",
                "",
                f"### Target Class: {dotted} (internal: {cls})",
            ]

            if hooks_list:
                prompt_lines.append("### Detected Mixin Hooks:")
                for h in hooks_list[:8]:
                    prompt_lines.append(f"- {h}")
                prompt_lines.append("")

            if strings_list:
                prompt_lines.append("### Detected Sensitive / Key Strings:")
                for s in strings_list[:12]:
                    tags_str = f" [{', '.join(s.get('tags', []))}]" if s.get("tags") else ""
                    prompt_lines.append(f'- "{s.get("string", "")}"{tags_str}')
                prompt_lines.append("")

            if candidates:
                prompt_lines.append(f"### Detected Obfuscated Members ({len(candidates)} items):")
                for c in candidates[:25]:
                    extra = f" (heuristics: {c.suggested_name})" if c.suggested_name else ""
                    prompt_lines.append(f"- {c.return_type} {c.member_name}({c.parameters}){extra}")
                prompt_lines.append("")

            code_lines = code.splitlines()
            code_preview = "\n".join(code_lines[:180])
            if len(code_lines) > 180:
                code_preview += f"\n// ... truncated {len(code_lines) - 180} more lines ..."

            prompt_lines.append(f"### Decompiled Source Code ({len(code_lines)} lines):")
            prompt_lines.append("```java")
            prompt_lines.append(code_preview)
            prompt_lines.append("```")
            prompt_lines.append("")
            prompt_lines.append("### Required Output:")
            prompt_lines.append("1. **Behavior Summary**: 2-3 sentences explaining what this class is doing.")
            prompt_lines.append("2. **Semantic Renames**: Provide a clean ProGuard mapping block in the following format:")
            prompt_lines.append("```proguard")
            prompt_lines.append(f"{dotted} -> <NewDescriptiveClassName>:")
            prompt_lines.append("    <return_type> <old_method_name>(<param_types>) -> <new_method_name>")
            prompt_lines.append("    <field_type> <old_field_name> -> <new_field_name>")
            prompt_lines.append("```")

            prompt = "\n".join(prompt_lines)
            self.send_json({
                "class": cls,
                "prompt": prompt,
                "candidate_count": len(candidates),
                "line_count": len(code_lines),
            })
            return

        if path == "/api/bytecode":
            cls = query.get("class", [""])[0]
            if not cls or not re.fullmatch(r"[A-Za-z_$][\w$/]*", cls):
                self.send_json({"ok": False, "error": "invalid class name"})
                return
            jar = _analysis_input(self.work_dir)
            javap = _javap_bin()
            if jar is None:
                self.send_json({"ok": False,
                                "error": "no input jar recorded in report.json"})
                return
            if jar.suffix.lower() == ".exe":
                from . import sandbox as SBX
                jar = SBX.plain_jar(jar)
            if javap is None:
                self.send_json({"ok": False,
                                "error": "javap not found (install a JDK)"})
                return
            try:
                proc = subprocess.run(
                    [javap, "-p", "-c", "-classpath", str(jar),
                     cls.replace("/", ".")],
                    capture_output=True, text=True, encoding="utf-8",
                    errors="replace", timeout=30)
            except Exception as exc:
                self.send_json({"ok": False, "error": f"javap failed: {exc}"})
                return
            if proc.returncode != 0 and not proc.stdout:
                err = (proc.stderr or "javap failed").strip()
                self.send_json({"ok": False, "error": err[:2000]})
                return
            out = proc.stdout
            if len(out) > 2_000_000:
                out = out[:2_000_000] + "\n// ... output truncated ...\n"
            self.send_json({"ok": True, "class": cls, "bytecode": out})
            return

        if path == "/api/class_info":
            cls = query.get("class", [""])[0]
            info = {"hooks": [], "strings": [], "engine": None, "quality": None, "attempts": [], "status": None}
            rep_json = self.work_dir / "report.json"
            if rep_json.is_file():
                try:
                    r_data = json.loads(rep_json.read_text(encoding="utf-8"))
                    outcomes = _report_classes(r_data)
                    if cls in outcomes:
                        co = outcomes[cls]
                        info["engine"] = co.get("engine")
                        info["quality"] = co.get("quality")
                        info["attempts"] = co.get("attempts", [])
                        info["status"] = co.get("status")
                        info["score"] = co.get("score")
                except Exception:
                    pass

            s_json = self.work_dir / "strings.json"
            if not s_json.is_file():
                s_json = self.work_dir.parent / (self.work_dir.name + "_strings") / "strings.json"
            if s_json.is_file():
                try:
                    s_data = json.loads(s_json.read_text(encoding="utf-8"))
                    info["strings"] = s_data.get("strings", {}).get(cls.replace(".", "/"), [])
                except Exception:
                    pass
            self.send_json(info)
            return

        if path == "/api/callgraph":
            cls = query.get("class", [""])[0]
            if not cls:
                self.send_error(400, "Missing 'class' parameter")
                return

            cg_data = self._get_cached_callgraph()
            if not cg_data:
                # 构建失败/无目标 ≠ 空图：返回结构化错误，禁止合成 reachable:null 假数据
                self.send_json({
                    "error": getattr(self, "_cg_error", None)
                             or "callgraph unavailable",
                    "class": cls,
                }, status=503)
                return

            cg, rep = cg_data
            reachable = (cls in rep.reachable_classes) if rep.entrypoints else None

            callers = []
            seen_callers = set()
            for m in cg.class_methods.get(cls, []):
                for edge in cg.callers.get(m, []):
                    c_key = (str(edge.caller), edge.opcode)
                    if c_key not in seen_callers:
                        seen_callers.add(c_key)
                        callers.append({"caller": edge.caller.display_name, "opcode": edge.opcode})

            callees = []
            seen_callees = set()
            for m in cg.class_methods.get(cls, []):
                for edge in cg.callees.get(m, []):
                    c_key = (str(edge.callee), edge.opcode)
                    if c_key not in seen_callees:
                        seen_callees.add(c_key)
                        callees.append({"callee": edge.callee.display_name, "opcode": edge.opcode})

            path_edges = CG.find_path(rep, cls)
            path_info = []
            if path_edges:
                for e in path_edges:
                    path_info.append({
                        "from": e.caller.display_name,
                        "to": e.callee.display_name,
                        "opcode": e.opcode,
                    })

            self.send_json({
                "class": cls,
                "reachable": reachable,
                "entrypoints_count": len(rep.entrypoints),
                "callers": callers[:25],
                "callees": callees[:25],
                "path": path_info,
            })
            return

        if path == "/api/report":
            rep_path = self.work_dir / "pipeline_summary.md"
            if not rep_path.is_file():
                rep_path = self.work_dir / "report.md"
            if not rep_path.is_file():
                rep_path = self.work_dir / "analysis.md"
            content = rep_path.read_text(encoding="utf-8", errors="replace") if rep_path.is_file() else "# No report generated yet"
            self.send_text(content)
            return

        if path == "/api/natives":
            nat_rep = self.work_dir / "native-triage.md"
            if not nat_rep.is_file():
                nat_rep = self.work_dir.parent / (self.work_dir.name + "_natives") / "native-triage.md"
            content = nat_rep.read_text(encoding="utf-8", errors="replace") if nat_rep.is_file() else "# No native triage report found"
            self.send_text(content)
            return

        if path == "/api/threats":
            tsv = self.work_dir / "strings.tsv"
            if not tsv.is_file():
                tsv = self.work_dir.parent / (self.work_dir.name + "_strings") / "strings.tsv"
            content = tsv.read_text(encoding="utf-8", errors="replace") if tsv.is_file() else "# No strings.tsv found"
            self.send_text(content)
            return

        if path == "/api/export_project":
            from . import project
            out_proj = self.work_dir / "project"
            src_dir = self.work_dir / "src"
            target_jar = self.work_dir
            if self.work_dir.is_dir():
                rep_json = self.work_dir / "report.json"
                if rep_json.is_file():
                    try:
                        r_data = json.loads(rep_json.read_text(encoding="utf-8"))
                        inp = r_data.get("input")
                        if inp and Path(inp).is_file():
                            target_jar = Path(inp)
                    except Exception:
                        pass

            try:
                stats = project.export_project(target_jar, out_proj, src_dir=src_dir)
                self.send_json({"ok": True, "project_dir": str(out_proj), "stats": stats})
            except Exception as exc:
                self.send_error(500, f"Failed to export project: {exc}")
            return

        self.send_error(404, "Not Found")

    def send_json(self, data: dict, status: int = 200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_text(self, text: str):
        body = text.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def start_server(work_dir: Path, port: int = 8080, open_browser: bool = True) -> None:
    """Start local web workbench server with port conflict auto-increment."""
    handler = lambda *args, **kwargs: WorkbenchHandler(*args, work_dir=work_dir, **kwargs)
    server = None
    chosen_port = port
    for p in range(port, port + 10):
        try:
            server = ThreadingHTTPServer(("127.0.0.1", p), handler)
            chosen_port = p
            break
        except OSError:
            continue
    if server is None:
        server = ThreadingHTTPServer(("127.0.0.1", port), handler)
        chosen_port = port

    url = f"http://127.0.0.1:{chosen_port}"
    print(f"jdec workbench listening at: {url}")
    print("Press Ctrl+C to stop.")
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nWorkbench stopped.")
    finally:
        server.server_close()
