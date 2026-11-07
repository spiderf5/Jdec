"""The zero-dependency web workbench."""

from __future__ import annotations

from harness import (  # noqa: F401
    Path, SAMPLE, check, json, tempfile, urllib,
)


def test_web_callgraph_error_semantics() -> None:
    """BUG round negative: /api/callgraph used to synthesize reachable:null
    plus empty lists when the callgraph could not be built - masking
    failures as normal-looking empty data."""
    print("web: /api/callgraph returns structured error instead of fake data")
    import urllib.request
    import urllib.error
    import threading
    from jdec import web as WB

    def fetch(url: str):
        try:
            with urllib.request.urlopen(url) as res:
                return res.status, json.loads(res.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode("utf-8"))

    # scenario 1: empty work dir -> no analysis target at all
    with tempfile.TemporaryDirectory() as td:
        handler = lambda *a, **k: WB.WorkbenchHandler(*a, work_dir=Path(td), **k)
        server = WB.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            status, body = fetch(
                f"http://127.0.0.1:{server.server_address[1]}"
                f"/api/callgraph?class=demo/X")
            check("no-target -> structured error (4xx/5xx)", status >= 400,
                  f"status={status}")
            check("no-target error mentions missing target",
                  "error" in body and "target" in body["error"], str(body))
            check("no synthesized reachable key", "reachable" not in body)
        finally:
            server.shutdown()

    # scenario 2: target resolves but build fails (not a real jar)
    with tempfile.TemporaryDirectory() as td:
        fake_jar = Path(td) / "fake.jar"
        fake_jar.write_bytes(b"this is not a zip archive")
        handler = lambda *a, **k: WB.WorkbenchHandler(*a, work_dir=fake_jar, **k)
        server = WB.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            status, body = fetch(
                f"http://127.0.0.1:{server.server_address[1]}"
                f"/api/callgraph?class=demo/X")
            check("build-failure -> structured error (4xx/5xx)", status >= 400,
                  f"status={status}")
            check("build-failure error mentions build failure",
                  "error" in body and "build failed" in body["error"], str(body))
            check("no synthesized reachable key on failure",
                  "reachable" not in body)
        finally:
            server.shutdown()


def test_web_workbench_features() -> None:
    print("web: interactive workbench with diff, annotations and LLM assist")
    import re
    from jdec import web as WB
    import urllib.request
    import threading

    with tempfile.TemporaryDirectory() as td:
        work_dir = Path(td)
        src_dir = work_dir / "src" / "demo" / "obf"
        src_dir.mkdir(parents=True, exist_ok=True)
        java_file = src_dir / "a.java"
        java_file.write_text(
            'package demo.obf;\n\n'
            'public class a {\n'
            '    public int x = 1;\n'
            '    public void b() {\n'
            '        System.out.println("Connecting to C2 host");\n'
            '    }\n'
            '}\n',
            encoding="utf-8"
        )

        # case-twin class: the on-disk stem is percent-encoded
        (work_dir / "src" / "demo" / "obf" / "%41.java").write_text(
            "package demo.obf;\n\npublic class A {}\n", encoding="utf-8")

        cfr_dir = work_dir / "engines" / "cfr" / "demo" / "obf"
        cfr_dir.mkdir(parents=True, exist_ok=True)
        (cfr_dir / "a.java").write_text(
            'package demo.obf;\n\n'
            'public class a {\n'
            '    public int x = 1;\n'
            '    public int y = 2;\n'
            '    public void b() {\n'
            '        System.out.println("Connecting to C2 host");\n'
            '    }\n'
            '}\n',
            encoding="utf-8"
        )

        (work_dir / "report.json").write_text(json.dumps({
            "target": "sample.jar",
            "outcomes": {
                "demo/obf/a": {
                    "engine": "vineflower",
                    "rel": "demo/obf/a.java",
                    "quality": {"score": 96.5},
                    "attempts": ["cfr", "vineflower"],
                    "status": "ok"
                }
            }
        }), encoding="utf-8")

        (work_dir / "strings.json").write_text(json.dumps({
            "strings": {
                "demo/obf/a": [
                    {"string": "Connecting to C2 host", "tags": ["c2-staging", "url"]}
                ]
            }
        }), encoding="utf-8")

        (work_dir / "pipeline_summary.md").write_text("# Pipeline Summary\nAutomated deobf successful.", encoding="utf-8")

        handler = lambda *args, **kwargs: WB.WorkbenchHandler(*args, work_dir=work_dir, **kwargs)
        server = WB.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        port = server.server_address[1]
        srv_thread = threading.Thread(target=server.serve_forever, daemon=True)
        srv_thread.start()

        try:
            base_url = f"http://127.0.0.1:{port}"

            # 1. Test GET /
            with urllib.request.urlopen(f"{base_url}/") as res:
                html_body = res.read().decode("utf-8")
                check("workbench home page returns 200", res.status == 200)
                check("workbench HTML has interactive tabs", "Engine Diff" in html_body and "AI Semantic Rename" in html_body)
                check("workbench HTML has clean benign tag", '<option value="benign">benign</option>' in html_body)
                check("workbench HTML has zero emojis", not bool(re.search(r'[\U00010000-\U0010ffff\u2600-\u27bf\u2300-\u23ff\u2b50-\u2b55\u200d\ufe0f]', html_body)))
                check("workbench renders the decoded tree label",
                      "currentData.names[cls] || cls" in html_body)

            # 2. Test GET /api/tree
            with urllib.request.urlopen(f"{base_url}/api/tree") as res:
                tree_data = json.loads(res.read().decode("utf-8"))
                check("tree contains demo/obf/a", "demo/obf/a" in tree_data.get("classes", []))
                check("tree keeps the on-disk stem as the key",
                      "demo/obf/%41" in tree_data.get("classes", []),
                      str(tree_data.get("classes")))
                check("tree sends a decoded display name",
                      tree_data.get("names", {}).get("demo/obf/%41") == "demo/obf/A",
                      str(tree_data.get("names")))

            # 3. Test GET /api/source
            with urllib.request.urlopen(f"{base_url}/api/source?class=demo/obf/a") as res:
                source_code = res.read().decode("utf-8")
                check("source endpoint returns code", "Connecting to C2" in source_code)

            # 4. Test GET /api/class_info
            with urllib.request.urlopen(f"{base_url}/api/class_info?class=demo/obf/a") as res:
                cinfo = json.loads(res.read().decode("utf-8"))
                check("class info has engine", cinfo.get("engine") == "vineflower")
                check("class info has strings", len(cinfo.get("strings", [])) >= 1)

            # 5. Test GET /api/report
            with urllib.request.urlopen(f"{base_url}/api/report") as res:
                rep_text = res.read().decode("utf-8")
                check("report returns pipeline summary", "Pipeline Summary" in rep_text)

            # 6. Test GET & POST /api/annotations
            with urllib.request.urlopen(f"{base_url}/api/annotations") as res:
                empty_anns = json.loads(res.read().decode("utf-8"))
                check("initial annotations are empty", len(empty_anns) == 0)

            post_data = json.dumps({
                "class": "demo/obf/a",
                "tag": "threat",
                "note": "Suspicious C2 beacon string"
            }).encode("utf-8")
            req = urllib.request.Request(f"{base_url}/api/annotations", data=post_data, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req) as res:
                post_res = json.loads(res.read().decode("utf-8"))
                check("annotation save succeeded", post_res.get("ok") is True)
                check("annotation returned has tag", post_res.get("annotations", {}).get("demo/obf/a", {}).get("tag") == "threat")

            notes_file = work_dir / "audit_notes.json"
            check("audit_notes.json written to disk", notes_file.is_file())
            saved_notes = json.loads(notes_file.read_text(encoding="utf-8"))
            check("saved notes contains tag and note", saved_notes.get("demo/obf/a", {}).get("note") == "Suspicious C2 beacon string")

            # 7. Test GET /api/diff (Final vs CFR)
            with urllib.request.urlopen(f"{base_url}/api/diff?class=demo/obf/a&e1=final&e2=cfr") as res:
                diff_data = json.loads(res.read().decode("utf-8"))
                check("diff is not identical", diff_data.get("identical") is False)
                check("diff has added/removed stats", diff_data.get("stats", {}).get("added", 0) > 0)
                check("diff text contains unified diff marker", "+++" in diff_data.get("diff", ""))

            with urllib.request.urlopen(f"{base_url}/api/diff?class=demo/obf/a&e1=final&e2=final") as res:
                diff_same = json.loads(res.read().decode("utf-8"))
                check("diff between same engine is identical", diff_same.get("identical") is True)

            # 8. Test GET /api/llm_prompt
            with urllib.request.urlopen(f"{base_url}/api/llm_prompt?class=demo/obf/a") as res:
                prompt_data = json.loads(res.read().decode("utf-8"))
                prompt_text = prompt_data.get("prompt", "")
                check("LLM prompt contains class", "demo.obf.a" in prompt_text)
                check("LLM prompt contains candidate member", "b(" in prompt_text or "x" in prompt_text)
                check("LLM prompt requests ProGuard format", "```proguard" in prompt_text)

            # 9. Test GET /api/callgraph
            with urllib.request.urlopen(f"{base_url}/api/callgraph?class=demo/obf/a") as res:
                cg_api_data = json.loads(res.read().decode("utf-8"))
                check("callgraph endpoint responds", "callers" in cg_api_data and "callees" in cg_api_data)

            # 10. Test Path traversal defense on /api/source and /api/llm_prompt
            with urllib.request.urlopen(f"{base_url}/api/source?class=../../secret") as res:
                trav_source = res.read().decode("utf-8")
                check("path traversal on /api/source blocked", "Source not found" in trav_source)

            with urllib.request.urlopen(f"{base_url}/api/llm_prompt?class=../../secret") as res:
                trav_prompt = json.loads(res.read().decode("utf-8"))
                check("path traversal on /api/llm_prompt handled safely", "prompt" in trav_prompt)

        finally:
            server.shutdown()
            server.server_close()


def test_web_source_path_containment() -> None:
    """Engine labels and report rels are joined into paths: keep them inside."""
    print("web: source lookup refuses engine labels and rels that escape")
    from jdec import web as WB

    with tempfile.TemporaryDirectory() as td:
        wd = Path(td)
        (wd / "src" / "demo").mkdir(parents=True)
        (wd / "src" / "demo" / "A.java").write_text("class A {}\n", encoding="utf-8")
        (wd / "secret.java").write_text("SECRET\n", encoding="utf-8")
        (wd / "report.json").write_text(json.dumps({"classes": {
            "demo/A": {"engine": "cfr", "rel": "../secret.java"}}}),
            encoding="utf-8")

        check("a known engine label maps to its key", WB._engine_key("cfr") == "cfr")
        check("an unknown engine label has no key",
              WB._engine_key("../../../") is None)
        got = WB._get_source_for_engine(wd, "demo/A", "../../../")
        check("an unknown engine label is not used as a path",
              got.startswith("// Unknown engine"), got[:80])
        got = WB._get_source_for_engine(wd, "demo/A", "final")
        check("a report rel that escapes src/ is refused",
              "SECRET" not in got, got[:80])


def test_web_bytecode_endpoint() -> None:
    """The Bytecode tab is backed by javap on the recorded input jar."""
    print("web: /api/bytecode disassembles a class from the input jar")
    import threading
    from jdec import web as WB
    handler = lambda *a, **k: WB.WorkbenchHandler(*a, work_dir=SAMPLE, **k)
    server = WB.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        base = f"http://127.0.0.1:{port}"
        with urllib.request.urlopen(base + "/api/tree", timeout=20) as res:
            tree = json.loads(res.read().decode("utf-8"))
        name = next(c for c in tree["classes"] if c.endswith("/Showcase"))
        with urllib.request.urlopen(base + "/api/bytecode?class=" + name, timeout=30) as res:
            data = json.loads(res.read().decode("utf-8"))
        check("bytecode endpoint succeeds", data.get("ok") is True, str(data.get("error")))
        check("bytecode contains disassembly",
              "Code:" in data.get("bytecode", "") or "Compiled from" in data.get("bytecode", ""))
        with urllib.request.urlopen(base + "/api/bytecode?class=../escape", timeout=20) as res:
            bad = json.loads(res.read().decode("utf-8"))
        check("bytecode endpoint rejects a bad class name", bad.get("ok") is False)
    finally:
        server.shutdown()


def test_web_class_tags() -> None:
    """The class tree gets failed/partial/native badges from report.json."""
    print("web: class tree tags carry quality, native count and engine")
    from jdec import web as WB
    tags = WB._class_tags({"classes": {
        "a/Broken": {"status": "failed", "rel": "a/Broken.java",
                     "engine": "cfr", "score": 0.0},
        "a/Part": {"status": "partial", "rel": "a/Part.java",
                   "engine": "vineflower", "score": 52.5},
        "a/Native": {"status": "ok", "rel": "a/Native.java",
                     "native_methods": 2},
        "a/Clean": {"status": "ok", "rel": "a/Clean.java",
                    "engine": "cfr"},
        "a/NoRel": {"status": "failed"},
    }})
    check("failed class is tagged", tags.get("a/Broken", {}).get("status") == "failed")
    check("partial keeps its winning engine",
          tags.get("a/Part", {}).get("engine") == "vineflower")
    check("native class is tagged even when status is ok",
          tags.get("a/Native", {}).get("native") == 2)
    check("clean class pays no badge payload", "a/Clean" not in tags)
    check("missing rel falls back to the class name",
          tags.get("a/NoRel", {}).get("status") == "failed")
    check("empty report has no tags", WB._class_tags({}) == {})

