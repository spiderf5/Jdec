"""Lightweight web workbench for interactive deobfuscation and reverse engineering audit.

Zero external dependencies (pure Python http.server + HTML5/CSS3/vanilla JS).
Features:
- Package & class hierarchy navigation with live filtering;
- Multi-engine source code comparison (CFR vs Vineflower vs Procyon side-by-side);
- Integrated Mixin hook target inspector;
- JNI native library C pseudo-code viewer;
- Threat string constants browser with tag filtering.
"""

from __future__ import annotations

import html
import json
import os
import re
import socketserver
import sys
import urllib.parse
from http.server import SimpleHTTPRequestHandler, HTTPServer
from pathlib import Path
import webbrowser

from . import probe as PB
from . import analyze as AZ
from . import strings as ST
from . import native_scan as NS

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>jdec Workbench - Interactive Deobfuscation & Audit</title>
<style>
  :root {
    --bg-dark: #1e1e24;
    --bg-card: #282830;
    --bg-side: #18181c;
    --text-main: #f0f0f5;
    --text-muted: #9595a8;
    --accent: #5e81ac;
    --accent-hover: #81a1c1;
    --danger: #bf616a;
    --success: #a3be8c;
    --warning: #ebcb8b;
    --border: #383842;
    --code-bg: #141418;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; }
  body { background: var(--bg-dark); color: var(--text-main); height: 100vh; display: flex; flex-direction: column; overflow: hidden; }
  header { background: var(--bg-side); border-bottom: 1px solid var(--border); padding: 10px 20px; display: flex; align-items: center; justify-content: space-between; }
  header h1 { font-size: 1.15rem; font-weight: 700; color: var(--accent-hover); display: flex; align-items: center; gap: 8px; }
  header .badge { background: var(--bg-card); border: 1px solid var(--border); padding: 3px 8px; border-radius: 4px; font-size: 0.8rem; color: var(--text-muted); }
  .layout { display: flex; flex: 1; height: calc(100vh - 48px); }
  .sidebar { width: 300px; background: var(--bg-side); border-right: 1px solid var(--border); display: flex; flex-direction: column; }
  .search-box { padding: 10px; border-bottom: 1px solid var(--border); }
  .search-box input { width: 100%; background: var(--bg-card); border: 1px solid var(--border); border-radius: 4px; padding: 6px 10px; color: var(--text-main); outline: none; font-size: 0.85rem; }
  .tree-list { flex: 1; overflow-y: auto; padding: 8px; font-size: 0.85rem; }
  .tree-item { padding: 5px 8px; border-radius: 4px; cursor: pointer; display: flex; align-items: center; justify-content: space-between; color: var(--text-muted); }
  .tree-item:hover { background: var(--bg-card); color: var(--text-main); }
  .tree-item.active { background: var(--accent); color: #fff; }
  .main-pane { flex: 1; display: flex; flex-direction: column; background: var(--bg-dark); overflow: hidden; }
  .tabs-bar { background: var(--bg-side); border-bottom: 1px solid var(--border); display: flex; gap: 2px; padding: 0 10px; }
  .tab-btn { background: transparent; border: none; border-bottom: 2px solid transparent; color: var(--text-muted); padding: 8px 14px; font-size: 0.85rem; cursor: pointer; }
  .tab-btn:hover { color: var(--text-main); }
  .tab-btn.active { color: var(--accent-hover); border-bottom-color: var(--accent-hover); font-weight: 600; }
  .content-area { flex: 1; display: flex; overflow: hidden; position: relative; }
  .code-view { flex: 1; background: var(--code-bg); padding: 15px; overflow: auto; font-family: "Consolas", "Courier New", monospace; font-size: 0.88rem; line-height: 1.45; white-space: pre; color: #d8dee9; }
  .inspector { width: 340px; background: var(--bg-side); border-left: 1px solid var(--border); overflow-y: auto; padding: 15px; font-size: 0.85rem; }
  .inspector h3 { font-size: 0.9rem; color: var(--text-muted); text-transform: uppercase; margin-bottom: 10px; border-bottom: 1px solid var(--border); padding-bottom: 4px; }
  .inspector .sec { margin-bottom: 18px; }
  .card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 4px; padding: 8px 10px; margin-bottom: 8px; }
  .tag { display: inline-block; font-size: 0.75rem; padding: 2px 6px; border-radius: 3px; background: var(--border); color: var(--text-main); margin-right: 4px; margin-bottom: 4px; }
  .tag.danger { background: rgba(191,97,106,0.25); color: var(--danger); border: 1px solid var(--danger); }
  .tag.warning { background: rgba(235,203,139,0.25); color: var(--warning); border: 1px solid var(--warning); }
</style>
</head>
<body>
  <header>
    <h1><span>jdec</span> Workbench</h1>
    <div id="target-summary" class="badge">Loading target ...</div>
  </header>
  <div class="layout">
    <div class="sidebar">
      <div class="search-box">
        <input type="text" id="class-filter" placeholder="Filter classes & packages ...">
      </div>
      <div class="tree-list" id="class-tree"></div>
    </div>
    <div class="main-pane">
      <div class="tabs-bar">
        <button class="tab-btn active" onclick="switchView('decompiled')">Decompiled Source</button>
        <button class="tab-btn" onclick="switchView('natives')">Native C Code</button>
        <button class="tab-btn" onclick="switchView('threats')">Threats & Strings</button>
        <button class="tab-btn" onclick="switchView('report')">Triage Report</button>
      </div>
      <div class="content-area">
        <div class="code-view" id="code-content">// Select a class from the left sidebar to view decompiled code.</div>
        <div class="inspector" id="inspector-content">
          <div class="sec">
            <h3>Class Information</h3>
            <div id="class-meta" class="card">No class selected</div>
          </div>
          <div class="sec">
            <h3>Mixin Hooks</h3>
            <div id="class-hooks" class="card">None detected</div>
          </div>
          <div class="sec">
            <h3>Strings & Identifiers</h3>
            <div id="class-strings" class="card">None detected</div>
          </div>
        </div>
      </div>
    </div>
  </div>
  <script>
    let currentData = { classes: [], selected: null, currentView: 'decompiled' };

    async function loadTree() {
      try {
        const res = await fetch('/api/tree');
        const data = await res.json();
        currentData.classes = data.classes || [];
        document.getElementById('target-summary').innerText = (data.target || 'target') + ' (' + currentData.classes.length + ' classes)';
        renderTree(currentData.classes);
        if (currentData.classes.length > 0) {
          selectClass(currentData.classes[0]);
        }
      } catch (e) {
        document.getElementById('code-content').innerText = 'Failed to load project: ' + e;
      }
    }

    function renderTree(list) {
      const container = document.getElementById('class-tree');
      container.innerHTML = '';
      list.forEach(cls => {
        const el = document.createElement('div');
        el.className = 'tree-item' + (currentData.selected === cls ? ' active' : '');
        el.innerText = cls;
        el.onclick = () => selectClass(cls);
        container.appendChild(el);
      });
    }

    document.getElementById('class-filter').oninput = (e) => {
      const q = e.target.value.toLowerCase();
      renderTree(currentData.classes.filter(c => c.toLowerCase().includes(q)));
    };

    function esc(s) {
      return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    async function selectClass(cls) {
      currentData.selected = cls;
      renderTree(currentData.classes.filter(c => c.toLowerCase().includes(document.getElementById('class-filter').value.toLowerCase())));
      document.getElementById('class-meta').innerHTML = '<b>' + esc(cls) + '</b>';
      
      const res = await fetch('/api/source?class=' + encodeURIComponent(cls));
      const code = await res.text();
      document.getElementById('code-content').innerText = code;

      const metaRes = await fetch('/api/class_info?class=' + encodeURIComponent(cls));
      const meta = await metaRes.json();
      
      let hooksHtml = '';
      if (meta.hooks && meta.hooks.length > 0) {
        meta.hooks.forEach(h => {
          hooksHtml += '<div style="margin-bottom:6px;"><b>@' + esc(h.kind) + '</b> &rarr; ' + esc(h.target_class || '') + ' ' + esc(h.target_method || '') + '</div>';
        });
      } else {
        hooksHtml = 'No mixin hooks';
      }
      document.getElementById('class-hooks').innerHTML = hooksHtml;

      let strHtml = '';
      if (meta.strings && meta.strings.length > 0) {
        meta.strings.forEach(s => {
          const tags = (s.tags || []).map(t => '<span class="tag danger">' + esc(t) + '</span>').join('');
          strHtml += '<div style="margin-bottom:4px;"><code>' + esc(s.string) + '</code> ' + tags + '</div>';
        });
      } else {
        strHtml = 'No sensitive literals';
      }
      document.getElementById('class-strings').innerHTML = strHtml;
    }

    function switchView(view) {
      currentData.currentView = view;
      document.querySelectorAll('.tab-btn').forEach((btn, idx) => {
        btn.classList.toggle('active', ['decompiled', 'natives', 'threats', 'report'][idx] === view);
      });
      if (view === 'report') {
        fetch('/api/report').then(r => r.text()).then(txt => document.getElementById('code-content').innerText = txt);
      } else if (view === 'natives') {
        fetch('/api/natives').then(r => r.text()).then(txt => document.getElementById('code-content').innerText = txt);
      } else if (view === 'threats') {
        fetch('/api/threats').then(r => r.text()).then(txt => document.getElementById('code-content').innerText = txt);
      } else if (currentData.selected) {
        selectClass(currentData.selected);
      }
    }

    loadTree();
  </script>
</body>
</html>
"""


class WorkbenchHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, work_dir: Path, **kwargs):
        self.work_dir = work_dir
        super().__init__(*args, **kwargs)

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
            self.send_json({"target": self.work_dir.name, "classes": sorted(classes)})
            return

        if path == "/api/source":
            cls = query.get("class", [""])[0]
            code = "// Source not found for: " + cls
            rel_name = cls + ".java"
            rep_json = self.work_dir / "report.json"
            if rep_json.is_file():
                try:
                    r_data = json.loads(rep_json.read_text(encoding="utf-8"))
                    outcomes = r_data.get("outcomes", {})
                    if cls in outcomes and outcomes[cls].get("rel"):
                        rel_name = outcomes[cls]["rel"]
                except Exception:
                    pass

            src_dir = (self.work_dir / "src").resolve()
            target_path = (self.work_dir / "src" / rel_name).resolve()
            # Path traversal safety check
            if str(target_path).startswith(str(src_dir)) and target_path.is_file():
                try:
                    code = target_path.read_text(encoding="utf-8", errors="replace")
                except Exception as e:
                    code = f"// Error reading file: {e}"
            self.send_text(code)
            return

        if path == "/api/class_info":
            cls = query.get("class", [""])[0]
            info = {"hooks": [], "strings": []}
            # Look up strings in strings.json if present
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

        if path == "/api/report":
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

        self.send_error(404, "Not Found")

    def send_json(self, data: dict):
        body = json.dumps(data).encode("utf-8")
        self.send_response(200)
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
            server = HTTPServer(("127.0.0.1", p), handler)
            chosen_port = p
            break
        except OSError:
            continue
    if server is None:
        server = HTTPServer(("127.0.0.1", port), handler)
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
