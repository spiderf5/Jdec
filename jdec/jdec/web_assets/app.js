(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const ROW_H = 30;
  const ANN_TAGS = new Set(["benign", "suspect", "threat", "core", "net", "hook"]);
  const TYPE_WORDS = new Set(("boolean byte char short int long float double void "
    + "String Object Class Integer Long Boolean Double Float Short Byte Character "
    + "List Map Set Collection Optional").split(" "));

  const currentData = {
    classes: [],
    names: {},
    tags: {},
    annotations: {},
    selected: null,
  };

  const state = {
    filter: "all",
    query: "",
    filtered: [],
    view: "source",
    iview: "overview",
    source: "",
    outline: [],
    paletteIndex: 0,
    paletteItems: [],
    graphFor: null,
    bytecodeFor: null,
    bytecodeCache: {},
    diffCache: {},
    auditLoaded: false,
    wrap: false,
  };

  function esc(value) {
    return String(value == null ? "" : value)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }

  function debounce(fn, ms) {
    let timer = null;
    return function () {
      const args = arguments;
      clearTimeout(timer);
      timer = setTimeout(() => fn.apply(null, args), ms);
    };
  }

  function toast(message, ms) {
    const el = $("toast");
    el.textContent = message;
    el.hidden = false;
    clearTimeout(el._timer);
    el._timer = setTimeout(() => { el.hidden = true; }, ms || 2200);
  }

  function encodeClass(cls) { return encodeURIComponent(cls); }

  function updateHash(cls, view) {
    const hash = "#c=" + encodeClass(cls || "") + (view ? "&v=" + view : "");
    if (window.location.hash !== hash) {
      history.replaceState(null, "", hash);
    }
  }

  function readHash() {
    const raw = window.location.hash.replace(/^#/, "");
    const out = {};
    raw.split("&").forEach((part) => {
      const idx = part.indexOf("=");
      if (idx > 0) out[part.slice(0, idx)] = decodeURIComponent(part.slice(idx + 1));
    });
    return out;
  }

  /* ------------------------------------------------------------------ tree */
  async function loadTree() {
    try {
      const [treeRes, annRes] = await Promise.all([
        fetch("/api/tree"),
        fetch("/api/annotations").catch(() => { throw new Error("annotations unavailable"); }),
      ]);
      const tree = await treeRes.json();
      currentData.annotations = (await annRes.json()) || {};
      currentData.classes = tree.classes || [];
      currentData.names = tree.names || {};
      currentData.tags = tree.tags || {};
      $("target-summary").textContent = tree.target || "target";
      $("target-summary").title = tree.target || "";
      $("status-target").textContent = (tree.target || "target") + "  /  " + currentData.classes.length + " classes";
      updateCounts();
      applyFilter();
      const wanted = readHash();
      const initial = wanted.c && currentData.classes.indexOf(wanted.c) >= 0
        ? wanted.c : currentData.classes[0];
      if (wanted.v && ["source", "diff", "bytecode", "audit"].indexOf(wanted.v) >= 0) {
        switchView(wanted.v);
      }
      if (initial) await selectClass(initial, true);
    } catch (err) {
      $("code-lines").innerHTML = '<div class="empty">Failed to load project: ' + esc(err) + "</div>";
      $("status-connection").textContent = "disconnected";
    }
  }

  function tagFor(cls) { return currentData.tags[cls] || null; }

  function annotationFor(cls) { return currentData.annotations[cls] || null; }

  function updateCounts() {
    let failed = 0, partial = 0, native = 0, tagged = 0;
    currentData.classes.forEach((cls) => {
      const tag = tagFor(cls);
      if (tag && tag.status === "failed") failed += 1;
      if (tag && tag.status === "partial") partial += 1;
      if (tag && tag.native) native += 1;
      const ann = annotationFor(cls);
      if (ann && (ann.tag || ann.note)) tagged += 1;
    });
    $("count-failed").textContent = failed;
    $("count-partial").textContent = partial;
    $("count-native").textContent = native;
    $("count-tagged").textContent = tagged;
    $("appbar-stats").innerHTML = "<span><b>" + currentData.classes.length + "</b> classes</span>"
      + "<span><b>" + failed + "</b> failed</span>"
      + "<span><b>" + partial + "</b> partial</span>"
      + "<span><b>" + native + "</b> native</span>";
  }

  function applyFilter() {
    const query = state.query.trim().toLowerCase();
    let list = currentData.classes;
    if (query) {
      list = list.filter((cls) => {
        const name = currentData.names[cls] || cls;
        return name.toLowerCase().indexOf(query) >= 0 || cls.toLowerCase().indexOf(query) >= 0;
      });
    }
    if (state.filter === "failed") list = list.filter((cls) => (tagFor(cls) || {}).status === "failed");
    else if (state.filter === "partial") list = list.filter((cls) => (tagFor(cls) || {}).status === "partial");
    else if (state.filter === "native") list = list.filter((cls) => Boolean((tagFor(cls) || {}).native));
    else if (state.filter === "tagged") {
      list = list.filter((cls) => {
        const ann = annotationFor(cls);
        return Boolean(ann && (ann.tag || ann.note));
      });
    }
    state.filtered = list.slice().sort((a, b) => a.localeCompare(b));
    const scroll = $("tree-scroll");
    const maxTop = Math.max(0, state.filtered.length * ROW_H - scroll.clientHeight);
    if (scroll.scrollTop > maxTop) scroll.scrollTop = maxTop;
    $("tree-count").textContent = state.filtered.length + " / " + currentData.classes.length;
    $("tree-footer").textContent = state.filter === "all" && !query
      ? "Ctrl+K opens the class palette" : "filter: " + state.filter;
    renderTree();
  }

  function renderTree() {
    const scroll = $("tree-scroll");
    const spacer = $("tree-spacer");
    const rows = $("tree-rows");
    const total = state.filtered.length;
    spacer.style.height = (total * ROW_H) + "px";
    const top = scroll.scrollTop;
    const start = Math.max(0, Math.floor(top / ROW_H) - 6);
    const end = Math.min(total, Math.ceil((top + scroll.clientHeight) / ROW_H) + 6);
    rows.style.transform = "translateY(" + (start * ROW_H) + "px)";
    const frag = document.createDocumentFragment();
    for (let i = start; i < end; i += 1) {
      const cls = state.filtered[i];
      const row = document.createElement("div");
      row.className = "tree-item" + (currentData.selected === cls ? " active" : "");
      row.title = currentData.names[cls] || cls;
      row.dataset.cls = cls;
      const label = document.createElement("span");
      label.className = "tree-label";
      label.textContent = currentData.names[cls] || cls;
      row.appendChild(label);
      const tag = tagFor(cls);
      if (tag) {
        if (tag.status === "failed") row.appendChild(badge("failed", "tag-failed", "decompilation failed"));
        else if (tag.status === "partial") {
          row.appendChild(badge("partial", "tag-partial",
            "some members missing" + (tag.score != null ? " / score " + tag.score : "")));
        }
        if (tag.native) row.appendChild(badge("native", "tag-native", tag.native + " native method(s)"));
        if (tag.engine) {
          const EN = { cfr: "CFR", vineflower: "VF", procyon: "Procyon" };
          row.appendChild(badge(EN[tag.engine] || tag.engine, "tag-engine", "winning engine: " + tag.engine));
        }
      }
      const ann = annotationFor(cls);
      if (ann && ANN_TAGS.has(ann.tag)) {
        row.appendChild(badge(ann.tag, "tag-" + ann.tag, "audit tag"));
      }
      row.addEventListener("click", () => selectClass(cls));
      frag.appendChild(row);
    }
    rows.replaceChildren(frag);
  }

  function badge(label, cls, title) {
    const el = document.createElement("span");
    el.className = "tag-badge " + cls;
    el.textContent = label;
    if (title) el.title = title;
    return el;
  }

  function scrollTreeTo(cls) {
    const idx = state.filtered.indexOf(cls);
    if (idx < 0) return;
    const scroll = $("tree-scroll");
    const top = idx * ROW_H;
    if (top < scroll.scrollTop || top + ROW_H > scroll.scrollTop + scroll.clientHeight) {
      scroll.scrollTop = Math.max(0, top - scroll.clientHeight / 2);
      renderTree();
    }
  }

  /* --------------------------------------------------------------- select */
  async function selectClass(cls, silent) {
    if (!cls) return;
    currentData.selected = cls;
    state.source = "";
    state.outline = [];
    $("crumb").innerHTML = "<b>" + esc(currentData.names[cls] || cls) + "</b>";
    $("code-lines").innerHTML = '<div class="empty">Loading source ...</div>';
    $("outline-list").innerHTML = "";
    $("class-meta").textContent = "Loading class ...";
    $("class-engine-info").innerHTML = "";
    $("class-strings").innerHTML = "";
    $("bytecode-body").innerHTML = '<div class="empty">Select the Bytecode tab to load it.</div>';
    $("diff-body").innerHTML = '<div class="empty">Run Compare to load a diff.</div>';
    state.bytecodeFor = null;
    state.graphFor = null;
    $("callgraph-body").innerHTML = '<div class="empty">Open Callgraph to load it.</div>';
    scrollTreeTo(cls);
    if (!silent) updateHash(cls, state.view);
    renderTree();
    $("status-selection").textContent = cls;
    loadSource(cls);
    loadClassInfo(cls);
    if (state.iview === "graph") loadGraph(cls);
    if (state.iview === "notes") fillNotes(cls);
    if (state.view === "bytecode") loadBytecode(cls);
    if (state.view === "diff") loadDiff();
    if (state.view === "audit") loadAudit();
    updateStatus();
  }

  async function loadSource(cls) {
    try {
      const res = await fetch("/api/source?class=" + encodeURIComponent(cls));
      const text = await res.text();
      if (cls !== currentData.selected) return;
      state.source = text;
      $("editor-meta").textContent = text.split("\n").length + " lines";
      renderSource(text);
      buildOutline(text);
    } catch (err) {
      $("code-lines").innerHTML = '<div class="empty">Failed to load source: ' + esc(err) + "</div>";
    }
  }

  /* --------------------------------------------------------------- source */
  const BLOCK =
    /^\s*(\/\*[\s\S]*?\*\/|\/\/.*)$/;
  const KEYWORDS = new Set(("abstract assert boolean break byte case catch char class const "
    + "continue default do double else enum extends final finally float for goto if "
    + "implements import instanceof int interface long native new package private protected "
    + "public return short static strictfp super switch synchronized this throw throws "
    + "transient try void volatile while true false null var record sealed permits yield").split(" "));

  function renderSource(text) {
    const target = $("code-lines");
    const frag = document.createDocumentFragment();
    const lines = text.split("\n");
    let inBlock = false;
    lines.forEach((line, idx) => {
      const row = document.createElement("div");
      row.className = "code-line";
      row.id = "line-" + (idx + 1);
      const no = document.createElement("span");
      no.className = "line-no";
      no.textContent = String(idx + 1);
      const code = document.createElement("span");
      code.className = "line-code";
      code.innerHTML = highlightJava(line, (v) => { inBlock = v; }, inBlock);
      row.appendChild(no);
      row.appendChild(code);
      frag.appendChild(row);
    });
    target.replaceChildren(frag);
  }

  function highlightJava(line, setBlock, blockStart) {
    let out = "";
    let i = 0;
    let block = blockStart;
    const push = (cls, text) => { out += '<span class="' + cls + '">' + esc(text) + "</span>"; };
    while (i < line.length) {
      if (block) {
        const end = line.indexOf("*/", i);
        if (end < 0) { push("tok-com", line.slice(i)); i = line.length; }
        else { push("tok-com", line.slice(i, end + 2)); i = end + 2; block = false; }
        setBlock(block);
        continue;
      }
      const rest = line.slice(i);
      const space = rest.match(/^\s+/);
      if (space) { out += space[0]; i += space[0].length; continue; }
      if (rest.startsWith("//")) { push("tok-com", rest); break; }
      if (rest.startsWith("/*")) {
        const end = rest.indexOf("*/", 2);
        if (end < 0) { push("tok-com", rest); block = true; setBlock(true); break; }
        push("tok-com", rest.slice(0, end + 2)); i += end + 2; continue;
      }
      const ch = rest[0];
      if (ch === '"' || ch === "'") {
        let j = 1;
        while (j < rest.length) {
          if (rest[j] === "\\") { j += 2; continue; }
          if (rest[j] === ch) { j += 1; break; }
          j += 1;
        }
        push("tok-str", rest.slice(0, j)); i += j; continue;
      }
      if (ch === "@") {
        const m = rest.match(/^@[A-Za-z_$][\w$.]*/);
        if (m) { push("tok-ann", m[0]); i += m[0].length; continue; }
      }
      if (/[0-9]/.test(ch)) {
        const m = rest.match(/^(?:0[xX][0-9a-fA-F]+|\d+(?:\.\d+)?(?:[eE][+-]?\d+)?[fFdDlL]?)/);
        if (m) { push("tok-num", m[0]); i += m[0].length; continue; }
      }
      const word = rest.match(/^[A-Za-z_$][\w$]*/);
      if (word) {
        const w = word[0];
        const after = rest.slice(w.length).match(/^\s*\(/);
        if (KEYWORDS.has(w)) push("tok-kw", w);
        else if (TYPE_WORDS.has(w) || /^[A-Z][A-Za-z0-9_$]*$/.test(w)) push("tok-type", w);
        else if (after) push("tok-fn", w);
        else out += esc(w);
        i += w.length;
        continue;
      }
      out += esc(ch);
      i += 1;
    }
    return out;
  }

  function buildOutline(text) {
    const items = [];
    const lines = text.split("\n");
    let block = false;
    lines.forEach((line, idx) => {
      let s = line;
      if (block) {
        const end = s.indexOf("*/");
        if (end < 0) return;
        s = s.slice(end + 2);
        block = false;
      }
      s = s.replace(/\/\*.*?\*\//g, "");
      const trimmed = s.trim();
      if (!trimmed || trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("@")) return;
      const type = trimmed.match(/\b(class|interface|enum|record)\s+([A-Za-z_$][\w$]*)/);
      if (type) {
        items.push({ kind: type[1], name: type[2], line: idx + 1, sig: trimmed.slice(0, 120) });
        return;
      }
      if (trimmed.indexOf("(") >= 0 && trimmed.indexOf(")") >= 0
          && !/^(if|for|while|switch|catch|return|new|throw|assert|try|else)\b/.test(trimmed)) {
        const m = trimmed.match(/([A-Za-z_$][\w$]*)\s*\(/);
        if (m) {
          items.push({ kind: "method", name: m[1], line: idx + 1, sig: trimmed.slice(0, 140) });
          return;
        }
      }
      const field = trimmed.match(/^(?:(?:public|private|protected|static|final|volatile|transient)\s+)*([A-Za-z_$][\w$<>\[\].]*)\s+([A-Za-z_$][\w$]*)\s*(?:=|;)/);
      if (field) items.push({ kind: "field", name: field[2], line: idx + 1, sig: trimmed.slice(0, 100) });
    });
    state.outline = items;
    renderOutline();
  }

  function renderOutline() {
    const filter = ($("outline-filter").value || "").toLowerCase();
    const items = state.outline.filter((it) => !filter
      || it.name.toLowerCase().indexOf(filter) >= 0
      || it.sig.toLowerCase().indexOf(filter) >= 0);
    const frag = document.createDocumentFragment();
    items.forEach((it) => {
      const row = document.createElement("div");
      row.className = "outline-item";
      row.innerHTML = '<span class="kind">' + esc(it.kind) + '</span><span class="sig">'
        + esc(it.sig) + '</span><span class="line-ref">' + it.line + "</span>";
      row.addEventListener("click", () => jumpToLine(it.line));
      frag.appendChild(row);
    });
    if (!items.length) {
      $("outline-list").innerHTML = '<div class="empty">No matching members.</div>';
    } else {
      $("outline-list").replaceChildren(frag);
    }
  }

  function jumpToLine(line) {
    switchView("source");
    const el = $("line-" + line);
    if (el) {
      el.scrollIntoView({ block: "center" });
      el.classList.add("target");
      setTimeout(() => el.classList.remove("target"), 1600);
    }
  }

  /* ------------------------------------------------------------- inspector */
  async function loadClassInfo(cls) {
    try {
      const res = await fetch("/api/class_info?class=" + encodeURIComponent(cls));
      const info = await res.json();
      if (cls !== currentData.selected) return;
      const tag = tagFor(cls) || {};
      const quality = info.quality || {};
      const score = quality.score != null ? quality.score
        : (info.score != null ? info.score : tag.score);
      const status = info.status || tag.status || "clean";
      const engine = info.engine || tag.engine || "-";
      let html = '<div class="card-title">' + esc(cls) + "</div>";
      html += '<div class="badge-row">';
      if (status === "failed") html += '<span class="tag-badge tag-failed">failed</span>';
      else if (status === "partial") html += '<span class="tag-badge tag-partial">partial</span>';
      else html += '<span class="tag-badge tag-engine">clean</span>';
      if (engine && engine !== "-") html += '<span class="tag-badge tag-engine">' + esc(engine) + "</span>";
      if (tag.native) html += '<span class="tag-badge tag-native">native ' + tag.native + "</span>";
      html += "</div>";
      html += '<dl class="kv">'
        + "<dt>status</dt><dd>" + esc(status) + "</dd>"
        + "<dt>engine</dt><dd>" + esc(engine) + "</dd>"
        + "<dt>score</dt><dd>" + (score != null ? esc(score) : "-") + "</dd>"
        + "<dt>source</dt><dd>" + esc(cls + ".java") + "</dd>"
        + "</dl>";
      $("class-meta").innerHTML = html;
      const attempts = (info.attempts || []).join(", ");
      $("class-engine-info").innerHTML = '<div class="card-title">Engine & Quality</div>'
        + '<dl class="kv"><dt>winner</dt><dd>' + esc(engine) + "</dd>"
        + "<dt>attempts</dt><dd>" + esc(attempts || "-") + "</dd>"
        + "<dt>quality</dt><dd>" + (score != null ? esc(score) : "-") + "</dd></dl>";
      renderClassStrings(info.strings || []);
      updateStatus();
    } catch (err) {
      if (cls === currentData.selected) {
        $("class-meta").textContent = "Failed to load class info: " + err;
      }
    }
  }

  function renderClassStrings(strings) {
    if (!strings || !strings.length) {
      $("class-strings").innerHTML = '<div class="muted">No tagged strings for this class.</div>';
      return;
    }
    $("class-strings").innerHTML = strings.slice(0, 30).map((s) => {
      const value = typeof s === "string" ? s : (s.string || "");
      const tags = (typeof s === "string" ? [] : (s.tags || [])).join(", ");
      return '<div class="string-item">' + esc(value)
        + (tags ? '<div class="string-tags">' + esc(tags) + "</div>" : "") + "</div>";
    }).join("");
  }

  async function loadGraph(cls) {
    if (state.graphFor === cls) return;
    state.graphFor = cls;
    $("callgraph-body").innerHTML = '<div class="empty">Building callgraph ...</div>';
    try {
      const res = await fetch("/api/callgraph?class=" + encodeURIComponent(cls));
      const data = await res.json();
      if (cls !== currentData.selected) return;
      if (data.error) {
        $("callgraph-body").innerHTML = '<div class="empty">' + esc(data.error) + "</div>";
        return;
      }
      let html = "";
      const reach = data.reachable;
      html += '<div class="graph-section"><h4>Reachability</h4><span class="'
        + (reach === true ? "reach-yes" : reach === false ? "reach-no" : "reach-unknown") + '">'
        + (reach === true ? "reachable from an entrypoint" : reach === false ? "not reachable" : "unknown (no entrypoints)")
        + "</span></div>";
      html += renderGraphList("Callers", data.callers, "caller");
      html += renderGraphList("Callees", data.callees, "callee");
      if (data.path && data.path.length) {
        html += '<div class="graph-section"><h4>Entry path</h4>' + data.path.map((p) => {
          return '<div class="graph-link"><span class="graph-op">' + esc(p.opcode || "") + "</span>"
            + esc(p.from || p.caller || "") + " -> " + esc(p.to || p.callee || "") + "</div>";
        }).join("") + "</div>";
      }
      $("callgraph-body").innerHTML = html;
      Array.prototype.forEach.call($("callgraph-body").querySelectorAll("[data-class]"), (el) => {
        el.addEventListener("click", () => {
          const target = el.getAttribute("data-class");
          if (currentData.classes.indexOf(target) >= 0) selectClass(target);
          else toast("Class not in this output: " + target);
        });
      });
    } catch (err) {
      if (cls === currentData.selected) {
        $("callgraph-body").innerHTML = '<div class="empty">Callgraph unavailable: ' + esc(err) + "</div>";
      }
    }
  }

  function renderGraphList(title, rows, key) {
    if (!rows || !rows.length) {
      return '<div class="graph-section"><h4>' + title + '</h4><span class="muted">None detected.</span></div>';
    }
    return '<div class="graph-section"><h4>' + title + "</h4>" + rows.map((r) => {
      const name = r[key] || "";
      const cls = name.split(":")[0].split("#")[0];
      return '<div class="graph-link" data-class="' + esc(cls) + '"><span class="graph-op">'
        + esc(r.opcode || "") + "</span>" + esc(name) + "</div>";
    }).join("") + "</div>";
  }

  /* ---------------------------------------------------------- bytecode/diff */
  async function loadBytecode(cls) {
    const target = $("bytecode-body");
    if (state.bytecodeCache[cls]) { target.innerHTML = state.bytecodeCache[cls]; return; }
    target.innerHTML = '<div class="empty">Running javap ...</div>';
    try {
      const apiClass = currentData.names[cls] || cls;
      const res = await fetch("/api/bytecode?class=" + encodeURIComponent(apiClass));
      const data = await res.json();
      if (cls !== currentData.selected) return;
      const html = data.ok
        ? '<pre class="bytecode-pre">' + esc(data.bytecode) + "</pre>"
        : '<div class="empty">' + esc(data.error || "Bytecode unavailable") + "</div>";
      state.bytecodeCache[cls] = html;
      target.innerHTML = html;
    } catch (err) {
      target.innerHTML = '<div class="empty">Bytecode unavailable: ' + esc(err) + "</div>";
    }
  }

  async function loadDiff() {
    const cls = currentData.selected;
    if (!cls) return;
    const e1 = $("diff-e1").value;
    const e2 = $("diff-e2").value;
    const key = cls + "|" + e1 + "|" + e2;
    const target = $("diff-body");
    if (state.diffCache[key]) { target.innerHTML = state.diffCache[key]; return; }
    target.innerHTML = '<div class="empty">Building diff ...</div>';
    try {
      const res = await fetch("/api/diff?class=" + encodeURIComponent(cls)
        + "&e1=" + encodeURIComponent(e1) + "&e2=" + encodeURIComponent(e2));
      const data = await res.json();
      $("diff-stats").textContent = data.identical
        ? "identical" : "+" + data.stats.added + " / -" + data.stats.removed;
      const lines = String(data.diff || "").split("\n");
      const html = '<pre class="diff-pre">' + lines.map((line) => {
        let cls2 = "diff-line";
        if (line.startsWith("+++") || line.startsWith("---")) cls2 += " meta";
        else if (line.startsWith("@@")) cls2 += " hunk";
        else if (line.startsWith("+")) cls2 += " add";
        else if (line.startsWith("-")) cls2 += " del";
        const mark = line.slice(0, 1);
        return '<div class="' + cls2 + '"><span class="mark">' + esc(mark) + "</span>"
          + esc(line.slice(1)) + "</div>";
      }).join("") + "</pre>";
      state.diffCache[key] = html;
      target.innerHTML = html;
    } catch (err) {
      target.innerHTML = '<div class="empty">Diff unavailable: ' + esc(err) + "</div>";
    }
  }

  /* ------------------------------------------------------------------ audit */
  async function loadAudit() {
    if (state.auditLoaded) return;
    const targets = [["/api/report", "report-body"], ["/api/natives", "natives-body"], ["/api/threats", "threats-body"]];
    await Promise.all(targets.map(async (pair) => {
      try {
        const res = await fetch(pair[0]);
        const text = await res.text();
        $(pair[1]).textContent = text;
      } catch (err) {
        $(pair[1]).textContent = "Failed to load: " + err;
      }
    }));
    state.auditLoaded = true;
  }

  /* --------------------------------------------------------------- notes/LLM */
  function fillNotes(cls) {
    const ann = annotationFor(cls) || {};
    $("audit-tag").value = ann.tag || "";
    $("audit-note").value = ann.note || "";
    $("audit-status").textContent = ann.updated_at ? "saved " + ann.updated_at : "";
  }

  async function saveNote() {
    const cls = currentData.selected;
    if (!cls) return;
    try {
      const res = await fetch("/api/annotations", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ class: cls, tag: $("audit-tag").value, note: $("audit-note").value.trim() }),
      });
      const data = await res.json();
      if (!data.ok) throw new Error(data.error || "save failed");
      currentData.annotations = data.annotations || {};
      updateCounts();
      renderTree();
      fillNotes(cls);
      toast("Note saved");
    } catch (err) {
      $("audit-status").textContent = "save failed";
      toast("Save failed: " + err);
    }
  }

  async function clearNote() {
    const cls = currentData.selected;
    if (!cls) return;
    try {
      const res = await fetch("/api/annotations", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ class: cls, tag: "", note: "" }),
      });
      const data = await res.json();
      if (!data.ok) throw new Error(data.error || "clear failed");
      currentData.annotations = data.annotations || {};
      updateCounts();
      renderTree();
      fillNotes(cls);
      toast("Note cleared");
    } catch (err) { toast("Clear failed: " + err); }
  }

  async function openLlm() {
    const cls = currentData.selected;
    if (!cls) return;
    try {
      const res = await fetch("/api/llm_prompt?class=" + encodeURIComponent(cls));
      const data = await res.json();
      $("llm-prompt").value = data.prompt || "";
      $("llm-meta").textContent = (data.candidate_count || 0) + " rename candidates / "
        + (data.line_count || 0) + " source lines";
      $("llm-modal").hidden = false;
      $("llm-prompt").focus();
    } catch (err) { toast("Prompt failed: " + err); }
  }

  /* --------------------------------------------------------------- palette */
  function openPalette() {
    $("palette-modal").hidden = false;
    $("palette-input").value = "";
    state.paletteIndex = 0;
    renderPalette("");
    $("palette-input").focus();
  }

  function closePalette() { $("palette-modal").hidden = true; }

  function renderPalette(query) {
    const q = (query || "").trim().toLowerCase();
    const list = currentData.classes.filter((cls) => {
      if (!q) return true;
      const name = currentData.names[cls] || cls;
      return name.toLowerCase().indexOf(q) >= 0 || cls.toLowerCase().indexOf(q) >= 0;
    }).slice(0, 80);
    state.paletteItems = list;
    if (state.paletteIndex >= list.length) state.paletteIndex = Math.max(0, list.length - 1);
    $("palette-list").innerHTML = list.length ? list.map((cls, idx) => {
      const tag = tagFor(cls);
      const label = currentData.names[cls] || cls;
      return '<div class="palette-item' + (idx === state.paletteIndex ? " sel" : "")
        + '" data-idx="' + idx + '">'
        + (tag && tag.status ? '<span class="tag-badge tag-' + tag.status + '">' + tag.status + "</span>" : "")
        + "<span>" + esc(label) + "</span></div>";
    }).join("") : '<div class="empty">No matching class.</div>';
    Array.prototype.forEach.call($("palette-list").querySelectorAll("[data-idx]"), (el) => {
      el.addEventListener("click", () => {
        const cls = state.paletteItems[Number(el.getAttribute("data-idx"))];
        closePalette();
        selectClass(cls);
      });
    });
  }

  function paletteMove(delta) {
    if (!state.paletteItems.length) return;
    state.paletteIndex = (state.paletteIndex + delta + state.paletteItems.length) % state.paletteItems.length;
    renderPalette($("palette-input").value);
    const sel = $("palette-list").querySelector(".sel");
    if (sel) sel.scrollIntoView({ block: "nearest" });
  }

  function paletteChoose() {
    const cls = state.paletteItems[state.paletteIndex];
    if (!cls) return;
    closePalette();
    selectClass(cls);
  }

  /* ------------------------------------------------------------------ views */
  function switchView(view) {
    state.view = view;
    Array.prototype.forEach.call(document.querySelectorAll("#main-tabs .tab"), (tab) => {
      tab.classList.toggle("active", tab.getAttribute("data-view") === view);
    });
    ["source", "diff", "bytecode", "audit"].forEach((name) => {
      $("view-" + name).classList.toggle("active", name === view);
    });
    if (currentData.selected) updateHash(currentData.selected, view);
    if (view === "bytecode" && currentData.selected) loadBytecode(currentData.selected);
    if (view === "diff" && currentData.selected) loadDiff();
    if (view === "audit") loadAudit();
  }

  function switchIView(name) {
    state.iview = name;
    Array.prototype.forEach.call(document.querySelectorAll("#inspector-tabs .tab"), (tab) => {
      tab.classList.toggle("active", tab.getAttribute("data-iview") === name);
    });
    ["overview", "members", "graph", "notes"].forEach((v) => {
      $("iview-" + v).classList.toggle("active", v === name);
    });
    if (name === "members") renderOutline();
    if (name === "graph" && currentData.selected) loadGraph(currentData.selected);
    if (name === "notes") fillNotes(currentData.selected);
  }

  function updateStatus() {
    const cls = currentData.selected;
    if (!cls) { $("status-selection").textContent = "no selection"; return; }
    const tag = tagFor(cls) || {};
    const bits = [cls];
    if (tag.status) bits.push(tag.status);
    if (tag.engine) bits.push(tag.engine);
    if (tag.native) bits.push(tag.native + " native");
    $("status-selection").textContent = bits.join("  /  ");
  }

  /* --------------------------------------------------------------- settings */
  function applyWrap(wrap) {
    state.wrap = wrap;
    document.body.classList.toggle("wrap", wrap);
    $("btn-wrap").textContent = wrap ? "No wrap" : "Wrap";
    localStorage.setItem("jdec.wrap", wrap ? "1" : "0");
  }

  function setupSplitter(el, varName, storageKey, min, max) {
    el.addEventListener("pointerdown", (event) => {
      event.preventDefault();
      el.setPointerCapture(event.pointerId);
      const startX = event.clientX;
      const start = parseInt(getComputedStyle(document.documentElement).getPropertyValue(varName), 10) || 300;
      const onMove = (e) => {
        let next = start + (e.clientX - startX);
        next = Math.max(min, Math.min(max, next));
        document.documentElement.style.setProperty(varName, next + "px");
      };
      const onUp = () => {
        el.removeEventListener("pointermove", onMove);
        el.removeEventListener("pointerup", onUp);
        const value = parseInt(getComputedStyle(document.documentElement).getPropertyValue(varName), 10) || 300;
        localStorage.setItem(storageKey, String(value));
      };
      el.addEventListener("pointermove", onMove);
      el.addEventListener("pointerup", onUp);
    });
  }

  function restoreLayout() {
    const sidebar = parseInt(localStorage.getItem("jdec.sidebar") || "300", 10);
    const inspector = parseInt(localStorage.getItem("jdec.inspector") || "360", 10);
    document.documentElement.style.setProperty("--sidebar-w", sidebar + "px");
    document.documentElement.style.setProperty("--inspector-w", inspector + "px");
    applyWrap(localStorage.getItem("jdec.wrap") === "1");
  }

  /* ---------------------------------------------------------------- bindings */
  function bind() {
    $("class-filter").addEventListener("input", debounce(() => {
      state.query = $("class-filter").value;
      applyFilter();
    }, 80));
    $("tree-scroll").addEventListener("scroll", () => renderTree());
    Array.prototype.forEach.call(document.querySelectorAll(".filter-pills .pill"), (btn) => {
      btn.addEventListener("click", () => {
        state.filter = btn.getAttribute("data-filter");
        Array.prototype.forEach.call(document.querySelectorAll(".filter-pills .pill"), (b) => {
          b.classList.toggle("active", b === btn);
        });
        applyFilter();
      });
    });
    Array.prototype.forEach.call(document.querySelectorAll("#main-tabs .tab"), (tab) => {
      tab.addEventListener("click", () => switchView(tab.getAttribute("data-view")));
    });
    Array.prototype.forEach.call(document.querySelectorAll("#inspector-tabs .tab"), (tab) => {
      tab.addEventListener("click", () => switchIView(tab.getAttribute("data-iview")));
    });
    $("outline-filter").addEventListener("input", debounce(renderOutline, 80));
    $("btn-diff").addEventListener("click", loadDiff);
    $("diff-e1").addEventListener("change", loadDiff);
    $("diff-e2").addEventListener("change", loadDiff);
    $("btn-save-note").addEventListener("click", saveNote);
    $("btn-clear-note").addEventListener("click", clearNote);
    $("btn-llm").addEventListener("click", openLlm);
    $("btn-llm-copy").addEventListener("click", async () => {
      try { await navigator.clipboard.writeText($("llm-prompt").value); toast("Prompt copied"); }
      catch (err) { $("llm-prompt").select(); document.execCommand("copy"); toast("Prompt copied"); }
    });
    $("btn-llm-close").addEventListener("click", () => { $("llm-modal").hidden = true; });
    $("btn-llm-dismiss").addEventListener("click", () => { $("llm-modal").hidden = true; });
    $("btn-help").addEventListener("click", () => { $("help-modal").hidden = false; });
    $("btn-help-close").addEventListener("click", () => { $("help-modal").hidden = true; });
    $("palette-trigger").addEventListener("click", openPalette);
    $("palette-input").addEventListener("input", () => {
      state.paletteIndex = 0;
      renderPalette($("palette-input").value);
    });
    $("palette-input").addEventListener("keydown", (event) => {
      if (event.key === "ArrowDown") { event.preventDefault(); paletteMove(1); }
      else if (event.key === "ArrowUp") { event.preventDefault(); paletteMove(-1); }
      else if (event.key === "Enter") { event.preventDefault(); paletteChoose(); }
      else if (event.key === "Escape") { closePalette(); }
    });
    $("palette-modal").addEventListener("click", (event) => {
      if (event.target === $("palette-modal")) closePalette();
    });
    $("help-modal").addEventListener("click", (event) => {
      if (event.target === $("help-modal")) $("help-modal").hidden = true;
    });
    $("btn-copy").addEventListener("click", async () => {
      try { await navigator.clipboard.writeText(state.source || ""); toast("Source copied"); }
      catch (err) { toast("Copy failed"); }
    });
    $("btn-wrap").addEventListener("click", () => applyWrap(!state.wrap));
    $("btn-export").addEventListener("click", exportProject);

    document.addEventListener("keydown", (event) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault(); openPalette(); return;
      }
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "s") {
        event.preventDefault(); saveNote(); return;
      }
      if (event.key === "F1") { event.preventDefault(); $("help-modal").hidden = false; return; }
      const tag = (event.target.tagName || "").toLowerCase();
      const typing = tag === "input" || tag === "textarea" || tag === "select";
      if (event.key === "Escape") {
        closePalette();
        $("llm-modal").hidden = true;
        $("help-modal").hidden = true;
        return;
      }
      if (!typing && /^[1-4]$/.test(event.key)) {
        switchView(["source", "diff", "bytecode", "audit"][Number(event.key) - 1]);
      }
      if (!typing && event.key === "/") {
        event.preventDefault();
        $("class-filter").focus();
      }
    });

    setupSplitter($("split-left"), "--sidebar-w", "jdec.sidebar", 220, 520);
    setupSplitter($("split-right"), "--inspector-w", "jdec.inspector", 280, 620);
  }

  async function exportProject() {
    $("btn-export").disabled = true;
    try {
      const res = await fetch("/api/export_project");
      const data = await res.json();
      if (!data.ok) throw new Error(data.error || "export failed");
      toast("Exported to " + data.project_dir, 5000);
    } catch (err) {
      toast("Export failed: " + err, 5000);
    } finally {
      $("btn-export").disabled = false;
    }
  }

  window.addEventListener("hashchange", () => {
    const wanted = readHash();
    if (wanted.c && wanted.c !== currentData.selected) selectClass(wanted.c, true);
    if (wanted.v) switchView(wanted.v);
  });

  bind();
  restoreLayout();
  loadTree();
})();
