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
from . import engines as EN
from . import rename as RN
from . import callgraph as CG

_CG_CACHE: dict[str, tuple[CG.CallGraph, CG.ReachabilityReport]] = {}

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
    --purple: #b48ead;
    --teal: #8fbcbb;
    --border: #383842;
    --code-bg: #141418;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; }
  body { background: var(--bg-dark); color: var(--text-main); height: 100vh; display: flex; flex-direction: column; overflow: hidden; }
  header { background: var(--bg-side); border-bottom: 1px solid var(--border); padding: 10px 20px; display: flex; align-items: center; justify-content: space-between; }
  header h1 { font-size: 1.15rem; font-weight: 700; color: var(--accent-hover); display: flex; align-items: center; gap: 8px; }
  header .badge { background: var(--bg-card); border: 1px solid var(--border); padding: 3px 8px; border-radius: 4px; font-size: 0.8rem; color: var(--text-muted); }
  .layout { display: flex; flex: 1; height: calc(100vh - 48px); }
  .sidebar { width: 320px; background: var(--bg-side); border-right: 1px solid var(--border); display: flex; flex-direction: column; }
  .search-box { padding: 10px; border-bottom: 1px solid var(--border); }
  .search-box input { width: 100%; background: var(--bg-card); border: 1px solid var(--border); border-radius: 4px; padding: 6px 10px; color: var(--text-main); outline: none; font-size: 0.85rem; }
  .filter-pills { display: flex; gap: 4px; padding: 6px 10px; border-bottom: 1px solid var(--border); background: rgba(0,0,0,0.1); }
  .pill { background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; color: var(--text-muted); font-size: 0.75rem; padding: 2px 8px; cursor: pointer; }
  .pill:hover { color: var(--text-main); }
  .pill.active { background: var(--accent); color: #fff; border-color: var(--accent); font-weight: 600; }
  .tree-list { flex: 1; overflow-y: auto; padding: 8px; font-size: 0.85rem; }
  .tree-item { padding: 5px 8px; border-radius: 4px; cursor: pointer; display: flex; align-items: center; justify-content: space-between; color: var(--text-muted); }
  .tree-item:hover { background: var(--bg-card); color: var(--text-main); }
  .tree-item.active { background: var(--accent); color: #fff; font-weight: 600; }
  .tree-label { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex: 1; }
  .tag-badge { font-size: 0.7rem; padding: 1px 5px; border-radius: 3px; margin-left: 6px; font-weight: 600; flex-shrink: 0; }
  .tag-suspect { background: rgba(235,203,139,0.25); color: #ebcb8b; border: 1px solid #ebcb8b; }
  .tag-threat { background: rgba(191,97,106,0.25); color: #bf616a; border: 1px solid #bf616a; }
  .tag-core { background: rgba(129,161,193,0.25); color: #81a1c1; border: 1px solid #81a1c1; }
  .tag-net { background: rgba(180,142,173,0.25); color: #b48ead; border: 1px solid #b48ead; }
  .tag-hook { background: rgba(143,188,187,0.25); color: #8fbcbb; border: 1px solid #8fbcbb; }
  .tag-benign { background: rgba(163,190,140,0.25); color: #a3be8c; border: 1px solid #a3be8c; }
  .main-pane { flex: 1; display: flex; flex-direction: column; background: var(--bg-dark); overflow: hidden; }
  .tabs-bar { background: var(--bg-side); border-bottom: 1px solid var(--border); display: flex; gap: 2px; padding: 0 10px; }
  .tab-btn { background: transparent; border: none; border-bottom: 2px solid transparent; color: var(--text-muted); padding: 8px 14px; font-size: 0.85rem; cursor: pointer; }
  .tab-btn:hover { color: var(--text-main); }
  .tab-btn.active { color: var(--accent-hover); border-bottom-color: var(--accent-hover); font-weight: 600; }
  .content-area { flex: 1; display: flex; overflow: hidden; position: relative; }
  .code-view { flex: 1; background: var(--code-bg); padding: 15px; overflow: auto; font-family: "Consolas", "Courier New", monospace; font-size: 0.88rem; line-height: 1.45; white-space: pre; color: #d8dee9; }
  .diff-view { flex: 1; display: none; flex-direction: column; background: var(--code-bg); overflow: hidden; }
  .diff-toolbar { padding: 8px 15px; background: var(--bg-side); border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 10px; font-size: 0.85rem; }
  .diff-toolbar select { background: var(--bg-card); color: var(--text-main); border: 1px solid var(--border); border-radius: 4px; padding: 4px 8px; font-size: 0.82rem; outline: none; }
  .diff-content { flex: 1; overflow: auto; padding: 12px; font-family: "Consolas", monospace; font-size: 0.88rem; line-height: 1.4; white-space: pre; }
  .diff-line { font-family: "Consolas", monospace; white-space: pre-wrap; padding: 1px 6px; }
  .diff-line.add { background: rgba(163, 190, 140, 0.18); color: #a3be8c; }
  .diff-line.del { background: rgba(191, 97, 106, 0.18); color: #bf616a; }
  .diff-line.chunk { background: rgba(94, 129, 172, 0.15); color: #88c0d0; font-weight: 600; }
  .diff-line.hdr { color: #81a1c1; font-weight: 600; }
  .diff-line.ctx { color: #abb2bf; }
  .inspector { width: 340px; background: var(--bg-side); border-left: 1px solid var(--border); overflow-y: auto; padding: 15px; font-size: 0.85rem; }
  .inspector h3 { font-size: 0.85rem; color: var(--text-muted); text-transform: uppercase; margin-bottom: 8px; border-bottom: 1px solid var(--border); padding-bottom: 4px; font-weight: 700; letter-spacing: 0.5px; }
  .inspector .sec { margin-bottom: 16px; }
  .card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 4px; padding: 8px 10px; margin-bottom: 8px; }
  .tag { display: inline-block; font-size: 0.75rem; padding: 2px 6px; border-radius: 3px; background: var(--border); color: var(--text-main); margin-right: 4px; margin-bottom: 4px; }
  .tag.danger { background: rgba(191,97,106,0.25); color: var(--danger); border: 1px solid var(--danger); }
  .tag.warning { background: rgba(235,203,139,0.25); color: var(--warning); border: 1px solid var(--warning); }
  .btn { background: var(--bg-card); border: 1px solid var(--border); color: var(--text-main); padding: 5px 10px; border-radius: 4px; cursor: pointer; font-size: 0.82rem; transition: all 0.15s; }
  .btn:hover { background: var(--border); border-color: var(--accent); }
  .btn-primary { background: var(--accent); color: #fff; border-color: var(--accent); font-weight: 600; }
  .btn-primary:hover { background: var(--accent-hover); }
  .btn-ghost { background: transparent; border-color: var(--border); color: var(--text-muted); }
  .btn-ghost:hover { color: var(--text-main); border-color: var(--text-muted); }
  .btn-ai { background: linear-gradient(135deg, #5e81ac, #b48ead); color: #fff; border: none; font-weight: 600; width: 100%; padding: 8px 12px; margin-top: 6px; border-radius: 4px; cursor: pointer; transition: opacity 0.15s; }
  .btn-ai:hover { opacity: 0.92; }
  /* Modal dialog */
  .modal-overlay { display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0, 0, 0, 0.72); backdrop-filter: blur(4px); z-index: 1000; align-items: center; justify-content: center; }
  .modal-overlay.active { display: flex; }
  .modal-box { background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; width: 750px; max-width: 92vw; max-height: 85vh; display: flex; flex-direction: column; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
  .modal-hdr { padding: 14px 20px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; }
  .modal-hdr h2 { font-size: 1.05rem; color: var(--accent-hover); }
  .modal-body { padding: 15px 20px; flex: 1; overflow-y: auto; display: flex; flex-direction: column; gap: 8px; }
  .modal-body textarea { width: 100%; height: 340px; background: var(--code-bg); color: #e5e9f0; border: 1px solid var(--border); border-radius: 4px; padding: 10px; font-family: "Consolas", monospace; font-size: 0.85rem; resize: vertical; line-height: 1.45; }
  .modal-ftr { padding: 12px 20px; border-top: 1px solid var(--border); display: flex; justify-content: flex-end; gap: 10px; align-items: center; }
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
      <div class="filter-pills">
        <button class="pill active" id="pill-all" onclick="setTreeFilter('all')">All</button>
        <button class="pill" id="pill-tagged" onclick="setTreeFilter('tagged')">Tagged</button>
        <button class="pill" id="pill-suspect" onclick="setTreeFilter('suspect')">⚠️ Suspects</button>
      </div>
      <div class="tree-list" id="class-tree"></div>
    </div>
    <div class="main-pane">
      <div class="tabs-bar">
        <button class="tab-btn active" onclick="switchView('decompiled')">Decompiled Source</button>
        <button class="tab-btn" onclick="switchView('diff')">Engine Diff</button>
        <button class="tab-btn" onclick="switchView('natives')">Native C Code</button>
        <button class="tab-btn" onclick="switchView('threats')">Threats & Strings</button>
        <button class="tab-btn" onclick="switchView('report')">Triage Report</button>
      </div>
      <div class="content-area">
        <div class="code-view" id="code-content">// Select a class from the left sidebar to view decompiled code.</div>
        <div class="diff-view" id="diff-view">
          <div class="diff-toolbar">
            <span>Engine 1:</span>
            <select id="diff-e1" onchange="fetchDiff()">
              <option value="final" selected>Final (Winner)</option>
              <option value="cfr">CFR 0.152</option>
              <option value="vineflower">Vineflower</option>
              <option value="procyon">Procyon</option>
            </select>
            <span>vs Engine 2:</span>
            <select id="diff-e2" onchange="fetchDiff()">
              <option value="cfr" selected>CFR 0.152</option>
              <option value="vineflower">Vineflower</option>
              <option value="procyon">Procyon</option>
              <option value="final">Final (Winner)</option>
            </select>
            <button class="btn btn-primary" onclick="fetchDiff()">Compare</button>
            <span id="diff-stats" class="badge"></span>
          </div>
          <div class="diff-content" id="diff-content">// Select a class and engines to compare diff.</div>
        </div>
        <div class="inspector" id="inspector-content">
          <div class="sec">
            <h3>Class Information</h3>
            <div id="class-meta" class="card">No class selected</div>
          </div>
          <div class="sec">
            <h3>Engine & Quality</h3>
            <div id="class-engine-info" class="card">Loading engine details ...</div>
          </div>
          <div class="sec">
            <h3>Audit & Triage Notes</h3>
            <div class="card">
              <div style="margin-bottom:8px;">
                <label style="font-size:0.75rem; color:var(--text-muted); display:block; margin-bottom:3px;">TAG</label>
                <select id="audit-tag" style="width:100%; background:var(--bg-dark); color:var(--text-main); border:1px solid var(--border); border-radius:4px; padding:4px 6px; font-size:0.82rem; outline:none;">
                  <option value="">-- No Tag --</option>
                  <option value="suspect">⚠️ Suspect (存疑)</option>
                  <option value="core">🔒 Core Logic (核心)</option>
                  <option value="net">🌐 Network / C2 (通信)</option>
                  <option value="threat">💣 Threat / Malicious (恶意)</option>
                  <option value="hook">🪝 Mixin / Hook (挂钩)</option>
                  <option value="benign">✅ Benign / Normal (正常)</option>
                </select>
              </div>
              <div style="margin-bottom:8px;">
                <label style="font-size:0.75rem; color:var(--text-muted); display:block; margin-bottom:3px;">INVESTIGATOR NOTE (CTRL+S)</label>
                <textarea id="audit-note" rows="4" style="width:100%; background:var(--bg-dark); color:var(--text-main); border:1px solid var(--border); border-radius:4px; padding:6px; font-size:0.82rem; resize:vertical; outline:none;" placeholder="Write observations or notes (Ctrl+S to save)..."></textarea>
              </div>
              <div style="display:flex; justify-content:space-between; align-items:center;">
                <button class="btn btn-primary" onclick="saveAuditNote()">💾 Save Note</button>
                <button class="btn btn-ghost" onclick="clearAuditNote()">Clear</button>
                <span id="audit-status" style="font-size:0.75rem; color:var(--text-muted);"></span>
              </div>
            </div>
            <button class="btn-ai" onclick="openLlmPromptModal()">🤖 AI Semantic Rename Prompt</button>
          </div>
          <div class="sec">
            <h3>Mixin Hooks</h3>
            <div id="class-hooks" class="card">None detected</div>
          </div>
          <div class="sec">
            <h3>Strings & Identifiers</h3>
            <div id="class-strings" class="card">None detected</div>
          </div>
          <div class="sec">
            <h3>Call Graph & Reachability</h3>
            <div class="card" id="class-reach-card">
              <div id="class-reach-badge" style="margin-bottom:8px;">Analyzing reachability ...</div>
              <div id="class-reach-path" style="display:none; margin-bottom:8px; font-size:0.78rem; background:rgba(0,0,0,0.25); padding:6px; border-radius:4px; border-left:2px solid var(--accent-hover);"></div>
              <div style="font-size:0.75rem; color:var(--text-muted); margin-bottom:3px; font-weight:600;">CALLERS (Incoming)</div>
              <div id="class-callers" style="margin-bottom:8px; font-size:0.8rem; max-height:110px; overflow-y:auto; line-height:1.4;">None detected</div>
              <div style="font-size:0.75rem; color:var(--text-muted); margin-bottom:3px; font-weight:600;">CALLEES (Outgoing)</div>
              <div id="class-callees" style="font-size:0.8rem; max-height:110px; overflow-y:auto; line-height:1.4;">None detected</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- LLM Prompt Modal -->
  <div class="modal-overlay" id="llm-modal">
    <div class="modal-box">
      <div class="modal-hdr">
        <h2 id="llm-modal-title">🤖 AI Semantic Rename Prompt</h2>
        <button class="btn btn-ghost" onclick="closeLlmModal()">&times;</button>
      </div>
      <div class="modal-body">
        <p style="font-size:0.82rem; color:var(--text-muted);">
          Copy this prompt into Claude, Gemini, or ChatGPT to analyze obfuscated logic and receive a standard ProGuard mapping block.
        </p>
        <textarea id="llm-prompt-text" readonly></textarea>
      </div>
      <div class="modal-ftr">
        <span id="copy-status" style="font-size:0.82rem; color:var(--success); display:none;">✓ Copied to clipboard!</span>
        <button class="btn btn-primary" id="btn-copy-prompt" onclick="copyLlmPrompt()">📋 Copy Prompt</button>
        <button class="btn btn-ghost" onclick="closeLlmModal()">Close</button>
      </div>
    </div>
  </div>

  <script>
    let currentData = {
      classes: [],
      selected: null,
      currentView: 'decompiled',
      annotations: {},
      treeFilter: 'all'
    };

    const TAG_MAP = {
      'suspect': { icon: '⚠️', label: '存疑', cls: 'tag-suspect' },
      'threat':  { icon: '💣', label: '恶意', cls: 'tag-threat' },
      'core':    { icon: '🔒', label: '核心', cls: 'tag-core' },
      'net':     { icon: '🌐', label: '通信', cls: 'tag-net' },
      'hook':    { icon: '🪝', label: 'Hook', cls: 'tag-hook' },
      'benign':  { icon: '✅', label: '正常', cls: 'tag-benign' }
    };

    async function loadTree() {
      try {
        const [resTree, resAnn] = await Promise.all([
          fetch('/api/tree'),
          fetch('/api/annotations').catch(() => ({ json: () => ({}) }))
        ]);
        const data = await resTree.json();
        currentData.annotations = (await resAnn.json()) || {};
        currentData.classes = data.classes || [];
        document.getElementById('target-summary').innerText = (data.target || 'target') + ' (' + currentData.classes.length + ' classes)';
        filterAndRenderTree();
        if (currentData.classes.length > 0) {
          selectClass(currentData.classes[0]);
        }
      } catch (e) {
        document.getElementById('code-content').innerText = 'Failed to load project: ' + e;
      }
    }

    function setTreeFilter(type) {
      currentData.treeFilter = type;
      document.querySelectorAll('.filter-pills .pill').forEach(btn => {
        btn.classList.toggle('active', btn.id === 'pill-' + type);
      });
      filterAndRenderTree();
    }

    function filterAndRenderTree() {
      const q = (document.getElementById('class-filter').value || '').toLowerCase();
      let list = currentData.classes.filter(c => c.toLowerCase().includes(q));
      if (currentData.treeFilter === 'tagged') {
        list = list.filter(c => Boolean(currentData.annotations[c] && (currentData.annotations[c].tag || currentData.annotations[c].note)));
      } else if (currentData.treeFilter === 'suspect') {
        list = list.filter(c => {
          const ann = currentData.annotations[c];
          return ann && (ann.tag === 'suspect' || ann.tag === 'threat');
        });
      }
      renderTree(list);
    }

    function renderTree(list) {
      const container = document.getElementById('class-tree');
      container.innerHTML = '';
      list.forEach(cls => {
        const el = document.createElement('div');
        el.className = 'tree-item' + (currentData.selected === cls ? ' active' : '');

        const label = document.createElement('span');
        label.className = 'tree-label';
        label.innerText = cls;
        el.appendChild(label);

        const ann = currentData.annotations[cls];
        if (ann && ann.tag && TAG_MAP[ann.tag]) {
          const tagInfo = TAG_MAP[ann.tag];
          const badge = document.createElement('span');
          badge.className = 'tag-badge ' + tagInfo.cls;
          badge.innerText = tagInfo.icon + ' ' + tagInfo.label;
          el.appendChild(badge);
        }

        el.onclick = () => selectClass(cls);
        container.appendChild(el);
      });
    }

    document.getElementById('class-filter').oninput = () => {
      filterAndRenderTree();
    };

    function esc(s) {
      return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    async function selectClass(cls) {
      currentData.selected = cls;
      filterAndRenderTree();
      document.getElementById('class-meta').innerHTML = '<b>' + esc(cls) + '</b>';

      // Load audit annotations
      const noteData = currentData.annotations[cls] || {};
      document.getElementById('audit-tag').value = noteData.tag || '';
      document.getElementById('audit-note').value = noteData.note || '';
      document.getElementById('audit-status').innerText = noteData.updated_at ? ('Saved ' + noteData.updated_at.split(' ')[1]) : '';

      // Load decompiled source
      if (currentData.currentView === 'decompiled') {
        const res = await fetch('/api/source?class=' + encodeURIComponent(cls));
        const code = await res.text();
        document.getElementById('code-content').innerText = code;
      } else if (currentData.currentView === 'diff') {
        fetchDiff();
      }

      // Load class metadata & engine info
      const metaRes = await fetch('/api/class_info?class=' + encodeURIComponent(cls));
      const meta = await metaRes.json();
      
      let engText = '<b>Engine:</b> ' + esc(meta.engine || 'Final (src)');
      if (meta.quality && meta.quality.score !== undefined) {
        engText += ' &bull; <b>Score:</b> ' + (Math.round(meta.quality.score * 10) / 10) + '%';
      }
      if (meta.attempts && meta.attempts.length > 0) {
        engText += '<div style="margin-top:4px; font-size:0.75rem; color:var(--text-muted);">Tries: ' + esc(meta.attempts.join(', ')) + '</div>';
      }
      document.getElementById('class-engine-info').innerHTML = engText;

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

      fetchCallGraph(cls);
    }

    async function fetchCallGraph(cls) {
      const badgeEl = document.getElementById('class-reach-badge');
      const pathEl = document.getElementById('class-reach-path');
      const callersEl = document.getElementById('class-callers');
      const calleesEl = document.getElementById('class-callees');
      badgeEl.innerHTML = '<span style="color:var(--text-muted); font-size:0.78rem;">Analyzing reachability ...</span>';
      pathEl.style.display = 'none';

      try {
        const res = await fetch('/api/callgraph?class=' + encodeURIComponent(cls));
        const data = await res.json();
        if (data.reachable === true) {
          badgeEl.innerHTML = '<span class="tag-badge tag-benign" style="font-size:0.76rem; padding:2px 7px;">🎯 Reachable from Entrypoint</span>' +
            '<div style="font-size:0.74rem; color:var(--text-muted); margin-top:3px;">Triggerable from ' + (data.entrypoints_count || 1) + ' entrypoint(s)</div>';
        } else if (data.reachable === false) {
          badgeEl.innerHTML = '<span class="tag-badge tag-suspect" style="font-size:0.76rem; padding:2px 7px;">💤 Unreachable / Dead Code</span>' +
            '<div style="font-size:0.74rem; color:var(--text-muted); margin-top:3px;">No execution path found from mod/mixin entrypoints</div>';
        } else {
          badgeEl.innerHTML = '<span style="font-size:0.76rem; color:var(--text-muted);">No entrypoints defined for target</span>';
        }

        if (data.path && data.path.length > 0) {
          let pathHtml = '<div style="font-weight:600; margin-bottom:4px; color:var(--accent-hover);">Execution Trigger Path:</div>';
          data.path.forEach((step, i) => {
            pathHtml += '<div style="margin-left:' + (i * 8) + 'px; margin-bottom:2px;">' +
              (i === 0 ? '🏁 ' : '&bull; ') + '<code>' + esc(step.from) + '</code>' +
              ' <span style="font-size:0.7rem; color:var(--text-muted);">(' + esc(step.opcode) + ')</span>' +
              ' &rarr; <code>' + esc(step.to) + '</code></div>';
          });
          pathEl.innerHTML = pathHtml;
          pathEl.style.display = 'block';
        }

        let cHtml = '';
        if (data.callers && data.callers.length > 0) {
          data.callers.forEach(c => {
            cHtml += '<div style="margin-bottom:3px;"><span style="color:var(--accent); font-size:0.72rem;">[' + esc(c.opcode) + ']</span> <code>' + esc(c.caller) + '</code></div>';
          });
        } else {
          cHtml = '<div style="color:var(--text-muted); font-size:0.75rem;">None detected</div>';
        }
        callersEl.innerHTML = cHtml;

        let ceHtml = '';
        if (data.callees && data.callees.length > 0) {
          data.callees.forEach(c => {
            ceHtml += '<div style="margin-bottom:3px;"><span style="color:var(--teal); font-size:0.72rem;">[' + esc(c.opcode) + ']</span> <code>' + esc(c.callee) + '</code></div>';
          });
        } else {
          ceHtml = '<div style="color:var(--text-muted); font-size:0.75rem;">None detected</div>';
        }
        calleesEl.innerHTML = ceHtml;
      } catch (e) {
        badgeEl.innerText = 'Call graph unavailable: ' + e;
      }
    }

    async function saveAuditNote() {
      const cls = currentData.selected;
      if (!cls) return;
      const tag = document.getElementById('audit-tag').value;
      const note = document.getElementById('audit-note').value.trim();
      const statusEl = document.getElementById('audit-status');
      statusEl.innerText = 'Saving ...';

      try {
        const res = await fetch('/api/annotations', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ class: cls, tag: tag, note: note })
        });
        const resData = await res.json();
        if (resData.ok) {
          currentData.annotations = resData.annotations || {};
          statusEl.innerText = 'Saved!';
          filterAndRenderTree();
          setTimeout(() => {
            const cur = currentData.annotations[cls];
            if (cur && cur.updated_at) {
              statusEl.innerText = 'Saved ' + cur.updated_at.split(' ')[1];
            }
          }, 1500);
        } else {
          statusEl.innerText = 'Save error';
        }
      } catch (e) {
        statusEl.innerText = 'Err: ' + e;
      }
    }

    async function clearAuditNote() {
      document.getElementById('audit-tag').value = '';
      document.getElementById('audit-note').value = '';
      await saveAuditNote();
    }

    async function fetchDiff() {
      const cls = currentData.selected;
      if (!cls) return;
      const e1 = document.getElementById('diff-e1').value;
      const e2 = document.getElementById('diff-e2').value;
      const diffContent = document.getElementById('diff-content');
      const statsBadge = document.getElementById('diff-stats');
      diffContent.innerText = 'Calculating diff between ' + e1 + ' and ' + e2 + ' ...';
      statsBadge.innerText = '...';

      try {
        const res = await fetch('/api/diff?class=' + encodeURIComponent(cls) + '&e1=' + encodeURIComponent(e1) + '&e2=' + encodeURIComponent(e2));
        const data = await res.json();

        if (data.identical) {
          statsBadge.innerText = 'Identical (0 diff)';
          diffContent.innerHTML = '<div style="color:var(--success); padding:10px;">✓ Output from ' + esc(e1) + ' and ' + esc(e2) + ' are completely identical.</div>';
          return;
        }

        statsBadge.innerText = '+' + (data.stats.added || 0) + ' / -' + (data.stats.removed || 0);

        const lines = (data.diff || '').split('\\n');
        let htmlOut = '';
        lines.forEach(line => {
          let lineCls = 'ctx';
          if (line.startsWith('+++') || line.startsWith('---')) {
            lineCls = 'hdr';
          } else if (line.startsWith('@@')) {
            lineCls = 'chunk';
          } else if (line.startsWith('+')) {
            lineCls = 'add';
          } else if (line.startsWith('-')) {
            lineCls = 'del';
          }
          htmlOut += '<div class="diff-line ' + lineCls + '">' + esc(line) + '</div>';
        });
        diffContent.innerHTML = htmlOut || '<div style="color:var(--text-muted); padding:10px;">No diff output generated.</div>';
      } catch (e) {
        diffContent.innerText = 'Diff calculation failed: ' + e;
      }
    }

    async function openLlmPromptModal() {
      const cls = currentData.selected;
      if (!cls) return;
      document.getElementById('llm-modal-title').innerText = '🤖 AI Semantic Rename: ' + cls;
      document.getElementById('llm-prompt-text').value = 'Generating prompt ...';
      document.getElementById('copy-status').style.display = 'none';
      document.getElementById('llm-modal').classList.add('active');

      try {
        const res = await fetch('/api/llm_prompt?class=' + encodeURIComponent(cls));
        const data = await res.json();
        document.getElementById('llm-prompt-text').value = data.prompt || '// No prompt generated';
      } catch (e) {
        document.getElementById('llm-prompt-text').value = 'Failed to generate prompt: ' + e;
      }
    }

    function closeLlmModal() {
      document.getElementById('llm-modal').classList.remove('active');
    }

    async function copyLlmPrompt() {
      const txt = document.getElementById('llm-prompt-text').value;
      try {
        await navigator.clipboard.writeText(txt);
        const status = document.getElementById('copy-status');
        status.style.display = 'inline';
        setTimeout(() => { status.style.display = 'none'; }, 2500);
      } catch (e) {
        alert('Copy failed: ' + e);
      }
    }

    function switchView(view) {
      currentData.currentView = view;
      document.querySelectorAll('.tab-btn').forEach((btn, idx) => {
        btn.classList.toggle('active', ['decompiled', 'diff', 'natives', 'threats', 'report'][idx] === view);
      });
      const codeView = document.getElementById('code-content');
      const diffView = document.getElementById('diff-view');

      if (view === 'diff') {
        codeView.style.display = 'none';
        diffView.style.display = 'flex';
        fetchDiff();
      } else {
        codeView.style.display = 'block';
        diffView.style.display = 'none';
        if (view === 'report') {
          fetch('/api/report').then(r => r.text()).then(txt => codeView.innerText = txt);
        } else if (view === 'natives') {
          fetch('/api/natives').then(r => r.text()).then(txt => codeView.innerText = txt);
        } else if (view === 'threats') {
          fetch('/api/threats').then(r => r.text()).then(txt => codeView.innerText = txt);
        } else if (currentData.selected) {
          selectClass(currentData.selected);
        }
      }
    }

    // Keyboard shortcut: Ctrl+S to save audit note
    document.addEventListener('keydown', e => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') {
        e.preventDefault();
        saveAuditNote();
      }
    });

    loadTree();
  </script>
</body>
</html>
"""


def _get_source_for_engine(work_dir: Path, cls: str, engine: str) -> str:
    """Retrieve Java source code for a class produced by a specific decompiler engine."""
    if not cls:
        return "// No class specified"

    rel_name = cls + ".java"
    rep_json = work_dir / "report.json"
    if rep_json.is_file():
        try:
            r_data = json.loads(rep_json.read_text(encoding="utf-8"))
            outcomes = r_data.get("outcomes", {})
            if cls in outcomes and outcomes[cls].get("rel"):
                rel_name = outcomes[cls]["rel"]
        except Exception:
            pass

    src_dir = (work_dir / "src").resolve()
    target_path = (src_dir / rel_name).resolve()

    eng_key = engine.lower().strip()
    if eng_key in ("final", "current", ""):
        if str(target_path).startswith(str(src_dir)) and target_path.is_file():
            try:
                return target_path.read_text(encoding="utf-8", errors="replace")
            except Exception as e:
                return f"// Error reading file: {e}"
        return f"// Source not found for {cls} in src/"

    # 1. Check existing engine directory: engines/<engine>/<rel_name>
    eng_dir = (work_dir / "engines" / eng_key).resolve()
    eng_target = (eng_dir / rel_name).resolve()
    if str(eng_target).startswith(str(eng_dir)) and eng_target.is_file():
        try:
            return eng_target.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            return f"// Error reading {engine} source: {e}"

    # 2. Check engine cache: _engines_cache/<engine>/<rel_name>
    cache_dir = (work_dir / "_engines_cache" / eng_key).resolve()
    cache_target = (cache_dir / rel_name).resolve()
    if str(cache_target).startswith(str(cache_dir)) and cache_target.is_file():
        try:
            return cache_target.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            return f"// Error reading cached {engine} source: {e}"

    # 3. Check pass 2 work directories: _work/out2_<engine>...
    work_sub = work_dir / "_work"
    if work_sub.is_dir():
        for d in work_sub.glob(f"out*_{eng_key}*"):
            f = d / rel_name
            if f.is_file():
                try:
                    return f.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    pass

    # 4. Check if the winning engine in report.json happens to match this engine
    if rep_json.is_file():
        try:
            r_data = json.loads(rep_json.read_text(encoding="utf-8"))
            outcomes = r_data.get("outcomes", {})
            if cls in outcomes and (outcomes[cls].get("engine") or "").lower() == eng_key:
                if target_path.is_file():
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
            return None

        cache_key = str(target.resolve())
        if cache_key in _CG_CACHE:
            return _CG_CACHE[cache_key]

        try:
            cg = CG.build_callgraph(target)
            rep = CG.compute_reachability(cg)
            _CG_CACHE[cache_key] = (cg, rep)
            return (cg, rep)
        except Exception:
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
            self.send_json({"target": self.work_dir.name, "classes": sorted(classes)})
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
                    outcomes = r_data.get("outcomes", {})
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
                    outcomes = r_data.get("outcomes", {})
                    if cls in outcomes and outcomes[cls].get("rel"):
                        rel_name = outcomes[cls]["rel"]
                except Exception:
                    pass

            src_file = self.work_dir / "src" / rel_name
            code = ""
            if src_file.is_file():
                try:
                    code = src_file.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    code = ""

            candidates = []
            if src_file.is_file():
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

        if path == "/api/class_info":
            cls = query.get("class", [""])[0]
            info = {"hooks": [], "strings": [], "engine": None, "quality": None, "attempts": [], "status": None}
            rep_json = self.work_dir / "report.json"
            if rep_json.is_file():
                try:
                    r_data = json.loads(rep_json.read_text(encoding="utf-8"))
                    outcomes = r_data.get("outcomes", {})
                    if cls in outcomes:
                        co = outcomes[cls]
                        info["engine"] = co.get("engine")
                        info["quality"] = co.get("quality")
                        info["attempts"] = co.get("attempts", [])
                        info["status"] = co.get("status")
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
                self.send_json({
                    "class": cls,
                    "reachable": None,
                    "entrypoints_count": 0,
                    "callers": [],
                    "callees": [],
                    "path": [],
                })
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
