"""Entrypoint reachability analysis and method-level static call graph engine.

In large Minecraft mods and obfuscated jars (often 5,000+ classes), reverse
engineers need to focus on what code is actually reachable from known entrypoints:
1. Mod entrypoints (fabric.mod.json, quilt.mod.json, mods.toml, @Mod);
2. Mixin hook targets (@Inject, @Overwrite, @Redirect methods);
3. Manifest executables (Main-Class, Premain-Class, Agent-Class);
4. ServiceLoader and event bus subscribers.

This module builds a precise method-level invocation graph from bytecode,
computes forward reachability, finds trigger paths from entrypoints to any target,
identifies dead code / unused library bloat, and provides jar pruning.
"""

from __future__ import annotations

import collections
import json
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from . import classfile as CF
from . import bytecode as BC
from . import mcmod as MM
from . import annotations as AN


@dataclass(frozen=True)
class MethodRef:
    owner: str       # internal name, e.g. "net/minecraft/client/Minecraft"
    name: str        # method name, e.g. "runTick"
    desc: str        # method descriptor, e.g. "()V"

    def __repr__(self) -> str:
        return f"{self.owner}.{self.name}{self.desc}"

    @property
    def display_name(self) -> str:
        simple = self.owner.split("/")[-1]
        return f"{simple}.{self.name}()"

    @property
    def qualified_name(self) -> str:
        dotted = self.owner.replace("/", ".")
        return f"{dotted}.{self.name}"


@dataclass
class CallEdge:
    caller: MethodRef
    callee: MethodRef
    opcode: str      # invokevirtual, invokestatic, invokespecial, invokeinterface, invokedynamic

    def __repr__(self) -> str:
        return f"{self.caller.display_name} --[{self.opcode}]--> {self.callee.display_name}"


@dataclass
class Entrypoint:
    method: MethodRef
    kind: str          # mod_init, mixin_hook, manifest_main, agent_premain, user_specified, clinit
    description: str   # human-readable context


class CallGraph:
    """Method-level and class-level invocation graph."""

    def __init__(self):
        self.methods: set[MethodRef] = set()
        self.classes: set[str] = set()
        self.class_methods: dict[str, list[MethodRef]] = {}
        # method -> edges
        self.callees: dict[MethodRef, list[CallEdge]] = {}
        self.callers: dict[MethodRef, list[CallEdge]] = {}
        # class -> classes
        self.class_callees: dict[str, set[str]] = {}
        self.class_callers: dict[str, set[str]] = {}
        # inheritance
        self.super_classes: dict[str, str] = {}
        self.interfaces: dict[str, list[str]] = {}
        self.subclasses: dict[str, set[str]] = {}
        # discovered entrypoints
        self.entrypoints: list[Entrypoint] = []

    def add_edge(self, caller: MethodRef, callee: MethodRef, opcode: str) -> None:
        edge = CallEdge(caller=caller, callee=callee, opcode=opcode)
        self.callees.setdefault(caller, []).append(edge)
        self.callers.setdefault(callee, []).append(edge)
        self.class_callees.setdefault(caller.owner, set()).add(callee.owner)
        self.class_callers.setdefault(callee.owner, set()).add(caller.owner)

    def all_subclasses(self, owner: str) -> set[str]:
        """Compute all transitive subclasses and implementors of a class or interface."""
        out: set[str] = set()
        queue = collections.deque([owner])
        while queue:
            curr = queue.popleft()
            for sub in self.subclasses.get(curr, ()):
                if sub not in out and sub not in ("java/lang/Object", "java/lang/Enum"):
                    out.add(sub)
                    queue.append(sub)
        return out


@dataclass
class ReachabilityReport:
    total_classes: int
    total_methods: int
    reachable_classes: set[str]
    reachable_methods: set[MethodRef]
    dead_classes: set[str]
    dead_methods: set[MethodRef]
    entrypoints: list[Entrypoint]
    call_graph: CallGraph
    predecessors: dict[MethodRef, CallEdge] = field(default_factory=dict)

    @property
    def reachability_pct(self) -> float:
        if self.total_classes == 0:
            return 100.0
        return round((len(self.reachable_classes) / self.total_classes) * 100.0, 1)

    @property
    def dead_classes_pct(self) -> float:
        if self.total_classes == 0:
            return 0.0
        return round((len(self.dead_classes) / self.total_classes) * 100.0, 1)


def _read_class_bytes(target: Path) -> dict[str, bytes]:
    """Extract class bytes from a jar file or directory."""
    out: dict[str, bytes] = {}
    if target.is_file() and target.suffix.lower() in (".jar", ".zip"):
        with zipfile.ZipFile(target) as z:
            for n in z.namelist():
                if n.endswith(".class") and not n.startswith("META-INF/"):
                    try:
                        out[n[:-6]] = z.read(n)
                    except Exception:
                        pass
    elif target.is_dir():
        for p in target.rglob("*.class"):
            try:
                rel = p.relative_to(target).as_posix()
                if rel.endswith(".class"):
                    out[rel[:-6]] = p.read_bytes()
            except Exception:
                pass
    return out


def build_callgraph(target: Path, custom_entrypoints: list[str] | None = None) -> CallGraph:
    """Build a method-level invocation graph from bytecode and discover entrypoints."""
    cg = CallGraph()
    raw_classes = _read_class_bytes(target)

    # 1. Parse all classes and index declarations
    parsed_classes: dict[str, CF.ClassFile] = {}
    for name, data in raw_classes.items():
        try:
            cf = CF.parse(data)
            parsed_classes[name] = cf
            cg.classes.add(cf.name)
            if cf.super_name:
                cg.super_classes[cf.name] = cf.super_name
                cg.subclasses.setdefault(cf.super_name, set()).add(cf.name)
            for iface in cf.interface_names:
                cg.interfaces.setdefault(cf.name, []).append(iface)
                cg.subclasses.setdefault(iface, set()).add(cf.name)
            for m in cf.methods:
                m_name = cf.utf8(m.name_index)
                m_desc = cf.utf8(m.descriptor_index)
                mref = MethodRef(owner=cf.name, name=m_name, desc=m_desc)
                cg.methods.add(mref)
                cg.class_methods.setdefault(cf.name, []).append(mref)
        except Exception:
            continue

    # 2. Extract method invocation opcodes and wire edges
    op_map = {
        0xB6: "invokevirtual",
        0xB7: "invokespecial",
        0xB8: "invokestatic",
        0xB9: "invokeinterface",
        0xBA: "invokedynamic",
    }

    for cf in parsed_classes.values():
        for m in cf.methods:
            m_name = cf.utf8(m.name_index)
            m_desc = cf.utf8(m.descriptor_index)
            caller = MethodRef(owner=cf.name, name=m_name, desc=m_desc)

            cinfo = BC.method_code(cf, m, decode_insns=True)
            if not cinfo or not cinfo.insns:
                continue

            for insn in cinfo.insns:
                if insn.op in (0xB6, 0xB7, 0xB8, 0xB9):
                    cp_idx = insn.arg
                    if not cp_idx or cp_idx >= len(cf.cp):
                        continue
                    e = cf.cp[cp_idx]
                    if not e or e[0] not in (CF.C_METHODREF, CF.C_INTERFACE_METHODREF):
                        continue
                    try:
                        callee_cls = cf.class_name(e[1][0])
                        nt = cf.cp[e[1][1]]
                        if not nt or nt[0] != CF.C_NAME_AND_TYPE:
                            continue
                        callee_name = cf.utf8(nt[1][0])
                        callee_desc = cf.utf8(nt[1][1])
                        callee = MethodRef(owner=callee_cls, name=callee_name, desc=callee_desc)
                        cg.add_edge(caller, callee, op_map.get(insn.op, "invoke"))
                    except Exception:
                        continue
                elif insn.op == 0xBA:  # invokedynamic
                    cp_idx = insn.arg
                    if cp_idx and cp_idx < len(cf.cp):
                        e = cf.cp[cp_idx]
                        if e and e[0] == CF.C_INVOKE_DYNAMIC:
                            try:
                                nt = cf.cp[e[1][1]]
                                if nt and nt[0] == CF.C_NAME_AND_TYPE:
                                    callee_name = cf.utf8(nt[1][0])
                                    callee_desc = cf.utf8(nt[1][1])
                                    # Target owner marked as dynamic
                                    callee = MethodRef(owner="<indy>", name=callee_name, desc=callee_desc)
                                    cg.add_edge(caller, callee, "invokedynamic")
                            except Exception:
                                pass
                elif insn.op in (0xB2, 0xB3):  # getstatic, putstatic -> triggers <clinit>
                    cp_idx = insn.arg
                    if cp_idx and cp_idx < len(cf.cp):
                        e = cf.cp[cp_idx]
                        if e and e[0] == CF.C_FIELDREF:
                            try:
                                field_cls = cf.class_name(e[1][0])
                                clinit_target = MethodRef(owner=field_cls, name="<clinit>", desc="()V")
                                if clinit_target in cg.methods:
                                    cg.add_edge(caller, clinit_target, "getstatic" if insn.op == 0xB2 else "putstatic")
                            except Exception:
                                pass

    # 3. Discover entrypoints from metadata and annotations
    discovered: list[Entrypoint] = []
    meta = None
    if target.is_file() or target.is_dir():
        try:
            meta = MM.read_mod_meta(target)
        except Exception:
            meta = None

    # (a) Mod entrypoints
    if meta and meta.entrypoints:
        for ep_str in meta.entrypoints:
            norm_cls = ep_str.replace(".", "/").strip()
            # If entrypoint specifies class::method
            ep_method = None
            if "::" in norm_cls:
                norm_cls, ep_method = norm_cls.split("::", 1)
            for m in cg.class_methods.get(norm_cls, []):
                if ep_method:
                    if m.name == ep_method:
                        discovered.append(Entrypoint(m, "mod_init", f"Mod entrypoint {ep_str}"))
                else:
                    if m.name in ("onInitialize", "onInitializeClient", "onInitializeServer", "init", "<init>", "<clinit>"):
                        discovered.append(Entrypoint(m, "mod_init", f"Mod lifecycle method in {ep_str}"))

    # (b) Manifest Main-Class and Agent entrypoints
    if meta and meta.manifest:
        main_cls = meta.manifest.main.get("Main-Class")
        if main_cls:
            norm_main = main_cls.replace(".", "/").strip()
            for m in cg.class_methods.get(norm_main, []):
                if m.name == "main":
                    discovered.append(Entrypoint(m, "manifest_main", f"Main-Class entrypoint in {main_cls}"))
        agent_attrs = meta.manifest.agent_attrs()
        for ag_key in ("Premain-Class", "Agent-Class"):
            ag_cls = agent_attrs.get(ag_key)
            if ag_cls:
                norm_ag = ag_cls.replace(".", "/").strip()
                for m in cg.class_methods.get(norm_ag, []):
                    if m.name in ("premain", "agentmain"):
                        discovered.append(Entrypoint(m, "agent_premain", f"{ag_key} in {ag_cls}"))

    # (c) Mixin hook methods and @Mod classes directly from annotations
    for cf in parsed_classes.values():
        is_mod_class = any(ann.simple_type in ("Mod", "Mixin") for ann in AN.class_annotations(cf))
        for m in cf.methods:
            m_name = cf.utf8(m.name_index)
            m_desc = cf.utf8(m.descriptor_index)
            m_ref = MethodRef(owner=cf.name, name=m_name, desc=m_desc)

            m_anns = AN.member_annotations(cf, m)
            hook_ann = next((ann for ann in m_anns if ann.simple_type in MM._MIXIN_KINDS), None)
            if hook_ann:
                targets = hook_ann.strings("method")
                tgt_info = f"@{hook_ann.simple_type} into {','.join(targets)}" if targets else f"@{hook_ann.simple_type}"
                discovered.append(Entrypoint(m_ref, "mixin_hook", tgt_info))
            elif is_mod_class and m_name in ("<init>", "<clinit>", "init", "onInitialize", "onInitializeClient"):
                discovered.append(Entrypoint(m_ref, "mod_init", f"Mod lifecycle method in @Mod class {cf.name}"))

    # (d) Custom user-specified entrypoints
    if custom_entrypoints:
        for u_ep in custom_entrypoints:
            u_clean = u_ep.replace(".", "/").strip()
            cls_part = u_clean
            meth_part = None
            if ":" in u_clean:
                cls_part, meth_part = u_clean.split(":", 1)
            elif "#" in u_clean:
                cls_part, meth_part = u_clean.split("#", 1)
            for m in cg.class_methods.get(cls_part, []):
                if meth_part is None or m.name == meth_part:
                    discovered.append(Entrypoint(m, "user_specified", f"User entrypoint: {u_ep}"))

    # (e) Fallback heuristics if no entrypoints could be identified
    if not discovered:
        for m in cg.methods:
            if m.name == "main" and "([Ljava/lang/String;)V" in m.desc:
                discovered.append(Entrypoint(m, "manifest_main", f"Static main entrypoint in {m.owner}"))
            elif m.name in ("premain", "agentmain"):
                discovered.append(Entrypoint(m, "agent_premain", f"Agent hook in {m.owner}"))

    # Deduplicate entrypoints by method
    seen_methods: set[MethodRef] = set()
    deduped: list[Entrypoint] = []
    for ep in discovered:
        if ep.method not in seen_methods:
            seen_methods.add(ep.method)
            deduped.append(ep)

    cg.entrypoints = deduped
    return cg


def compute_reachability(cg: CallGraph, target_internal_only: bool = True) -> ReachabilityReport:
    """Perform forward BFS reachability analysis from all entrypoints."""
    visited_methods: set[MethodRef] = set()
    predecessors: dict[MethodRef, CallEdge] = {}
    queue = collections.deque()

    for ep in cg.entrypoints:
        visited_methods.add(ep.method)
        queue.append(ep.method)

    while queue:
        curr = queue.popleft()

        # Static initializer reachability: whenever a class is accessed, its <clinit> runs
        if curr.owner in cg.classes and curr.name != "<clinit>":
            clinit_ref = MethodRef(owner=curr.owner, name="<clinit>", desc="()V")
            if clinit_ref in cg.methods and clinit_ref not in visited_methods:
                visited_methods.add(clinit_ref)
                predecessors[clinit_ref] = CallEdge(caller=curr, callee=clinit_ref, opcode="clinit")
                queue.append(clinit_ref)

        outgoing = cg.callees.get(curr, [])
        for edge in outgoing:
            callee = edge.callee
            targets = [callee]

            # Virtual dispatch expansion: only for polymorphic calls (invokevirtual / invokeinterface)
            # Never for constructor invokespecial, static methods, or java/lang/Object roots
            if edge.opcode in ("invokevirtual", "invokeinterface") and callee.name not in ("<init>", "<clinit>") and callee.owner not in ("java/lang/Object", "java/lang/Enum"):
                for sub in cg.all_subclasses(callee.owner):
                    if sub in cg.classes:
                        sub_meth = MethodRef(owner=sub, name=callee.name, desc=callee.desc)
                        if sub_meth in cg.methods:
                            targets.append(sub_meth)

            for tgt in targets:
                if tgt not in visited_methods:
                    visited_methods.add(tgt)
                    predecessors[tgt] = edge
                    queue.append(tgt)

    if target_internal_only:
        reachable_methods = {m for m in visited_methods if m.owner in cg.classes}
    else:
        reachable_methods = set(visited_methods)

    reachable_classes = {m.owner for m in reachable_methods}
    dead_classes = cg.classes - reachable_classes
    dead_methods = {m for m in cg.methods if m not in visited_methods and m.owner in cg.classes}

    return ReachabilityReport(
        total_classes=len(cg.classes),
        total_methods=len(cg.methods),
        reachable_classes=reachable_classes,
        reachable_methods=reachable_methods,
        dead_classes=dead_classes,
        dead_methods=dead_methods,
        entrypoints=cg.entrypoints,
        call_graph=cg,
        predecessors=predecessors,
    )


def find_path(rep: ReachabilityReport, target: str | MethodRef) -> list[CallEdge] | None:
    """Find the shortest invocation chain from any entrypoint to a target class or method."""
    target_nodes: list[MethodRef] = []
    if isinstance(target, MethodRef):
        target_nodes = [target]
    else:
        clean = target.replace(".", "/").strip()
        if ":" in clean:
            cls_part, meth_part = clean.split(":", 1)
            target_nodes = [m for m in rep.reachable_methods if m.owner == cls_part and m.name == meth_part]
        else:
            target_nodes = [m for m in rep.reachable_methods if m.owner == clean]

    if not target_nodes:
        return None

    # Pick the target method with shortest predecessor chain
    best_path: list[CallEdge] | None = None
    for tn in target_nodes:
        if tn not in rep.predecessors and tn not in {ep.method for ep in rep.entrypoints}:
            continue

        curr = tn
        path: list[CallEdge] = []
        visited = set()
        while curr in rep.predecessors:
            if curr in visited:
                break  # cycle protection
            visited.add(curr)
            edge = rep.predecessors[curr]
            path.append(edge)
            curr = edge.caller

        path.reverse()
        if best_path is None or len(path) < len(best_path):
            best_path = path

    return best_path


def prune_jar(input_jar: Path, output_jar: Path, reachable_classes: set[str]) -> tuple[int, int, int]:
    """Create a slimmed jar containing only reachable classes and resource files.

    Returns (kept_classes, dropped_classes, bytes_saved).
    """
    kept_classes = 0
    dropped_classes = 0
    bytes_saved = 0

    output_jar.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(input_jar, "r") as z_in, zipfile.ZipFile(output_jar, "w", zipfile.ZIP_DEFLATED) as z_out:
        for item in z_in.infolist():
            name = item.filename
            data = z_in.read(name)
            if name.endswith(".class") and not name.startswith("META-INF/"):
                cname = name[:-6]
                outer = cname.split("$")[0]
                if cname in reachable_classes or outer in reachable_classes:
                    z_out.writestr(item, data)
                    kept_classes += 1
                else:
                    dropped_classes += 1
                    bytes_saved += len(data)
            else:
                # Retain resources, manifests, assets
                z_out.writestr(item, data)

    return kept_classes, dropped_classes, bytes_saved


def export_dot(cg: CallGraph, reachable_methods: set[MethodRef] | None = None, max_edges: int = 250) -> str:
    """Export the call graph to Graphviz DOT format."""
    lines = [
        "digraph CallGraph {",
        '  graph [rankdir="LR", bgcolor="#1e1e24", fontname="Consolas", fontcolor="#f0f0f5"];',
        '  node [shape="box", style="filled,rounded", fontname="Consolas", fontcolor="#ffffff", color="#383842"];',
        '  edge [fontname="Consolas", fontcolor="#81a1c1", color="#5e81ac", fontsize=9];',
    ]

    ep_methods = {ep.method for ep in cg.entrypoints}
    edge_count = 0

    for caller, edges in cg.callees.items():
        if reachable_methods and caller not in reachable_methods:
            continue
        for edge in edges:
            if reachable_methods and edge.callee not in reachable_methods:
                continue

            c_label = caller.display_name.replace('"', '\\"')
            t_label = edge.callee.display_name.replace('"', '\\"')

            c_color = "#a3be8c" if caller in ep_methods else "#434c5e"
            t_color = "#bf616a" if "exec" in t_label or "reflect" in t_label.lower() else "#2e3440"

            lines.append(f'  "{caller}" [label="{c_label}", fillcolor="{c_color}"];')
            lines.append(f'  "{edge.callee}" [label="{t_label}", fillcolor="{t_color}"];')
            lines.append(f'  "{caller}" -> "{edge.callee}" [label="{edge.opcode}"];')

            edge_count += 1
            if edge_count >= max_edges:
                lines.append(f'  // ... truncated after {max_edges} edges ...')
                break
        if edge_count >= max_edges:
            break

    lines.append("}")
    return "\n".join(lines)


def export_json(rep: ReachabilityReport) -> dict:
    """Export reachability metrics and entrypoints to JSON."""
    return {
        "summary": {
            "total_classes": rep.total_classes,
            "total_methods": rep.total_methods,
            "reachable_classes": len(rep.reachable_classes),
            "reachable_methods": len(rep.reachable_methods),
            "dead_classes": len(rep.dead_classes),
            "dead_methods": len(rep.dead_methods),
            "reachability_pct": rep.reachability_pct,
            "dead_classes_pct": rep.dead_classes_pct,
        },
        "entrypoints": [
            {
                "method": str(ep.method),
                "kind": ep.kind,
                "description": ep.description,
            }
            for ep in rep.entrypoints
        ],
        "reachable_classes_list": sorted(list(rep.reachable_classes)),
        "dead_classes_list": sorted(list(rep.dead_classes)),
    }


def render_markdown(rep: ReachabilityReport, target_path: str | None = None) -> str:
    """Render a human-readable markdown reachability audit report."""
    md = [
        "# Entrypoint Reachability & Call Graph Report\n",
        f"- **Total classes**: {rep.total_classes}",
        f"- **Reachable classes**: {len(rep.reachable_classes)} ({rep.reachability_pct}%)",
        f"- **Dead / Unused classes**: {len(rep.dead_classes)} ({rep.dead_classes_pct}%)",
        f"- **Total declared methods**: {rep.total_methods}",
        f"- **Reachable methods**: {len(rep.reachable_methods)}",
        f"- **Discovered entrypoints**: {len(rep.entrypoints)}\n",
        "## Discovered Entrypoints\n",
        "| Kind | Entrypoint Method | Context |",
        "| :--- | :--- | :--- |",
    ]

    for ep in rep.entrypoints[:20]:
        md.append(f"| `{ep.kind}` | `{ep.method.display_name}` | {ep.description} |")
    if len(rep.entrypoints) > 20:
        md.append(f"| ... | *and {len(rep.entrypoints) - 20} more entrypoints* | |")

    if target_path:
        path_edges = find_path(rep, target_path)
        md.append(f"\n## Shortest Path to `{target_path}`\n")
        if path_edges:
            md.append("Execution trigger chain from entrypoint:\n")
            for i, edge in enumerate(path_edges, 1):
                md.append(f"{i}. `{edge.caller.display_name}` --(`{edge.opcode}`)--> `{edge.callee.display_name}`")
        else:
            md.append(f"⚠️ Target `{target_path}` is **unreachable** from any discovered entrypoint (potential dead code or dynamic reflection).")

    if rep.dead_classes:
        md.append("\n## Dead / Unreachable Classes (Sample Top 15)\n")
        md.append("Classes not invoked from any mod entrypoint or Mixin hook:\n")
        for dc in sorted(list(rep.dead_classes))[:15]:
            md.append(f"- `{dc}`")
        if len(rep.dead_classes) > 15:
            md.append(f"- *... and {len(rep.dead_classes) - 15} more dead classes*")

    return "\n".join(md)
