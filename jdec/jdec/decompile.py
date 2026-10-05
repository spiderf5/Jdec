"""The decompilation pipeline.

Two passes, because running three engines over everything is wasteful while
running one engine over everything leaves recoverable classes broken:

  pass 1  chunk the jar across N JVMs with the best-guess leading engine
  pass 2  anything missing, or carrying an engine error marker, gets
          re-run through every engine and the best output wins

Correctness details that matter here:
  * nested classes are usually inlined into their outer file, so `A$B` is
    considered produced when `A.java` exists
  * each chunk gets the original jar on its classpath, otherwise engines
    cannot resolve types outside the chunk
  * Procyon takes jar input only, so chunks are re-packed for it
"""

from __future__ import annotations

import concurrent.futures as cf
import json
import os
import shutil
import sys
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from . import classfile as CF
from . import engines as EN
from .probe import profile_jar, JarProfile
from .score import evaluate, better, Quality


@dataclass
class ClassOutcome:
    name: str                       # internal name, e.g. a/b/C
    rel: str | None = None          # relative java path in output
    engine: str | None = None
    variant: str = "default"
    quality: Quality | None = None
    attempts: list[str] = field(default_factory=list)
    status: str = "pending"         # ok | missing | failed | partial
    native_methods: int = 0         # body is not in the bytecode at all


@dataclass
class Report:
    input: str
    output: str
    started: float
    elapsed: float = 0.0
    profile: JarProfile | None = None
    engines_used: list[str] = field(default_factory=list)
    total: int = 0
    ok: int = 0
    partial: int = 0
    missing: int = 0
    failed: int = 0
    retried: int = 0
    improved: int = 0
    coverage_avg: float | None = None
    native_methods: int = 0
    native_classes: int = 0
    outcomes: dict[str, ClassOutcome] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# jar handling
# --------------------------------------------------------------------------

def _jar_index(jar: Path, limit: int = 0,
               validate: bool = True) -> tuple[list[str], list[str], dict[str, str]]:
    """Index a jar by class *internal* name.

    Entry paths and internal names are not always the same thing (relocated or
    jar-in-jar layouts), and everything downstream - output paths, produced-set
    checks - is keyed on the internal name. Returns (good, broken, entry_map),
    where entry_map is internal name -> zip entry path.

    Reads straight from the archive; unpacking thousands of tiny files to disk
    is far slower than re-reading a zip entry when we need it.
    """
    good: list[str] = []
    broken: list[str] = []
    entries: dict[str, str] = {}
    with zipfile.ZipFile(jar) as z:
        cls = [n for n in z.namelist()
               if n.endswith(".class") and not n.startswith("META-INF/")]
        if limit:
            cls = cls[:limit]
        for n in cls:
            if not validate:
                good.append(n[:-6])
                entries[n[:-6]] = n
                continue
            try:
                cf = CF.parse(z.read(n))
            except Exception:
                broken.append(n[:-6])
                continue
            good.append(cf.name)
            entries[cf.name] = n
    return good, broken, entries


def _pack_names(jar: Path, names: list[str], out: Path, entries: dict[str, str],
                extra_jar: Path | None = None) -> Path:
    """Build a jar containing `names`, optionally plus everything in extra_jar.

    Entries are stored under the internal name, so a remapped class lands on a
    path that matches what its own bytecode claims.
    """
    out.parent.mkdir(parents=True, exist_ok=True)
    written: set[str] = set()
    with zipfile.ZipFile(jar) as zin, zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zout:
        for n in names:
            try:
                zout.writestr(n + ".class", zin.read(entries.get(n, n + ".class")))
                written.add(n + ".class")
            except KeyError:
                pass
        if extra_jar and extra_jar.exists() and extra_jar != jar:
            with zipfile.ZipFile(extra_jar) as src:
                for m in src.namelist():
                    if m.endswith(".class") and m not in written:
                        try:
                            zout.writestr(m, src.read(m))
                        except Exception:
                            pass
    return out


def _chunks(items: list[str], n: int) -> list[list[str]]:
    if n <= 1:
        return [items]
    size = max(1, (len(items) + n - 1) // n)
    return [items[i:i + size] for i in range(0, len(items), size)]


def _case_collisions(names: list[str]) -> dict[str, list[str]]:
    """Group class names that differ only by letter case.

    ZKM-style mangling happily emits `myau/A` and `myau/a` as two distinct
    classes. A zip is case-sensitive so both survive in the archive, but the
    decompiled output is written to a filesystem that is not: on Windows and
    macOS `myau/A.java` and `myau/a.java` are one file, so whichever the engine
    writes second overwrites the first. Because the pipeline used to derive the
    class it had just written from the output path, the survivor was then
    credited to *both* classes and the victim was still reported as recovered.
    """
    groups: dict[str, list[str]] = {}
    for n in names:
        groups.setdefault(n.lower(), []).append(n)
    return {k: sorted(v) for k, v in groups.items() if len(v) > 1}


def _safe_rel(name: str) -> str:
    """A relative .java path for `name` that no case-insensitive FS can merge.

    Uppercase letters are percent-encoded, which is unambiguous because `%`
    cannot occur in a Java identifier. Only applied to classes that really do
    collide, so the common output tree keeps its natural names.
    """
    parts = name.split("/")
    out = []
    for seg in parts[:-1]:
        out.append(seg)
    simple = parts[-1]
    out.append("".join("%%%02X" % ord(c) if c.isupper() else c for c in simple))
    return "/".join(out) + ".java"


def _iso_buckets(collisions: dict[str, list[str]]) -> list[list[str]]:
    """Partition case-colliding classes into engine-run-sized buckets.

    Members of one group all fold to the same lowercase name, so no two of
    them may share an output directory. Classes from *different* groups never
    collide, so bucket i can safely hold the i-th member of every group: the
    isolation pass then costs one engine run per bucket instead of one JVM
    per class (the real ZKM sample: 170 colliding classes -> 2 runs).
    """
    count = max(len(grp) for grp in collisions.values())
    buckets: list[list[str]] = [[] for _ in range(count)]
    for grp in collisions.values():
        for i, name in enumerate(sorted(grp)):
            buckets[i].append(name)
    return [sorted(b) for b in buckets]


def _produced_set(out_dir: Path) -> set[str]:
    return {p.relative_to(out_dir).as_posix()[:-5] for p in out_dir.rglob("*.java")}


def _is_produced(name: str, produced: set[str]) -> bool:
    if name in produced:
        return True
    outer = name.split("$", 1)[0]
    return outer != name and outer in produced


# --------------------------------------------------------------------------
# passes
# --------------------------------------------------------------------------

def _run_chunks(
    engine_key: str,
    variant: str,
    jobs: int,
    inputs: list[Path],
    out_dirs: list[Path],
    engines_dir: Path,
    classpath: list[str],
    timeout: int,
    memory: str,
    label: str,
) -> list[EN.RunResult]:
    engine = EN.ENGINES[engine_key]
    # results[i] belongs to inputs[i]: completion order would silently mispair
    # callers that zip the two lists (the isolation buckets did exactly that)
    results: list[EN.RunResult | None] = [None] * len(inputs)

    def one(i: int) -> tuple[int, EN.RunResult]:
        cp = [] if engine.needs_jar_input else classpath
        return i, EN.run_engine(engine, engines_dir, inputs[i], out_dirs[i],
                                variant=variant, timeout=timeout, memory=memory,
                                extra_cp=cp)

    with cf.ThreadPoolExecutor(max_workers=jobs) as pool:
        futs = [pool.submit(one, i) for i in range(len(inputs))]
        done = 0
        for f in cf.as_completed(futs):
            i, r = f.result()
            results[i] = r
            done += 1
            err = f"  ({r.error})" if r.error else ""
            print(f"    {label} chunk {done}/{len(futs)}: {len(r.files)} files "
                  f"in {r.seconds:.1f}s{err}", flush=True)
    return [r for r in results if r is not None]


def decompile(
    input_path: Path,
    out_dir: Path,
    engines_dir: Path,
    engine_order: list[str] | None = None,
    jobs: int = 0,
    memory: str = "2g",
    timeout: int = 1800,
    verify_all: bool = False,
    resume: bool = False,
    keep_work: bool = True,
    clean_work: bool = False,
    skip_precheck: bool = False,
    limit: int = 0,
) -> Report:
    t0 = time.time()
    out_dir.mkdir(parents=True, exist_ok=True)
    src_dir = out_dir / "src"
    src_dir.mkdir(exist_ok=True)
    work = out_dir / "_work"

    print(f"[1/5] profiling {input_path.name} ...")
    prof = profile_jar(input_path)
    print("  " + prof.summary().replace("\n", "\n  "))

    # pick the leading engine: old bytecode favours Procyon, modern favours CFR
    order = list(engine_order or _default_engine_order(prof))
    order = [e for e in order if e in EN.ENGINES and EN.ENGINES[e].available(engines_dir)]
    if not order:
        raise SystemExit("no decompiler engine available (run with --install-engines)")
    lead = order[0]
    print(f"  engine order: {', '.join(order)}")

    print(f"[2/5] scanning classes ...")
    if work.exists() and not resume:
        try:
            shutil.rmtree(work, ignore_errors=True)
        except Exception:  # noqa: BLE001
            work = out_dir / f"_work_{int(time.time())}"
    work.mkdir(parents=True, exist_ok=True)

    # A single unparsable class makes Vineflower abort the whole run, so
    # validate up front and quarantine anything we cannot read.
    good, broken, entries = _jar_index(input_path, limit=limit,
                                       validate=not skip_precheck)
    if broken:
        print(f"  quarantined {len(broken)} unreadable class(es): "
              + ", ".join(broken[:4]) + ("..." if len(broken) > 4 else ""))
    print(f"  {len(good)} classes")
    if not good:
        print("  nothing readable to decompile")
        return _empty_report(input_path, src_dir, prof, order, t0, good + broken, broken)

    if jobs <= 0:
        jobs = min(4, max(1, (os.cpu_count() or 2)))
    jobs = min(jobs, max(1, len(good) // 200 or 1))

    outcomes: dict[str, ClassOutcome] = {n: ClassOutcome(name=n) for n in good + broken}
    for n in broken:
        outcomes[n].status = "broken"

    classpath = [str(input_path)]

    # Classes whose names differ only by case cannot share an output directory:
    # one engine run would have the second file overwrite the first, and the
    # victim could not be told apart from the survivor afterwards. They are
    # excluded from the batched passes and decompiled in buckets that never
    # place two same-lowercase names in one directory, so the mapping from
    # class to file is carried explicitly instead of being guessed back out
    # of a path.
    collisions = _case_collisions(good)
    colliding = {n for grp in collisions.values() for n in grp}
    batched = [n for n in good if n not in colliding]
    if colliding:
        print(f"  {len(colliding)} class(es) in {len(collisions)} case-colliding "
              f"group(s) will be decompiled one per output directory")

    print(f"[3/5] pass 1: {EN.ENGINES[lead].label} across {jobs} parallel chunk(s) ...")
    parts = _chunks(batched, jobs)
    chunk_jars, out_dirs = [], []
    lead_needs_all = EN.ENGINES[lead].needs_jar_input
    for i, part in enumerate(parts):
        jpath = work / f"chunk{i}.jar"
        # Procyon has no external classpath option, so its jar must be whole
        _pack_names(input_path, part, jpath, entries,
                    extra_jar=input_path if lead_needs_all else None)
        chunk_jars.append(jpath)
        out_dirs.append(work / f"out1_{i}")
    results = _run_chunks(lead, "default", jobs, chunk_jars, out_dirs, engines_dir,
                          classpath, timeout, memory, EN.ENGINES[lead].label)

    # merge pass 1 into src/
    produced: set[str] = set()
    for r in results:
        for rel, path in r.files.items():
            stem = rel[:-5]
            dest = src_dir / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            if resume and dest.exists():
                produced.add(stem)
                continue
            shutil.copy2(path, dest)
            produced.add(stem)

    for name in batched:
        o = outcomes[name]
        if _is_produced(name, produced):
            o.status = "ok"
            o.engine = lead
            o.rel = (name if name in produced else name.split("$", 1)[0]) + ".java"
            o.attempts.append(lead)
        else:
            o.status = "missing"

    # ---- case-colliding classes: one output directory per bucket -----------
    # `rel` is derived from the class name rather than from whatever path the
    # engine happened to write, so the two members of `A`/`a` cannot be
    # confused even though the filesystem merged them.
    isolated = 0
    if colliding:
        buckets = _iso_buckets(collisions)
        iso_inputs, iso_dirs = [], []
        for i, names in enumerate(buckets):
            bdir = work / f"iso_{i}"
            if bdir.exists():
                shutil.rmtree(bdir, ignore_errors=True)
            bdir.mkdir(parents=True, exist_ok=True)
            bjar = work / f"iso_{i}.jar"
            _pack_names(input_path, names, bjar, entries,
                        extra_jar=input_path if lead_needs_all else None)
            iso_inputs.append(bjar)
            iso_dirs.append(bdir)
        iso_results = _run_chunks(lead, "default", jobs, iso_inputs, iso_dirs,
                                  engines_dir, classpath, timeout, memory,
                                  f"{EN.ENGINES[lead].label}:isolated")
        for names, r in zip(buckets, iso_results):
            for name in names:
                o = outcomes[name]
                src_file = r.files.get(name + ".java")
                if src_file is None:
                    # an engine may inline a nested class under its outer type
                    outer = name.split("$", 1)[0] + ".java"
                    src_file = r.files.get(outer)
                if src_file is None:
                    o.status = "missing"
                    o.attempts.append(f"{lead}:isolated")
                    continue
                rel = _safe_rel(name)
                dest = src_dir / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src_file, dest)
                o.rel = rel
                o.status = "ok"
                o.engine = lead
                o.attempts.append(f"{lead}:isolated")
                isolated += 1
        if isolated:
            print(f"  recovered {isolated} case-colliding class(es) into "
                  f"separately-named files")

    # ------------------------------------------------------------- pass 2
    suspects = [n for n in good if outcomes[n].status == "missing"]
    suspects += _scan_error_markers(src_dir, good, outcomes)
    suspects = sorted(set(suspects))
    print(f"[4/5] pass 2: {len(suspects)} class(es) need a second opinion ...")

    retried = improved = 0
    if suspects:
        # ground truth for just the suspects: cheap enough, and it is what
        # makes "which engine won" an answerable question
        truth: dict[str, CF.ClassFile] = {}
        with zipfile.ZipFile(input_path) as z:
            for n in suspects:
                try:
                    truth[n] = CF.parse(z.read(entries.get(n, n + ".class")))
                except Exception:
                    pass

        # Case-colliding classes are partitioned into buckets to prevent
        # same-lowercase files overwriting each other in engine output dirs
        suspect_col = _case_collisions(suspects)
        if suspect_col:
            col_names = {n for grp in suspect_col.values() for n in grp}
            non_col = [n for n in suspects if n not in col_names]
            buckets = _iso_buckets(suspect_col)
            if non_col:
                buckets[0].extend(non_col)
            suspect_batches = [sorted(b) for b in buckets]
        else:
            suspect_batches = [suspects]

        candidates: dict[str, list[tuple[str, str, Path, Quality]]] = {}
        variants = ["default", "lenient"]
        for ekey in order:
            for variant in variants:
                eng = EN.ENGINES[ekey]
                if variant == "lenient" and "lenient" not in eng.variants:
                    continue
                matched = 0
                for bi, batch in enumerate(suspect_batches):
                    odir = work / f"out2_{ekey}_{variant}_{bi}"
                    if odir.exists():
                        shutil.rmtree(odir, ignore_errors=True)
                    retry_only = work / f"retry_{bi}.jar"
                    if not retry_only.exists():
                        _pack_names(input_path, batch, retry_only, entries)
                    if eng.needs_jar_input:
                        retry_merged = work / f"retry_merged_{bi}.jar"
                        if not retry_merged.exists():
                            _pack_names(input_path, batch, retry_merged, entries,
                                        extra_jar=input_path)
                        inp: Path = retry_merged
                    else:
                        inp = retry_only
                    r = EN.run_engine(eng, engines_dir, inp, odir, variant=variant,
                                      timeout=timeout, memory=memory, extra_cp=classpath)
                    if not r.files:
                        continue
                    for rel, path in r.files.items():
                        stem = rel[:-5]
                        if stem not in batch:
                            # an engine may inline a nested class under its outer
                            if not any(s.split("$", 1)[0] == stem for s in batch):
                                continue
                            targets = [s for s in batch if s.split("$", 1)[0] == stem]
                        else:
                            targets = [stem]
                        try:
                            src = path.read_text("utf-8", "replace")
                        except Exception:
                            continue
                        for t in targets:
                            gt = truth.get(t)
                            if gt is None:
                                continue
                            q = evaluate(src, gt)
                            candidates.setdefault(t, []).append((ekey, variant, path, q))
                            matched += 1
                if matched:
                    print(f"    {eng.label}[{variant}]: {matched} candidate(s)")
                else:
                    print(f"    {eng.label}[{variant}]: produced nothing"
                          + (f" ({r.error})" if r.error else ""))

        for name, cands in candidates.items():
            cands.sort(key=lambda c: -c[3].score)
            best = None
            for ekey, variant, path, q in cands:
                if better(q, best[3] if best else None):
                    best = (ekey, variant, path, q)
            if best is None:
                continue
            ekey, variant, path, q = best
            o = outcomes[name]
            retried += 1
            prev_truth = truth.get(name)
            # the incumbent has to be re-scored, otherwise "is this candidate
            # better?" compares against nothing and every retry wins by default
            prev_q = None
            if prev_truth is not None and o.rel and (src_dir / o.rel).exists():
                prev_q = _quality_of(src_dir / o.rel, prev_truth)
            if o.status != "ok" or (prev_q is not None and better(q, prev_q)):
                rel = _safe_rel(name) if name in colliding else (name + ".java")
                dest = src_dir / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, dest)
                o.rel = rel
                o.engine = ekey
                o.variant = variant
                o.quality = q
                o.status = "ok" if q.score >= 75 else "partial"
                if o.status == "ok":
                    improved += 1
            o.attempts.append(f"{ekey}:{variant}")

    # ------------------------------------------------------- verification
    print("[5/5] verification ...")
    if verify_all:
        cov_sum = cov_n = 0.0
        with zipfile.ZipFile(input_path) as z:
            for name in good:
                o = outcomes[name]
                try:
                    gt = CF.parse(z.read(entries.get(name, name + ".class")))
                except Exception:
                    continue
                rel = o.rel
                if rel and (src_dir / rel).exists():
                    src = (src_dir / rel).read_text("utf-8", "replace")
                    q = evaluate(src, gt)
                    o.quality = q
                    cov_sum += q.coverage
                    cov_n += 1
                    if q.class_level_failure or q.coverage < 0.9:
                        # A class the engine gave up on wholesale, or one that
                        # is missing a big share of its members, is a failure.
                        # A class that merely lost a method or two is partial --
                        # throwing away the rest of the file would understate
                        # what was actually recovered.
                        if q.class_level_failure or q.coverage < 0.5:
                            o.status = "failed"
                        else:
                            o.status = "partial"
        coverage = (cov_sum / cov_n) if cov_n else None
    else:
        coverage = None
        for name in good:
            if outcomes[name].status == "missing":
                outcomes[name].status = "failed"

    # A native method has no body in the bytecode at all, so counting it as a
    # recovery failure would be wrong. Report it separately.
    native_total = native_classes = 0
    with zipfile.ZipFile(input_path) as z:
        for name in good:
            try:
                cf = CF.parse(z.read(entries.get(name, name + ".class")))
            except Exception:
                continue
            n = sum(1 for m in cf.methods if m.access_flags & CF.ACC_NATIVE)
            if n:
                outcomes[name].native_methods = n
                native_total += n
                native_classes += 1
    if native_total:
        print(f"  {native_total} native method(s) in {native_classes} class(es) "
              f"carry no bytecode and cannot be decompiled")

    ok = sum(1 for o in outcomes.values() if o.status == "ok")
    partial = sum(1 for o in outcomes.values() if o.status == "partial")
    failed = sum(1 for o in outcomes.values() if o.status == "failed")
    missing = sum(1 for o in outcomes.values() if o.status == "missing")
    nbroken = sum(1 for o in outcomes.values() if o.status == "broken")
    if nbroken:
        print(f"  {nbroken} class(es) are unreadable and were quarantined")

    rep = Report(
        input=str(input_path), output=str(src_dir), started=t0, elapsed=time.time() - t0,
        profile=prof, engines_used=order, total=len(good) + len(broken), ok=ok, partial=partial,
        missing=missing, failed=failed, retried=retried, improved=improved,
        coverage_avg=coverage, outcomes=outcomes,
        native_methods=native_total, native_classes=native_classes,
    )
    if clean_work:
        # A real run leaves thousands of intermediate files. Some environments
        # wrap rmtree and abort the process on a bulk delete (not an Exception,
        # so a narrow handler would miss it and the report would never be
        # written). Cleaning up is therefore opt-in, and never fatal.
        try:
            shutil.rmtree(work, ignore_errors=True)
        except BaseException as exc:  # noqa: BLE001
            print(f"  (work dir kept at {work}: {type(exc).__name__})")
    else:
        print(f"  work dir kept at {work} (pass --clean-work to remove it)")
    return rep


def _empty_report(input_path: Path, src_dir: Path, prof, order: list[str],
                  t0: float, names: list[str], broken: list[str]) -> Report:
    return Report(
        input=str(input_path), output=str(src_dir), started=t0, elapsed=time.time() - t0,
        profile=prof, engines_used=order, total=len(names),
        failed=len(broken),
        outcomes={n: ClassOutcome(name=n, status="broken") for n in broken},
        notes=["no readable classes in input"],
    )


def _quality_of(path: Path, cf) -> Quality | None:
    """Re-score a file we already wrote, against the same ground truth."""
    try:
        src = path.read_text("utf-8", "replace")
    except OSError:
        return None
    return evaluate(src, cf)


def _default_engine_order(prof: JarProfile) -> list[str]:
    versions = prof.java_versions or {}
    dominant = max(versions.items(), key=lambda kv: kv[1])[0] if versions else "8"

    def as_int(v: str) -> int:
        try:
            return int(v.split(".")[-1]) if "." in v else int(v)
        except ValueError:
            return 8

    old = as_int(dominant) <= 8
    if old:
        return ["cfr", "procyon", "vineflower"]
    return ["cfr", "vineflower", "procyon"]


def _scan_error_markers(src_dir: Path, all_names: list[str],
                        outcomes: dict[str, ClassOutcome]) -> list[str]:
    """Cheap regex sweep: which already-produced files look broken?"""
    import re
    bad = re.compile(
        r"(could\s*n'?o?t\s+be\s+decompiled|unable\s+to\s+decompile|internal\s+error|"
        r"failed\s+to\s+decompile|error\s+while\s+decompiling)", re.I)
    suspects: list[str] = []
    for name in all_names:
        o = outcomes.get(name)
        if o is None or not o.rel:
            continue
        p = src_dir / o.rel
        if not p.exists():
            continue
        try:
            head = p.read_text("utf-8", "replace")
        except Exception:
            continue
        if bad.search(head):
            o.status = "missing"
            suspects.append(name)
    return suspects


# --------------------------------------------------------------------------
# reporting
# --------------------------------------------------------------------------

def write_report(rep: Report, out_dir: Path) -> None:
    lines = [
        "# decompilation report", "",
        f"- input: `{rep.input}`",
        f"- output: `{rep.output}`",
        f"- classes: {rep.total}",
        f"- engines: {', '.join(rep.engines_used)}",
        f"- elapsed: {rep.elapsed:.1f}s",
        "",
        "## result", "",
        f"| status | count |", "|---|---|",
        f"| fully recovered | {rep.ok} |",
        f"| partial (some members missing) | {rep.partial} |",
        f"| failed | {rep.failed + rep.missing} |",
        f"| unreadable (quarantined) | "
        f"{sum(1 for o in rep.outcomes.values() if o.status == 'broken')} |",
        f"| retried with other engines | {rep.retried} |",
        f"| improved by retry | {rep.improved} |",
    ]
    if rep.coverage_avg is not None:
        lines.append(f"- average member recovery: {rep.coverage_avg * 100:.1f}%")
    if rep.native_methods:
        lines.append(f"- native methods: {rep.native_methods} in "
                     f"{rep.native_classes} classes (no bytecode exists for "
                     f"these; they are declarations only)")
    lines.append("")
    if rep.profile:
        lines += ["## input profile", "", "```", rep.profile.summary(), "```", ""]

    worst = [o for o in rep.outcomes.values()
             if o.status in ("failed", "missing", "partial", "broken")]
    worst.sort(key=lambda o: (o.quality.score if o.quality else 0))
    if worst:
        lines += ["## classes that did not come out clean", ""]
        lines.append("| class | status | score | issue |")
        lines.append("|---|---|---|---|")
        for o in worst[:60]:
            q = o.quality
            issue = (q.issues[0] if q and q.issues else
                     ("no output from any engine" if o.status in ("missing", "failed") else ""))
            lines.append(f"| `{o.name}` | {o.status} | "
                         f"{q.score if q else '-'} | {issue} |")
        if len(worst) > 60:
            lines.append(f"| ... | {len(worst) - 60} more | | |")
        lines.append("")

    (out_dir / "report.md").write_text("\n".join(lines), encoding="utf-8")
    payload = {
        "input": rep.input, "output": rep.output, "elapsed": rep.elapsed,
        "total": rep.total, "ok": rep.ok, "partial": rep.partial,
        "failed": rep.failed + rep.missing, "retried": rep.retried,
        "improved": rep.improved, "coverage_avg": rep.coverage_avg,
        "native_methods": rep.native_methods, "native_classes": rep.native_classes,
        "classes": {k: {"status": v.status, "engine": v.engine, "variant": v.variant,
                        "rel": v.rel,
                        "native_methods": v.native_methods,
                        "score": v.quality.score if v.quality else None,
                        "issues": v.quality.issues if v.quality else []}
                    for k, v in rep.outcomes.items()},
    }
    (out_dir / "report.json").write_text(json.dumps(payload, indent=1), encoding="utf-8")
