"""Argument schema for the jdec CLI.

Each subparser records a ``handler`` name instead of a function object, so
this module never imports the command implementations. cli.main resolves the
name against cli_commands when the command actually runs.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from . import toolchain as TC
from ._version import __version__

DEFAULT_ENGINES_DIR = Path(os.environ.get("JDEC_ENGINES_DIR") or TC.default_engines_dir())


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="jdec",
        description="multi-engine Java decompiler with bytecode-verified output selection",
    )
    p.add_argument("--version", action="version",
                   version=f"%(prog)s {__version__}")
    p.add_argument("--engines-dir", default=str(DEFAULT_ENGINES_DIR),
                   help="where decompiler jars live")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("probe", help="fingerprint a jar without decompiling")
    sp.add_argument("input")
    sp.set_defaults(handler="cmd_probe")

    si = sub.add_parser(
        "ircheck",
        help="byte-exactness gate: parse -> re-assemble -> compare (IR precondition)")
    si.add_argument("input", help="jar, .class file, or a directory of classes")
    si.add_argument("--json", default=None, help="write the full report as JSON")
    si.add_argument("--limit", type=int, default=10,
                    help="show at most N mismatches (default 10)")
    si.add_argument("--allow-undecodable", action="store_true",
                    help="treat classes/methods that could not be decoded as "
                         "acceptable (default: exit 3, because they were "
                         "never checked)")
    si.set_defaults(handler="cmd_ircheck")

    sr = sub.add_parser(
        "reasons",
        help="audit the rewrite journal: every accepted deflat edit must "
             "replay from the original bytes")
    sr.add_argument("original", help="the jar the rewrites started from")
    sr.add_argument("rewritten", nargs="?", default=None,
                    help="optional: also prove every rewritten method is the "
                         "audited derivation")
    sr.add_argument("--json", default=None, help="write the full report as JSON")
    sr.add_argument("--limit", type=int, default=10,
                    help="show at most N problems (default 10)")
    sr.set_defaults(handler="cmd_reasons")

    sv = sub.add_parser(
        "verify",
        help="JVM gate: load every class under -Xverify:all "
             "(proves a rewrite did not break the frames)")
    sv.add_argument("input", help="jar or directory of .class files")
    sv.add_argument("--cp", action="append", default=[],
                    help="extra classpath entry (repeatable); pass the original "
                         "jar when verifying a rewritten one")
    sv.add_argument("--limit", type=int, default=0,
                    help="only check the first N classes")
    sv.add_argument("--show", type=int, default=10,
                    help="show at most N problems per bucket")
    sv.add_argument("--java", default=None,
                    help="java executable to verify with (default: JAVA_HOME); "
                         "classes newer than that JVM are reported SKIP, not INVALID")
    sv.add_argument("--timeout", type=int, default=900)
    sv.add_argument("--focus", default=None,
                    help="rewritten-methods file (from `deflat --rewritten`); "
                         "reports how many of them sit in a class that was not judged")
    sv.add_argument("--siblings", action="store_true",
                    help="also put every other *.jar in the target's directory on "
                         "the classpath (one-shot experiment; can shadow the real deps)")
    sv.add_argument("--allow-skipped", action="store_true",
                    help="treat classes newer than this JVM as acceptable")
    sv.add_argument("--json", default=None, help="write the full report as JSON")
    sv.add_argument("--allow-unresolved", action="store_true",
                    help="classes whose dependencies are missing were not judged; "
                         "without this flag they make the run fail")
    sv.set_defaults(handler="cmd_verify")

    sb = sub.add_parser(
        "behave",
        help="differential behaviour: run the same cases against two jars "
             "and compare (executes target code; needs --execute)")
    sb.add_argument("original", help="the jar you started from")
    sb.add_argument("rewritten", help="the jar a rewrite produced")
    sb.add_argument("--spec", default=None,
                    help="cases file, one per line: class|method|argTypes|argValues "
                         "(types: int,long,boolean,double,float,short,byte,char,FQCN)")
    sb.add_argument("--derive", action="store_true",
                    help="derive cases from the jar itself: every method whose "
                         "parameters can be synthesised (primitives, String, "
                         "arrays, objects), arity <= 8")
    sb.add_argument("--from", dest="from_file", default=None,
                    help="with --derive: only these methods, as written by "
                         "`deflat --rewritten` (class<TAB>name<TAB>descriptor)")
    sb.add_argument("--per-param", type=int, default=4,
                    help="how many inputs per parameter (default 4)")
    sb.add_argument("--no-stable", dest="stable", action="store_false",
                    help="skip the self-consistency baseline (two runs of the "
                         "original are compared to drop non-deterministic cases)")
    sb.add_argument("--execute", action="store_true",
                    help="required: this runs methods from the target jars")
    sb.add_argument("--no-sandbox", dest="no_sandbox",
                    action="store_true",
                    help="run the replay JVM without the Java sandbox: "
                         "writes outside the work dir, network, exec, "
                         "native libraries and System.exit then become "
                         "allowed (unsafe on untrusted jars)")
    sb.add_argument("--cp", action="append", default=None, metavar="PATH",
                    help="extra classpath entry the target needs to load "
                         "(repeatable). Without it every case in a class whose "
                         "supertype lives elsewhere is unusable")
    sb.add_argument("--engine", choices=["jvm", "interp", "both"], default="jvm",
                    help="jvm: reflective differential; interp: the in-memory "
                         "interpreter; both: run and cross-check")
    sb.add_argument("--trials", type=int, default=4,
                    help="interp: deterministic input vectors per method")
    sb.add_argument("--interp-gate", type=float, default=None, metavar="PCT",
                    help="fail (exit 5) when fewer than PCT%% of ALL rewritten "
                         "methods got a conclusive interp verdict")
    sb.add_argument("--union-gate", type=float, default=None, metavar="PCT",
                    help="fail (exit 5) when fewer than PCT%% of ALL rewritten "
                         "methods were judged by either engine (only with "
                         "--engine both)")
    sb.add_argument("--gate", type=float, default=None, metavar="PCT",
                    help="fail (exit 5) when fewer than PCT%% of the invokable "
                         "methods got a verdict")
    sb.add_argument("--value-gate", type=float, default=None, metavar="PCT",
                    help="fail (exit 5) below PCT%% value-only union coverage "
                         "(returned-value evidence only)")
    sb.add_argument("--nodeny-gate", type=float, default=None, metavar="PCT",
                    help="fail (exit 5) below PCT%% after excluding methods "
                         "whose only evidence is a sandbox denial")
    sb.add_argument("--show", type=int, default=10)
    sb.add_argument("--json", default=None)
    sb.set_defaults(handler="cmd_behave")

    se = sub.add_parser("engines", help="download / check decompiler engines")
    se.add_argument("--with-ghidra", action="store_true",
                    help="download and prepare Ghidra Headless native engine into engines/ghidra")
    se.add_argument("--from-dir", default=None, metavar="DIR",
                    help="install from a pre-staged offline engine bundle")
    se.add_argument("--offline", action="store_true",
                    help="never touch the network; copy from --from-dir or report missing")
    se.add_argument("--mirror", default=None, metavar="URL",
                    help="Maven mirror base URL (also JDEC_MAVEN_MIRROR)")
    se.add_argument("--verify-only", action="store_true",
                    help="only verify a bundle's sha1/size/zip integrity, no install")
    se.add_argument("--json", default=None, metavar="PATH",
                    help="write a machine-readable bundle/engine report")
    se.set_defaults(handler="cmd_engines")

    ss = sub.add_parser("strings",
                        help="dump string constants (survives most obfuscation)")
    ss.add_argument("input")
    ss.add_argument("-o", "--output", default=None)
    ss.add_argument("--grep", default=None,
                    help="only literals containing this text (case-insensitive)")
    ss.add_argument("--suspicious", action="store_true",
                    help="only literals that look like url / ip / path / "
                         "credential / exec / machine-id")
    ss.add_argument("--min-len", type=int, default=1,
                    help="skip literals shorter than this")
    ss.add_argument("--limit", type=int, default=0,
                    help="only scan the first N classes")
    ss.set_defaults(handler="cmd_strings")

    sa = sub.add_parser("analyze",
                        help="report what a Minecraft jar hooks into (no decompiling)")
    sa.add_argument("input")
    sa.add_argument("-o", "--output", default=None)
    sa.add_argument("--mc-version", default=None, help="Minecraft version, e.g. 1.20.4")
    sa.add_argument("--mappings", default=None, help="mapping file (proguard/tiny/tsrg)")
    sa.add_argument("--mapping-set", default="auto",
                    choices=["auto", "mojang", "yarn", "mcp", "official-srg", "forge-srg", "none"])
    sa.add_argument("--no-invert", action="store_true",
                    help="mapping file is already obf -> named")
    sa.add_argument("--limit", type=int, default=0,
                    help="only scan the first N classes for signals")
    sa.set_defaults(handler="cmd_analyze")

    sd = sub.add_parser("decompile", help="decompile a jar or class directory")
    sd.add_argument("input")
    sd.add_argument("-o", "--output", default=None)
    sd.add_argument("-e", "--engine", default=None,
                    help="comma separated engine order, e.g. cfr,vineflower,procyon")
    sd.add_argument("-j", "--jobs", type=int, default=0, help="parallel JVMs (default: auto)")
    sd.add_argument("--memory", default="2g", help="heap per JVM, e.g. 4g")
    sd.add_argument("--timeout", type=int, default=1800, help="per-chunk timeout in seconds")
    sd.add_argument("--verify-all", action="store_true",
                    help="score every class against its bytecode (slower, full report)")
    sd.add_argument("--resume", action="store_true", help="reuse existing work in the output dir")
    sd.add_argument("--keep-work", action="store_true",
                    help="kept for compatibility; intermediate files are kept "
                         "by default now")
    sd.add_argument("--clean-work", action="store_true",
                    help="delete the intermediate work directory when done "
                         "(it can hold thousands of files, so this is opt-in)")
    sd.add_argument("--deobf", action="store_true",
                    help="force deobfuscation attempt (auto-enabled for obfuscated Minecraft)")
    sd.add_argument("--mc-version", default=None, help="Minecraft version, e.g. 1.20.4")
    sd.add_argument("--mappings", default=None, help="mapping file (proguard/tiny/tsrg)")
    sd.add_argument("--mapping-set", default="auto",
                    choices=["auto", "mojang", "yarn", "mcp", "official-srg", "forge-srg", "none"],
                    help="which mapping source to fetch")
    sd.add_argument("--limit", type=int, default=0,
                    help="only decompile the first N classes (quick trial run)")
    sd.add_argument("--no-invert", action="store_true",
                    help="mapping file is already obf -> named (do not invert proguard)")
    sd.add_argument("--strict-remap", action="store_true",
                    help="fail the run instead of writing back classes that "
                         "could not be remapped (default: warn loudly)")
    sd.set_defaults(handler="cmd_decompile")

    snv = sub.add_parser("natives",
                         help="extract shipped native libs and read their PE "
                              "export tables (triage for Ghidra/IDA)")
    snv.add_argument("input")
    snv.add_argument("-o", "--output", default=None,
                     help="output dir for extracted libs + report")
    snv.add_argument("--no-decl", action="store_true",
                     help="skip scanning java-side native declarations")
    snv.add_argument("--decompile", action="store_true",
                     help="decompile extracted native libraries to C pseudo-code using Ghidra Headless")
    snv.add_argument("--ghidra", default=None,
                     help="path to Ghidra installation directory (or set GHIDRA_HOME)")
    snv.add_argument("--fetch-ghidra", action="store_true",
                     help="automatically download Ghidra into engines/ghidra if not present")
    snv.add_argument("--mappings", default=None, dest="mappings_tsv",
                     help="frida regnatives TSV (cls, method, sig, ptr, [base, module]) - "
                          "enables address-table mode for dynamically registered natives")
    snv.set_defaults(handler="cmd_natives")

    sdb = sub.add_parser("nativedb",
                         help="build & query an analysis bundle for a dumped "
                              "native library (the IDA+MCP discipline, jdec flavor)")
    sdb.add_argument("input")
    sdb.add_argument("--build", metavar="OUTDIR")
    sdb.add_argument("--search", default=None)
    sdb.add_argument("--strings", action="store_true")
    sdb.set_defaults(handler="cmd_nativedb")

    sop = sub.add_parser("opspool",
                         help="statically decrypt PhantomShield-family "
                              "string pools (DES/CBC + swp inverse, no JVM)")
    sop.add_argument("input")
    sop.add_argument("-o", "--output", default=None,
                     help="output TSV (default: <stem>_ops_pool.tsv)")
    sop.set_defaults(handler="cmd_ops_pool")

    si = sub.add_parser("indy",
                        help="enumerate invokedynamic sites and BootstrapMethods")
    si.add_argument("input")
    si.add_argument("-o", "--output", default=None,
                    help="write detailed JSON (stats + sampled sites)")
    si.add_argument("--sample", type=int, default=40,
                    help="how many classes of site detail to include")
    si.add_argument("--resolve", action="store_true",
                    help="resolve LambdaMetafactory implementation targets "
                         "(owner/name/desc) instead of only counting sites")
    si.set_defaults(handler="cmd_indy")

    sr = sub.add_parser("recover",
                        help="self-consistent replay: decrypt indy-encrypted "
                             "strings/constants by running the target's own "
                             "bootstrap machinery (EXECUTES code from the "
                             "target jar; needs a runnable classpath and "
                             "--execute)")
    sr.add_argument("input")
    sr.add_argument("--execute", action="store_true",
                    help="run the replay JVM. WARNING: the replay EXECUTES "
                         "code from the target jar (initializers, decryptors) "
                         "with your process's permissions; a Java sandbox is "
                         "installed by default, but stubs and timeouts are "
                         "not a substitute for it. Without this flag only "
                         "the static spec is generated.")
    sr.add_argument("--no-sandbox", dest="no_sandbox",
                    action="store_true",
                    help="run the replay JVM without the Java sandbox: "
                         "writes outside the work dir, network, exec, "
                         "native libraries and System.exit then become "
                         "allowed (unsafe on untrusted jars)")
    sr.add_argument("-o", "--output", default=None, help="output dir")
    sr.add_argument("--cp", default="", help="extra classpath entries for the "
                   "replay JVM, ';'-separated on Windows (MC jars, libs, stubs)")
    sr.add_argument("--cp-file", dest="cp_file", default=None,
                    help="file containing classpath entries (one per line or "
                         "';'-joined) - use instead of --cp when long")
    sr.add_argument("--java", default="java", help="java executable to run")
    sr.add_argument("--limit", type=int, default=0,
                    help="only recover the first N classes with sites")
    sr.add_argument("--stop-on-error", action="store_true",
                    help="abort the replay JVM on first failure (debug)")
    sr.add_argument("--timeout", type=int, default=1800,
                    help="kill the replay JVM after N seconds (default 1800); "
                         "every site runs its own decryption for real, so "
                         "big samples can need well over 30 minutes")
    sr.add_argument("--rewrite-src", metavar="DIR", default=None,
                    help="rewrite recovered plaintexts into decompiled "
                         ".java sources under DIR (matches the BSM call "
                         "form Cls.method(\"site\", \"cipher\", seed)); "
                         "pair with decompile output src/")
    sr.add_argument("--from-frida", dest="from_frida", default=None,
                    help="ingest external Frida dynamic dump TSV (mappings, trace, or string dump) "
                         "for source rewriting or combining with replay")
    sr.add_argument("--no-stubs", dest="with_stubs", action="store_false", default=True,
                    help="do not inject synthetic Minecraft runtime stubs into classpath")
    sr.set_defaults(handler="cmd_recover")

    sp = sub.add_parser("pool",
                        help="string-pool (non-indy) decryption via JVM "
                             "replay: scan call sites -> harvest via "
                             "reflective driver -> rewrite sources")
    sp.add_argument("action", choices=["scan", "harvest", "apply"])
    sp.add_argument("input",
                    help="scan: decompiled src dir; harvest: pool_spec.tsv; "
                         "apply: decompiled src dir")
    sp.add_argument("-o", "--output", default=None,
                    help="scan: spec path; harvest: harvest.tsv path; "
                         "apply: rewritten source tree (default <src>_pool)")
    sp.add_argument("--harvest", default=None,
                    help="apply: harvest.tsv from the harvest step")
    sp.add_argument("--from-frida", dest="from_frida", default=None,
                    help="ingest external Frida dynamic dump TSV for source rewriting")
    sp.add_argument("--cp", default="", help="extra classpath entries for "
                    "the replay JVM, ';'-separated on Windows (MC jars, "
                    "lwjgl-api, libs, stubs)")
    sp.add_argument("--cp-file", dest="cp_file", default=None,
                    help="file containing classpath entries (one per line "
                         "or ';'-joined) - use instead of --cp when long")
    sp.add_argument("--java", default="java", help="java executable to run")
    sp.add_argument("--timeout", type=int, default=3600,
                    help="kill the replay JVM after N seconds (default "
                         "3600); partial output is kept on timeout")
    sp.add_argument("--execute", action="store_true",
                    help="harvest: run the replay JVM. WARNING: the replay "
                         "EXECUTES code from the target jar with your "
                         "process's permissions; a Java sandbox is "
                         "installed by default. Required for the harvest "
                         "step.")
    sp.add_argument("--no-sandbox", dest="no_sandbox",
                    action="store_true",
                    help="run the replay JVM without the Java sandbox: "
                         "writes outside the work dir, network, exec, "
                         "native libraries and System.exit then become "
                         "allowed (unsafe on untrusted jars)")
    sp.add_argument("--no-stubs", dest="with_stubs", action="store_false", default=True,
                    help="do not inject synthetic Minecraft runtime stubs into classpath")
    sp.set_defaults(handler="cmd_pool")

    ssc = sub.add_parser("scorecard",
                         help="fixed-metric regression baseline over a set "
                              "of jars (probe+strings, optional "
                              "analyze/decompile); JSON+markdown out, "
                              "--compare diffs against a previous run")
    ssc.add_argument("input", nargs="+",
                     help="jar paths and/or directories (dirs scanned for "
                          "*.jar)")
    ssc.add_argument("-o", "--output", default=None,
                     help="output JSON path (default ./scorecard.json; "
                          "a .md twin is written next to it)")
    ssc.add_argument("--analyze", action="store_true",
                     help="also run the analyze pass (hooks/notes counts)")
    ssc.add_argument("--decompile", action="store_true",
                     help="also decompile (slow; full clean/partial/failed "
                          "counts)")
    ssc.add_argument("--compare", default=None,
                     help="previous scorecard.json - adds a delta section")
    ssc.add_argument("--timeout", type=int, default=1800,
                     help="per-jar decompile timeout (decompile mode only)")
    ssc.set_defaults(handler="cmd_scorecard")

    sw = sub.add_parser("web",
                        help="launch lightweight local web workbench for "
                             "interactive multi-engine review & triage")
    sw.add_argument("input", help="decompiled output directory or jar path")
    sw.add_argument("--port", type=int, default=8080, help="HTTP server port")
    sw.add_argument("--no-browser", action="store_true", help="do not auto-open browser")
    sw.set_defaults(handler="cmd_web")

    sren = sub.add_parser("rename",
                          help="semantic identifier recovery & LLM prompt export")
    sren.add_argument("input", help="source directory or single .java file")
    sren.add_argument("-o", "--output", default=None,
                      help="output ProGuard mapping file with heuristic suggestions")
    sren.add_argument("--prompt-out", default=None,
                      help="export structured JSON prompt for LLM renaming")
    sren.add_argument("--limit", type=int, default=50,
                      help="maximum members to include in prompt export")
    sren.set_defaults(handler="cmd_rename")

    sdef = sub.add_parser("deflat",
                          help="bytecode control flow de-flattening and constant folding")
    sdef.add_argument("input", help="target jar to de-flatten")
    sdef.add_argument("-o", "--output", default=None,
                      help="output jar path (default: <input>_deflat.jar)")
    sdef.add_argument("-j", "--jobs", type=int, default=0, metavar="N",
                      help="rewrite classes in N worker processes (default: "
                           "auto; 1 disables). The process pool is only "
                           "used for the instruction-level path")
    sdef.add_argument("--no-verify", action="store_true",
                      help="skip the -Xverify:all gate (the output is then not "
                           "guaranteed to load)")
    sdef.add_argument("--rewritten", default=None,
                      help="write the class/method/descriptor of every rewritten "
                           "method to this file (input for `behave --from`)")
    sdef.add_argument("--byte-patch", action="store_true",
                      help="use the old byte-patching passes (NOP fill, original "
                           "StackMapTable kept) instead of the instruction-level "
                           "rewrite")
    sdef.add_argument("--recompute-frames", action="store_true",
                      help="with --byte-patch: also regenerate the "
                           "StackMapTables (the instruction-level path always does)")
    sdef.add_argument("--strip-frames", action="store_true",
                      help="byte-patch, then strip the StackMapTables: for feeding "
                           "a decompiler, not for running the jar")
    sdef.add_argument("--no-reasons", action="store_true",
                      help="skip the independent replay of rewrite reasons "
                           "(diagnostics only: the pipeline then reports partial)")
    sdef.add_argument("--cp", action="append", default=None, metavar="PATH",
                      help="extra classpath entry holding the target's libraries "
                           "(repeatable). Frame generation needs the real "
                           "supertypes: without them every merge with a library "
                           "type widens to Object and the verifier rejects the "
                           "method afterwards")
    sdef.set_defaults(handler="cmd_deflat")

    def _add_devirt_args(parser):
        parser.add_argument("input", help="target jar or class file to devirtualize")
        parser.add_argument("--no-verify", action="store_true",
                            help="skip the -Xverify:all gate on the output jar "
                                 "(it is then not guaranteed to load)")
        parser.add_argument("-o", "--output", default=None,
                            help="output path (default: <input>_devirt.<ext>)")
        parser.add_argument("--pool", default=None,
                            help="JSON file containing dumped virtual code pools / methods")
        parser.add_argument("--cp", action="append", default=None, metavar="PATH",
                            help="extra classpath entry holding the target's "
                                 "libraries (repeatable); see `deflat --cp`")
        parser.set_defaults(handler="cmd_devirt")

    sdevirt = sub.add_parser("devirt",
                             help="devirtualize custom bytecode instruction streams to standard JVM bytecode")
    _add_devirt_args(sdevirt)

    sbvm = sub.add_parser("bvm",
                          help="alias for 'devirt' devirtualization")
    _add_devirt_args(sbvm)

    def _add_auto_args(parser):
        parser.add_argument("input", help="target jar or directory")
        parser.add_argument("-o", "--output", default=None,
                            help="output workspace directory (default: <input>_auto)")
        parser.add_argument("--mc-version", default=None, help="Minecraft version (e.g. 1.20.4, 1.8.9)")
        parser.add_argument("--mapping-set", default="auto",
                            choices=["auto", "mojang", "yarn", "mcp", "official-srg", "none"],
                            help="mapping set for deobfuscation (default: auto)")
        parser.add_argument("--mappings", default=None, help="custom mapping file (proguard/tiny/tsrg)")
        parser.add_argument("--no-deflat", action="store_true", help="skip control flow unflattening")
        parser.add_argument("--no-recover", action="store_true", help="skip dynamic replay string decryption")
        parser.add_argument("--allow-replay", action="store_true",
                            help="enable dynamic replay string decryption - EXECUTES code "
                                 "from the target jar on this machine; opt-in, default off")
        parser.add_argument("--no-sandbox", action="store_true",
                            help="run replay without isolation (unsafe on untrusted jars); "
                                 "by default the JVM sandbox is applied, with a "
                                 "process-level fallback on JDK 24+")
        parser.add_argument("--strict", action="store_true",
                            help="CI mode: exit 2 on any stage failure or partial result "
                                 "(default exit codes: 0=success, 1=partial, 2=failed)")
        parser.add_argument("--no-stubs", dest="with_stubs", action="store_false", default=True,
                            help="do not inject synthetic Minecraft runtime stubs into replay classpath")
        parser.add_argument("--no-natives", action="store_true", help="skip native library triage")
        parser.add_argument("--no-analyze", action="store_true", help="skip behavioral analysis / Mixin scan")
        parser.add_argument("-j", "--jobs", type=int, default=0, help="parallel JVMs (0 = auto)")
        parser.add_argument("--timeout", type=int, default=1800, help="decompile timeout in seconds")
        parser.add_argument("--verify-all", action="store_true", help="verify all classes against bytecode")
        parser.add_argument("--web", action="store_true", help="launch Web Workbench on completion")
        parser.add_argument("--port", type=int, default=8080, help="Web Workbench port (default: 8080)")
        parser.add_argument("--clean-work", action="store_true", help="delete intermediate _work directory")
        parser.add_argument("--export-project", action="store_true",
                            help="export complete IDE Gradle project after pipeline")
        parser.add_argument("--compile", action="store_true",
                            help="run javac compilation verification loop after project export")
        parser.add_argument("--cp", default="",
                            help="classpath entries for replay JVM")
        parser.add_argument("--cp-file", dest="cp_file", default=None,
                            help="file with classpath entries for the replay JVM "
                                 "(remapped MC + libraries) - boosts recovery yield")
        parser.set_defaults(handler="cmd_auto")

    sauto = sub.add_parser("auto",
                           help="fully automated end-to-end deobfuscation and triage pipeline")
    _add_auto_args(sauto)

    spipe = sub.add_parser("pipeline",
                           help="alias for 'auto' pipeline")
    _add_auto_args(spipe)

    def _add_reach_args(parser):
        parser.add_argument("input", help="target jar or directory")
        parser.add_argument("-e", "--entrypoints", default=None,
                            help="comma-separated custom entrypoint classes or methods (e.g. com/example/Mod:init)")
        parser.add_argument("-t", "--target", default=None,
                            help="target class or method to trace shortest execution path from entrypoints")
        parser.add_argument("--prune", default=None,
                            help="write a jar dropping SUSPECTED-unused classes only "
                                 "(conservative: keeps indy handles and reflection-by-name "
                                 "targets; not a behaviour-safe slim jar)")
        parser.add_argument("--dot", default=None,
                            help="export call graph in Graphviz DOT format")
        parser.add_argument("--json", default=None,
                            help="export reachability metrics to JSON")
        parser.add_argument("-o", "--output", default=None,
                            help="export markdown reachability audit report")
        parser.set_defaults(handler="cmd_reach")

    sreach = sub.add_parser("reach",
                            help="entrypoint reachability analysis, call graph and dead code pruning")
    _add_reach_args(sreach)

    scg = sub.add_parser("callgraph",
                         help="alias for 'reach' call graph analysis")
    _add_reach_args(scg)

    def _add_project_args(parser):
        parser.add_argument("input", help="target jar to projectize")
        parser.add_argument("-o", "--output", default=None,
                            help="output project directory (default: <input>_project)")
        parser.add_argument("--src", default=None,
                            help="pre-existing decompiled source directory (default: auto-detected or decompiles)")
        parser.add_argument("--mc-version", default=None,
                            help="Minecraft version target (e.g. 1.20.4, 1.8.9)")
        parser.add_argument("--game-intermediary-jar", "--intermediary-jar", default=None,
                            dest="intermediary_jar",
                            help="path to Minecraft client-intermediary.jar for grounding symbols")
        parser.add_argument("--no-stubs", action="store_true",
                            help="skip bundling mc_stubs.jar into libs/")
        parser.add_argument("--compile", action="store_true",
                            help="run javac compilation diagnostic and auto-repair loop")
        parser.set_defaults(handler="cmd_project")

    sproj = sub.add_parser("project",
                           help="export decompiled code as a complete IDE-ready Gradle project")
    _add_project_args(sproj)

    sexp = sub.add_parser("export",
                          help="alias for 'project' IDE project export")
    _add_project_args(sexp)

    return p
