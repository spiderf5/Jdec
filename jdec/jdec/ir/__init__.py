"""The typed-IR layer the roadmap's stage 02 needs, and its gate.

Nothing here mutates a class yet. What it does provide is the precondition:

    `roundtrip` re-assembles every method from its decoded instructions and
    compares the result with the bytes that came in.

That check exists because a rewrite pass is only trustworthy if it can
reproduce its input exactly before it changes anything. If `classfile.parse` +
`bytecode.encode` cannot return the original bytes, then any frame/type work
built on top inherits an unknown amount of corruption, and every later failure
looks like an IR bug when it is really an encoder bug.

Current state (measured 2026-10-29, see jdec/change-report.md):

    class-level  4233/4233 parsed classes byte-identical (the one deliberately
                 truncated fixture is counted as unreadable, not as a pass)
    method-level 33231/33231 Code arrays byte-identical
    corpus       tests/*.jar + two real-world installers (HMCL 10.5 MB,
                 OptiFine 2.6 MB), 192 distinct opcodes including
                 tableswitch / lookupswitch / wide / multianewarray /
                 invokeinterface / invokedynamic

What belongs here next, in order, and only after `ircheck` stays green:

    types.py     Type / StackFrame / Label, JVMS 4.10.1.2 merge rules
    assume.py    branch-target frame propagation (the verifier's worklist)
    frames.py    StackMapTable emission from computed frames
    assemble.py  insert/delete/replace instructions + re-layout

`bytecode.encode` already does the re-layout half of that last item; it takes
an explicit `pc_map` for exactly this reason.
"""

from .roundtrip import (  # noqa: F401
    AuditReport,
    MethodMismatch,
    audit_class_bytes,
    audit_path,
    audit_jar,
    audit_dir,
)

__all__ = [
    "AuditReport",
    "MethodMismatch",
    "audit_class_bytes",
    "audit_path",
    "audit_jar",
    "audit_dir",
]
