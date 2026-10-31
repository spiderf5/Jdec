"""The typed-IR layer the roadmap's stage 02 needs, and its gate.

Nothing here mutates a class yet. What it does provide is the precondition:

    `roundtrip` re-assembles every method from its decoded instructions and
    compares the result with the bytes that came in.

That check exists because a rewrite pass is only trustworthy if it can
reproduce its input exactly before it changes anything. If `classfile.parse` +
`bytecode.encode` cannot return the original bytes, then any frame/type work
built on top inherits an unknown amount of corruption, and every later failure
looks like an IR bug when it is really an encoder bug.

Current state (measured 2026-10-29):

    class-level  4233/4233 parsed classes byte-identical (the one deliberately
                 truncated fixture is counted as unreadable, not as a pass)
    method-level 33231/33231 Code arrays byte-identical
    corpus       tests/*.jar + two real-world installers (HMCL 10.5 MB,
                 OptiFine 2.6 MB), 192 distinct opcodes including
                 tableswitch / lookupswitch / wide / multianewarray /
                 invokeinterface / invokedynamic

What is here now:

    types.py      Type tokens and the JVMS 4.10.1.2 merge rules
    hierarchy.py  common supertypes (jar index + platform classes via the JVM)
    assume.py     the verifier's worklist: instructions -> frames
    frames.py     frames -> StackMapTable payload (always full_frame)
    attrs.py      read/write the sub-attributes nested inside Code
    roundtrip.py  the byte-exactness gate (ircheck)

Measured 2026-10-30 on HMCL (3693 classes / 29,208 methods): frames recomputed
for every method, 0 untypable, 0 classes rejected by `-Xverify:all`. That is the
proof this layer works.

What it is not yet used for: deflat's rewritten methods. There the JVM still asks
for frames at offsets the analysis never reaches (dead padding at the end of a
protected range), so `deflat --recompute-frames` is opt-in and the default keeps
the original table.

What belongs here next:

    assemble.py  insert/delete/replace instructions + re-layout

`bytecode.encode` already does the re-layout half of that; it takes an explicit
`pc_map` for exactly this reason.
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
