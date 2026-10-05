"""Comprehensive mechanical fixer for the flattened BytecodeVM CFR/VF trees.

Handles the four residual decompiler-artifact classes:
  A. unbox-cascade ternaries with mangled branch types (Object/Boolean/char)
  B. `stackWords[...] = <boolean-expr>;`  -> `= (<expr>) ? 1L : 0L;`
  C. `(boolean)((unbox-ternary))`         -> `((unbox-ternary)) != 0`
Iterates javac until the incompatible-type family is gone.
"""
import re
import subprocess
import sys
import collections

SRC_LIST = "vf2_sources.txt"

# unbox value expressions observed: simple vars, field chains, array accesses
_VAL = r"[\w$.]+(?:\[[^\]]*\])?"

# variant regexes -> normalized int-typed ternary
UNBOX_VARIANTS = [
    # X instanceof Boolean ? (Boolean)X : (X instanceof Character ? (char)((Number)X).intValue() : ((Number)X).intValue())
    re.compile(r"(?P<v>" + _VAL + r") instanceof Boolean \? \(Boolean\)(?P=v) : \((?P=v) instanceof Character \? \(char\)\(\(Number\)(?P=v)\)\.intValue\(\) : \(\(Number\)(?P=v)\)\.intValue\(\)\)\)"),
    # ... ? (Boolean)X : (X instanceof Character ? (Character)X : ((Number)X).intValue())
    re.compile(r"(?P<v>" + _VAL + r") instanceof Boolean \? \(Boolean\)(?P=v) : \((?P=v) instanceof Character \? \(Character\)(?P=v) : \(\(Number\)(?P=v)\)\.intValue\(\)\)\)"),
    # ... ? (Boolean)X : (X instanceof Character ? (int)((Character)X).charValue() : ((Number)X).intValue())
    re.compile(r"(?P<v>" + _VAL + r") instanceof Boolean \? \(Boolean\)(?P=v) : \((?P=v) instanceof Character \? \(int\)\(\(Character\)(?P=v)\)\.charValue\(\) : \(\(Number\)(?P=v)\)\.intValue\(\)\)\)"),
    # ... ? X : (X instanceof Character ? (Character)X : ((Number)X).intValue())
    re.compile(r"(?P<v>" + _VAL + r") instanceof Boolean \? (?P=v) : \((?P=v) instanceof Character \? \(Character\)(?P=v) : \(\(Number\)(?P=v)\)\.intValue\(\)\)\)"),
]


def normalize_unbox(s: str) -> str:
    def repl(m):
        v = m.group("v")
        return (f"({v} instanceof Boolean"
                f" ? (((Boolean){v}).booleanValue() ? 1 : 0)"
                f" : ({v} instanceof Character"
                f" ? ((Character){v}).charValue()"
                f" : ((Number){v}).intValue()))")
    prev = None
    while prev != s:
        prev = s
        for pat in UNBOX_VARIANTS:
            s = pat.sub(repl, s)
    return s


def run_javac() -> list:
    subprocess.run(["javac", "-Xmaxerrs", "500", "-nowarn", "-d", "vf2_built",
                    "@" + SRC_LIST],
                   stdout=open("jc.txt", "wb"), stderr=subprocess.STDOUT)
    data = open("jc.txt", "rb").read().decode("gbk", "replace")
    errs = []
    for l in data.splitlines():
        m = re.match(r"([^\s:]+\.java):(\d+): 错误: (.+)$", l)
        if m:
            errs.append((m.group(1).replace("\\", "/"), int(m.group(2)), m.group(3)))
    return errs


def main() -> int:
    for it in range(8):
        errs = run_javac()
        if not errs:
            print(f"iteration {it}: CLEAN")
            return 0
        kinds = collections.Counter(k[:46] for _f, _l, k in errs)
        print(f"iteration {it}: {len(errs)} errors: " +
              "; ".join(f"{c}x {k}" for k, c in kinds.most_common(5)))

        byfile = collections.defaultdict(list)
        for f, ln, kind in errs:
            byfile[f].append((ln, kind))

        for f, items in byfile.items():
            lines = open(f, encoding="utf-8").read().split("\n")
            changed = False
            for ln, kind in sorted(items, reverse=True):
                line = lines[ln - 1]
                # B: stackWords = <boolean-expr>;
                if "boolean无法转换为long" in kind and "stackWords" in line and "=" in line:
                    pre, rhs = line.split("=", 1)
                    rhs = rhs.strip().rstrip(";")
                    lines[ln - 1] = f"{pre}= ({rhs}) ? 1L : 0L;"
                    changed = True
                # C: (boolean)(int-typed expr)
                elif "int无法转换为boolean" in kind and "(boolean)" in line:
                    lines[ln - 1] = line.replace("(boolean)(", "(", 1)
                    # 找该语句的闭合 ');' → 追加 != 0
                    j = ln - 1
                    depth = 0
                    done = False
                    while j < len(lines) and not done:
                        for ch_idx, ch in enumerate(lines[j]):
                            if ch == "(":
                                depth += 1
                            elif ch == ")":
                                depth -= 1
                                if depth == 0 and lines[j][ch_idx:ch_idx + 2] == ");":
                                    lines[j] = (lines[j][:ch_idx] +
                                                " != 0" + lines[j][ch_idx:])
                                    done = True
                                    break
                        j += 1
                    changed = True
                # A/D: Boolean/Character/Number 级联与 INT#1 —— 统一 normalize
                elif ("Boolean" in kind or "INT#1" in kind or
                      "Character" in kind or "Number" in kind):
                    new_line = normalize_unbox(line)
                    if new_line != line:
                        lines[ln - 1] = new_line
                        changed = True
            if changed:
                open(f, "w", encoding="utf-8").write("\n".join(lines))

    errs = run_javac()
    print(f"final: {len(errs)} error lines")
    for f, ln, k in errs[:10]:
        print(f, ln, k[:70])
    return 0 if not errs else 1


if __name__ == "__main__":
    sys.exit(main())
