"""Run Reflect over a class list, bisecting to isolate JVM-crashing classes.

A native crash in some <clinit> kills the whole JVM (no exception to catch),
so the only way to get through a list that contains such a class is to shrink
the batches until the poison class is alone. Everything decoded before the
crash is already flushed to the shared output file; repeated classes across
bisect runs just produce duplicate lines, removed by the final dedup pass.
"""

import subprocess
import sys
from pathlib import Path

TAP = Path(__file__).resolve().parent
WT = str(TAP).replace("\\", "/")
P = "D:/MC/PCL/.minecraft"
# Myau targets 1.8.9 (mcmod.info). Vanilla 1.8.9 ships its classes in the
# default package (notch names); a Forge mod references SRG names like
# net/minecraft/client/Minecraft, which only exist after FML's runtime
# remap. Essential-loom's cache carries exactly that remap already done:
# minecraft-srg.jar (notch -> SRG) + forge-srg.jar.
LOOM = ("C:/Users/33503/.gradle/caches/essential-loom/1.8.9/"
        "de.oceanlabs.mcp.mcp_stable.1_8_9.22-1.8.9-forge-1.8.9-11.15.1.2318-1.8.9")
CP = ";".join([
    f"{LOOM}/minecraft-srg.jar",
    f"{LOOM}/forge/forge-srg.jar",
    f"{P}/libraries/com/google/code/gson/gson/2.2.4/gson-2.2.4.jar",
    f"{P}/libraries/com/google/guava/guava/17.0/guava-17.0.jar",
    f"{P}/libraries/org/lwjgl/lwjgl/lwjgl/2.9.4-nightly-20150209/lwjgl-2.9.4-nightly-20150209.jar",
    f"{P}/libraries/org/lwjgl/lwjgl/lwjgl_util/2.9.4-nightly-20150209/lwjgl_util-2.9.4-nightly-20150209.jar",
    f"{P}/libraries/org/apache/commons/commons-lang3/3.3.2/commons-lang3-3.3.2.jar",
    f"{P}/libraries/commons-io/commons-io/2.4/commons-io-2.4.jar",
    # round 4 additions: log4j was the top skip reason (37 classes), and
    # 1.8.9's Minecraft.<clinit> does LogManager.getLogger() — the 56
    # "Could not initialize class net.minecraft.client.Minecraft" skips are
    # likely log4j cascades too. launchwrapper + vineflower cover the rest
    # (LaunchClassLoader / IResultSaver refs — Myau bundles a decompiler).
    f"{P}/libraries/org/apache/logging/log4j/log4j-api/2.0-beta9/log4j-api-2.0-beta9.jar",
    f"{P}/libraries/org/apache/logging/log4j/log4j-core/2.0-beta9/log4j-core-2.0-beta9.jar",
    "C:/Users/33503/.gradle/caches/modules-2/files-2.1/net.minecraft/launchwrapper/1.12/111e7bea9c968cdb3d06ef4632bf7ff0824d0f36/launchwrapper-1.12.jar",
    "D:/MC/Workbuddy/deobf/jdec/engines/vineflower-1.11.1.jar",
    "D:/MC/samples/Myau0729-obf.jar",
    f"{WT}/classes",
])


def run(classes: list[str], tag: str) -> bool:
    probe = TAP / f"_probe_{tag}.txt"
    probe.write_text("\n".join(classes) + "\n", encoding="utf-8")
    try:
        r = subprocess.run(
            ["java",
             f"-javaagent:{WT}/stringspy.jar",
             f"-javaagent:{WT}/noexit.jar",
             f"-Dtap.calls={WT}/calls.tsv",
             f"-Dtap.classes={probe.name}",
             f"-Dtap.out={WT}/decoded_full.tsv",
             f"-Dtap.log={WT}/reflect_full.log",
             "-cp", CP, "Reflect"],
            cwd=str(TAP), capture_output=True, timeout=180)
        return r.returncode == 0
    except subprocess.TimeoutExpired:
        return False
    finally:
        probe.unlink(missing_ok=True)


def bisect(classes: list[str], tag: str, poisons: list[str]) -> None:
    if not classes:
        return
    if run(classes, tag):
        print(f"  ok  {tag}: {len(classes)} classes")
        return
    if len(classes) == 1:
        print(f"  POISON {tag}: {classes[0]}")
        poisons.append(classes[0])
        return
    mid = len(classes) // 2
    bisect(classes[:mid], tag + "a", poisons)
    bisect(classes[mid:], tag + "b", poisons)


def main() -> None:
    list_file = Path(sys.argv[1])
    classes = [l.strip() for l in
               list_file.read_text(encoding="utf-8").splitlines() if l.strip()]
    poisons: list[str] = []
    bisect(classes, list_file.stem, poisons)
    print(f"poison classes: {len(poisons)}")
    if poisons:
        (TAP / "poison_classes.txt").open("a", encoding="utf-8").write(
            "\n".join(poisons) + "\n")


if __name__ == "__main__":
    main()
