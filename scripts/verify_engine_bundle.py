#!/usr/bin/env python3
"""Build or verify an offline bundle of the four decompiler engine jars.

``--build`` runs ONCE on a machine with network access (it calls the normal
downloader, which pins each jar to a hard-coded sha1). Everything after that
is local: ``--verify`` never opens a socket and can run inside an air-gapped
CI job. The jars are never committed and never packaged into the wheel.

Examples:
    python scripts/verify_engine_bundle.py --build /tmp/jdec-engines
    python scripts/verify_engine_bundle.py --build /tmp/jdec-engines --zip /tmp/jdec-engines.zip
    python scripts/verify_engine_bundle.py --verify /tmp/jdec-engines
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from jdec import engines as EN  # noqa: E402 - sys.path is set above on purpose


def _manifest(dest: Path) -> dict:
    paths = {name: rel for rows in EN._ARTIFACTS.values() for name, rel in rows}
    artifacts = []
    for name, sha1 in EN._SHA1.items():
        jar = dest / name
        artifacts.append({
            "name": name,
            "sha1": sha1,
            "size": jar.stat().st_size if jar.is_file() else None,
            "maven_path": paths.get(name),
        })
    return {
        "schema": 1,
        "source": EN.maven_base(),
        "artifacts": artifacts,
        "redistribution": ("Third-party jars. Check each project's licence "
                           "before redistributing; this bundle is NOT part "
                           "of the jdec wheel."),
        "ghidra": "not included (separate large download and licence)",
    }


def build(dest: Path, mirror: str | None, archive: str | None) -> int:
    if mirror:
        os.environ["JDEC_MAVEN_MIRROR"] = mirror
    dest.mkdir(parents=True, exist_ok=True)
    missing = EN.ensure_engines(dest)
    if missing:
        print(f"could not fetch: {', '.join(missing)}")
        return 1
    report = EN.verify_bundle(dest)
    for name, state in report["files"].items():
        print(f"  {name:<40} {state}")
    (dest / "ENGINES.json").write_text(
        json.dumps(_manifest(dest), indent=2), encoding="utf-8")
    if archive:
        base = str(Path(archive).with_suffix(""))
        made = shutil.make_archive(base, "zip", root_dir=dest)
        print(f"archive   : {made}")
    print(f"overall   : {'OK' if report['ok'] else 'FAILED'} ({dest})")
    return 0 if report["ok"] else 1


def verify(dest: Path) -> int:
    report = EN.verify_bundle(dest)
    for name, state in report["files"].items():
        print(f"  {name:<40} {state}")
    print(f"overall   : {'OK' if report['ok'] else 'FAILED'} ({dest})")
    return 0 if report["ok"] else 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--build", metavar="DIR",
                       help="download the four jars and write ENGINES.json")
    group.add_argument("--verify", metavar="DIR",
                       help="check a bundle locally, without any network access")
    p.add_argument("--mirror", default=None, metavar="URL",
                   help="Maven mirror for --build (also JDEC_MAVEN_MIRROR)")
    p.add_argument("--zip", default=None, metavar="PATH",
                   help="with --build, also produce a zip archive of the bundle")
    args = p.parse_args(argv)
    if args.verify:
        return verify(Path(args.verify))
    return build(Path(args.build), args.mirror, args.zip)


if __name__ == "__main__":
    sys.exit(main())
