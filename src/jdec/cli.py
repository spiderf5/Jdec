"""Command line entry point: parse, dispatch, and translate fatal errors."""

from __future__ import annotations

import sys
import zipfile
import zlib
from pathlib import Path

from . import container as CT
from .cli_args import DEFAULT_ENGINES_DIR, build_parser

__all__ = ["main", "build_parser", "DEFAULT_ENGINES_DIR"]

_COMPAT = {
    "_dir_to_jar", "_resolve_input", "_mapping_set_for", "_load_mapping",
    "_write_rewritten", "_read_rewritten", "_print_verify", "_do_project_export",
}


def __getattr__(name: str):
    """Keep ``from jdec import cli as CL`` working for direct handler calls.

    The regression suite calls CL.cmd_deflat / CL.cmd_ircheck / ... directly,
    and one test calls CL._mapping_set_for. Resolve those lazily so importing
    cli stays cheap and cli_commands is only loaded when a command runs.
    """
    if name.startswith("cmd_") or name in _COMPAT:
        from . import cli_commands as CM
        try:
            return getattr(CM, name)
        except AttributeError:
            pass
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def main(argv: list[str] | None = None) -> int:
    if sys.platform == "win32":
        try:
            if hasattr(sys.stdout, "reconfigure"):
                sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            if hasattr(sys.stderr, "reconfigure"):
                sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    args = build_parser().parse_args(argv)
    from . import cli_commands as CM
    handler = getattr(CM, args.handler)
    try:
        return handler(args)
    except (zipfile.BadZipFile, zlib.error) as exc:
        # A corrupt or truncated container is a verdict on the input, not a
        # crash. Letting it escape would mean Python's default status 1 -
        # which every wrapper here reads as "partial success" - and a
        # traceback where the answer should be "this file is damaged".
        hint = ""
        target = getattr(args, "input", None)
        if target:
            try:
                if CT.kind_of(Path(target)) == CT.KIND_CLASS:
                    hint = (" (this is a single class file; ircheck reads one, "
                            "the rest of the commands want a jar)")
            except OSError:
                pass
        print(f"cannot read the input: {type(exc).__name__}: {exc}{hint}")
        return 2
    except CT.ContainerError as exc:
        print(str(exc))
        return 2
    except BrokenPipeError:
        # `jdec decompile big.jar | head` closes the pipe mid-report; that is
        # the reader's choice, not a failure of the run.
        return 0


if __name__ == "__main__":
    sys.exit(main())
