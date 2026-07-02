"""CLI entry point for MTF parser.

Usage:  python -m mtf_parser <file.bkf> [--quiet]
"""

import sys
import argparse

from .parser import parse_mtf, MTFParseError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mtf_parser",
        description="Parse and traverse a Microsoft Tape Format (BKF) backup file.",
    )
    parser.add_argument(
        "file",
        help="Path to the BKF file to parse.",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress output (just return exit code).",
    )

    args = parser.parse_args(argv)

    try:
        with open(args.file, "rb") as f:
            parse_mtf(f, quiet=args.quiet)
    except FileNotFoundError:
        print(f"Error: file not found — {args.file}", file=sys.stderr)
        return 1
    except MTFParseError as e:
        print(f"Parse error: {e}", file=sys.stderr)
        return 2
    except EOFError as e:
        print(f"Unexpected end of file: {e}", file=sys.stderr)
        return 3
    except OSError as e:
        print(f"I/O error: {e}", file=sys.stderr)
        return 4

    return 0


if __name__ == "__main__":
    sys.exit(main())
