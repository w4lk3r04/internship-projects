"""Command-line entry point for the ATT&CK mapper MVP."""

import argparse
import json
from pathlib import Path
import sys

from .markdown import render_markdown
from .mapper import AttackMapper


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Map a Red Team report to MITRE ATT&CK.")
    parser.add_argument("report", help="Path to a UTF-8 text or Markdown report.")
    parser.add_argument(
        "--markdown-output",
        type=Path,
        help="Also write the threat intelligence matrix to this Markdown file.",
    )
    parser.add_argument(
        "--title",
        default="MITRE ATT&CK Threat Intelligence Matrix",
        help="Title used in the Markdown export.",
    )
    args = parser.parse_args(argv)
    try:
        result = AttackMapper().analyze_file(args.report)
        if args.markdown_output:
            args.markdown_output.write_text(
                render_markdown(result, title=args.title),
                encoding="utf-8",
            )
    except (OSError, UnicodeError) as exc:
        parser.error(str(exc))
    json.dump(result, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
