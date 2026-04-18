"""Command-line entry point for dep-audit-cli."""
from __future__ import annotations

import sys
import argparse
from pathlib import Path

from dep_audit.finder import find_dependency_files
from dep_audit.resolver import resolve_dependencies
from dep_audit.auditor import AuditReport, FileAudit
from dep_audit.formatter import render


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dep-audit",
        description="Surface outdated and vulnerable dependencies across Python projects.",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        default=["."],
        metavar="PATH",
        help="Directories to scan (default: current directory).",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        dest="fmt",
        help="Output format (default: text).",
    )
    parser.add_argument(
        "--exit-code",
        action="store_true",
        help="Exit with code 1 when issues are found.",
    )
    return parser


def run(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    file_audits: list[FileAudit] = []

    for raw_path in args.paths:
        root = Path(raw_path).resolve()
        dep_files = find_dependency_files(root)
        for dep_file in dep_files:
            resolved = resolve_dependencies(dep_file)
            file_audits.append(FileAudit(path=dep_file, deps=resolved))

    report = AuditReport(file_audits=file_audits)
    print(render(report, fmt=args.fmt))

    if args.exit_code and report.has_issues:
        return 1
    return 0


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
