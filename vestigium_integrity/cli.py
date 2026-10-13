from __future__ import annotations

import argparse
import json
from typing import Any

from . import __version__
from .core import IntegrityError, build_manifest, compare_manifest, load_manifest, prepare_output, scan_directory, write_manifest


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vestigium-integrity",
        description="Create and verify offline SHA-256 directory evidence manifests.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    snapshot = commands.add_parser("snapshot", help="Create a new manifest outside the source directory.")
    snapshot.add_argument("source", help="Directory to inspect; a symbolic link is not accepted.")
    snapshot.add_argument("--output", required=True, help="New manifest file; existing files are never overwritten.")
    snapshot.add_argument("--json", action="store_true", help="Print one machine-readable JSON report.")
    verify = commands.add_parser("verify", help="Compare a directory with a trusted manifest.")
    verify.add_argument("source", help="Directory to inspect.")
    verify.add_argument("manifest", help="Previously saved manifest.")
    verify.add_argument("--json", action="store_true", help="Print one machine-readable JSON report.")
    return parser


def _display(report: dict[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(report, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return
    status = report["status"]
    if status == "ok":
        print(f"SNAPSHOT CREATED: {json.dumps(report['manifest'], ensure_ascii=True)}")
    elif status == "clean":
        print("MATCH: all recorded entries match; no added entries.")
    elif status == "different":
        print("DIFFERENCES FOUND")
    elif status == "incomplete":
        print("INCOMPLETE: scan could not finish; no clean result is available.")
    else:
        print("ERROR: operation could not finish; no clean result is available.")
    summary = report.get("summary")
    if summary is not None:
        print(f"Scanned: {summary['files']} files, {summary['directories']} directories, {summary['symlinks']} symbolic links; {summary['bytes']} bytes.")
    changes = report.get("changes")
    if changes:
        for category in ("added", "missing", "changed"):
            for item in changes[category]:
                path = item["path"] if isinstance(item, dict) else item
                detail = f" ({', '.join(item['reasons'])})" if isinstance(item, dict) else ""
                print(f"  {category.upper()}: {json.dumps(path, ensure_ascii=True)}{detail}")
    for issue in report["issues"]:
        print(f"  {issue['code']}: {json.dumps(issue['path'], ensure_ascii=True)}: {json.dumps(issue['message'], ensure_ascii=True)}")


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    report: dict[str, Any] = {"command": args.command, "status": "error", "complete": False, "issues": []}
    exit_code = 2
    try:
        if args.command == "snapshot":
            prepare_output(args.source, args.output)
            reference = None
        else:
            reference = load_manifest(args.manifest)
        result = scan_directory(args.source)
        report.update({"complete": result.complete, "summary": result.summary, "issues": result.issues})
        if not result.complete:
            report["status"] = "incomplete"
            if args.command == "verify":
                report["changes"] = None
        elif args.command == "snapshot":
            destination = write_manifest(args.source, args.output, build_manifest(result))
            report.update({"status": "ok", "manifest": str(destination)})
            exit_code = 0
        else:
            changes = compare_manifest(reference, result)
            differs = any(changes.values())
            report.update({"status": "different" if differs else "clean", "changes": changes})
            exit_code = 1 if differs else 0
    except (IntegrityError, OSError) as error:
        report.update({"status": "error", "complete": False, "issues": [{"path": ".", "code": "operation_error", "message": str(error)}]})
    except KeyboardInterrupt:
        report.update({"status": "incomplete", "complete": False, "issues": [{"path": ".", "code": "interrupted", "message": "Operation interrupted."}]})
    _display(report, args.json)
    return exit_code
