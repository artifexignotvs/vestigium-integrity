from __future__ import annotations

import argparse
import json
from typing import Any

from . import __version__
from .core import IntegrityError, build_manifest, compare_manifest, load_manifest, prepare_output, scan_directory, write_manifest
from .seal import AuthenticationError, create_seal, diff_manifests, load_key, load_seal, verify_seal, write_seal


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
    diff = commands.add_parser("diff", help="Compare two saved manifests without reading source directories.")
    diff.add_argument("before")
    diff.add_argument("after")
    diff.add_argument("--json", action="store_true")
    seal = commands.add_parser("seal", help="Authenticate a saved manifest using an external shared secret.")
    seal.add_argument("manifest")
    seal.add_argument("--key-file", required=True, help="Owner-only file containing 32 to 4096 raw random bytes.")
    seal.add_argument("--output", required=True, help="New envelope file; existing files are never overwritten.")
    seal.add_argument("--json", action="store_true")
    check = commands.add_parser("verify-seal", help="Verify a shared-secret seal; this does not scan a directory.")
    check.add_argument("seal")
    check.add_argument("--key-file", required=True)
    check.add_argument("--source", help="After authentication succeeds, compare this directory to the embedded manifest.")
    check.add_argument("--json", action="store_true")
    return parser


def _display(report: dict[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(report, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return
    status = report["status"]
    if report["command"] in ("seal", "verify-seal") and status in ("sealed", "authenticated", "unauthenticated"):
        print(status.upper() + ": shared-secret integrity; no author identity or filesystem verification.")
        for issue in report["issues"]:
            print(json.dumps(issue["message"], ensure_ascii=True))
        return
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
        if args.command == "diff":
            report.update(diff_manifests(load_manifest(args.before), load_manifest(args.after)))
            _display(report, args.json)
            return 1 if report["status"] == "different" else 0
        if args.command in ("seal", "verify-seal"):
            key = load_key(args.key_file)
            if args.command == "seal":
                manifest = load_manifest(args.manifest)
                write_seal(args.output, create_seal(manifest, key))
                status = "sealed"
            else:
                manifest = verify_seal(load_seal(args.seal), key)
                status = "authenticated"
            report.update(status=status, complete=True, authentication="shared-secret-hmac-sha256", author_identity_verified=False, filesystem_verified=False)
            if args.command == "verify-seal" and args.source:
                result = scan_directory(args.source)
                report.update(complete=result.complete, summary=result.summary, issues=result.issues)
                if not result.complete:
                    report.update(status="incomplete", changes=None)
                    _display(report, args.json)
                    return 2
                changes = compare_manifest(manifest, result)
                differs = any(changes.values())
                report.update(status="different" if differs else "clean", changes=changes, filesystem_verified=not differs)
                _display(report, args.json)
                return 1 if differs else 0
            _display(report, args.json)
            return 0
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
    except AuthenticationError as error:
        report.update(status="unauthenticated", complete=True, issues=[{"path": ".", "code": "authentication_failed", "message": str(error)}])
        exit_code = 1
    except (IntegrityError, OSError) as error:
        report.update({"status": "error", "complete": False, "issues": [{"path": ".", "code": "operation_error", "message": str(error)}]})
    except KeyboardInterrupt:
        report.update({"status": "incomplete", "complete": False, "issues": [{"path": ".", "code": "interrupted", "message": "Operation interrupted."}]})
    _display(report, args.json)
    return exit_code
