from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCHEMA = "vestigium-integrity/v1"
MAX_MANIFEST_BYTES = 64 * 1024 * 1024
CHUNK_SIZE = 1024 * 1024
HEX_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
DRIVE_PREFIX = re.compile(r"[A-Za-z]:")


class IntegrityError(Exception):
    pass


class ManifestError(IntegrityError):
    pass


@dataclass
class ScanResult:
    entries: list[dict[str, Any]]
    issues: list[dict[str, str]]

    @property
    def complete(self) -> bool:
        return not self.issues

    @property
    def summary(self) -> dict[str, int]:
        return {
            "files": sum(item["type"] == "file" for item in self.entries),
            "directories": sum(item["type"] == "directory" for item in self.entries),
            "symlinks": sum(item["type"] == "symlink" for item in self.entries),
            "bytes": sum(item.get("size", 0) for item in self.entries),
        }


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
        + "\n"
    ).encode("utf-8")


def valid_relative_path(value: Any) -> bool:
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        return False
    if value.startswith("/") or DRIVE_PREFIX.match(value):
        return False
    return all(part not in ("", ".", "..") for part in value.split("/"))


def _signature(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _directory_flags() -> int:
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _require_platform() -> None:
    if (
        not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_DIRECTORY")
        or os.open not in os.supports_dir_fd
        or os.stat not in os.supports_dir_fd
        or os.readlink not in os.supports_dir_fd
        or os.scandir not in os.supports_fd
        or os.stat not in os.supports_follow_symlinks
    ):
        raise IntegrityError("This platform does not support the required no-follow filesystem operations.")


def _issue(issues: list[dict[str, str]], path: str, code: str, message: str) -> None:
    issues.append({"path": path or ".", "code": code, "message": message})


def _hash_file(parent_fd: int, name: str, expected: os.stat_result) -> tuple[str, int]:
    # Nexus symbolicus inter inspectionem et aperturam substitutus non sequitur.
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(name, flags, dir_fd=parent_fd)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or _signature(before) != _signature(expected):
            raise IntegrityError("File changed before hashing; take a new snapshot of a stable source.")
        digest = hashlib.sha256()
        size = 0
        while True:
            block = os.read(descriptor, CHUNK_SIZE)
            if not block:
                break
            digest.update(block)
            size += len(block)
            if size > before.st_size:
                raise IntegrityError("File grew during hashing; take a new snapshot of a stable source.")
        after = os.fstat(descriptor)
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        # Mutatio detecta totam inspectionem imperfectam reddit.
        if (
            _signature(before) != _signature(after)
            or _signature(after) != _signature(current)
            or size != before.st_size
        ):
            raise IntegrityError("File changed during hashing; take a new snapshot of a stable source.")
        return digest.hexdigest(), size
    finally:
        os.close(descriptor)


def _walk_directory(
    descriptor: int,
    prefix: str,
    entries: list[dict[str, Any]],
    issues: list[dict[str, str]],
) -> None:
    before = os.fstat(descriptor)
    try:
        with os.scandir(descriptor) as iterator:
            names = sorted(entry.name for entry in iterator)
    except OSError as error:
        _issue(issues, prefix, "unreadable_directory", str(error))
        return
    for name in names:
        relative = f"{prefix}/{name}" if prefix else name
        if not valid_relative_path(relative):
            _issue(issues, relative, "unsupported_path", "Path cannot be represented by the portable manifest format.")
            continue
        try:
            info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISREG(info.st_mode):
                digest, size = _hash_file(descriptor, name, info)
                entries.append({"path": relative, "type": "file", "sha256": digest, "size": size})
            elif stat.S_ISLNK(info.st_mode):
                # Meta nexus describitur; res ad quam ducit non aperitur.
                target = os.readlink(name, dir_fd=descriptor)
                after = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if _signature(info) != _signature(after):
                    raise IntegrityError("Symbolic link changed while being recorded.")
                entries.append({"path": relative, "type": "symlink", "target": target})
            elif stat.S_ISDIR(info.st_mode):
                child = os.open(name, _directory_flags(), dir_fd=descriptor)
                try:
                    opened = os.fstat(child)
                    if _signature(info) != _signature(opened):
                        raise IntegrityError("Directory changed before scanning.")
                    entries.append({"path": relative, "type": "directory"})
                    _walk_directory(child, relative, entries, issues)
                    after = os.fstat(child)
                    current = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                    if _signature(after) != _signature(current):
                        raise IntegrityError("Directory was replaced while being scanned.")
                finally:
                    os.close(child)
            else:
                _issue(issues, relative, "unsupported_type", "Special files are not supported; scan is incomplete.")
        except IntegrityError as error:
            _issue(issues, relative, "source_changed", str(error))
        except OSError as error:
            _issue(issues, relative, "read_error", str(error))
    after = os.fstat(descriptor)
    try:
        with os.scandir(descriptor) as iterator:
            final_names = sorted(entry.name for entry in iterator)
    except OSError as error:
        _issue(issues, prefix, "unreadable_directory", str(error))
        return
    if names != final_names or _signature(before) != _signature(after):
        _issue(issues, prefix, "directory_changed", "Directory entries or metadata changed while being scanned.")


def scan_directory(source: str | Path) -> ScanResult:
    _require_platform()
    source_path = Path(os.path.abspath(source))
    entries: list[dict[str, Any]] = []
    issues: list[dict[str, str]] = []
    try:
        before = os.lstat(source_path)
        if not stat.S_ISDIR(before.st_mode):
            raise IntegrityError("Source must be a directory, and the source itself must not be a symbolic link.")
        descriptor = os.open(source_path, _directory_flags())
        try:
            opened = os.fstat(descriptor)
            if _signature(before) != _signature(opened):
                raise IntegrityError("Source directory changed before scanning.")
            _walk_directory(descriptor, "", entries, issues)
            after = os.fstat(descriptor)
            current = os.lstat(source_path)
            if _signature(after) != _signature(current):
                _issue(issues, ".", "source_changed", "Source directory was replaced while being scanned.")
        finally:
            os.close(descriptor)
    except RecursionError:
        _issue(issues, ".", "depth_limit", "Directory nesting exceeds the scanner depth limit.")
    except OSError as error:
        _issue(issues, ".", "read_error", str(error))
    except IntegrityError as error:
        _issue(issues, ".", "source_changed", str(error))
    return ScanResult(sorted(entries, key=lambda item: item["path"]), sorted(issues, key=lambda item: (item["path"], item["code"])))


def build_manifest(result: ScanResult) -> dict[str, Any]:
    # Index fidelis ex inspectione imperfecta constitui non potest.
    if not result.complete:
        raise IntegrityError("Cannot create a manifest from an incomplete scan.")
    return {"schema": SCHEMA, "algorithm": "sha256", "entries": result.entries}


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ManifestError(f"Duplicate JSON field: {key!r}.")
        result[key] = value
    return result


def validate_manifest(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"schema", "algorithm", "entries"}:
        raise ManifestError("Manifest must contain exactly schema, algorithm, and entries.")
    if value["schema"] != SCHEMA or value["algorithm"] != "sha256":
        raise ManifestError("Unsupported manifest schema or digest algorithm.")
    if not isinstance(value["entries"], list):
        raise ManifestError("Manifest entries must be an array.")
    paths: dict[str, str] = {}
    for item in value["entries"]:
        if not isinstance(item, dict) or not valid_relative_path(item.get("path")):
            raise ManifestError("Each entry must have a safe, relative POSIX path.")
        path = item["path"]
        if path in paths:
            raise ManifestError(f"Duplicate manifest path: {path!r}.")
        kind = item.get("type")
        if kind == "file":
            if set(item) != {"path", "type", "size", "sha256"}:
                raise ManifestError(f"Invalid file fields for {path!r}.")
            if type(item["size"]) is not int or item["size"] < 0:
                raise ManifestError(f"Invalid file size for {path!r}.")
            if not isinstance(item["sha256"], str) or not HEX_DIGEST.fullmatch(item["sha256"]):
                raise ManifestError(f"Invalid SHA-256 digest for {path!r}.")
        elif kind == "directory":
            if set(item) != {"path", "type"}:
                raise ManifestError(f"Invalid directory fields for {path!r}.")
        elif kind == "symlink":
            if set(item) != {"path", "type", "target"}:
                raise ManifestError(f"Invalid symbolic link fields for {path!r}.")
            if not isinstance(item["target"], str) or not item["target"] or "\x00" in item["target"]:
                raise ManifestError(f"Invalid symbolic link target for {path!r}.")
        else:
            raise ManifestError(f"Unsupported entry type for {path!r}.")
        paths[path] = kind
    for path in paths:
        parts = path.split("/")
        for length in range(1, len(parts)):
            parent = "/".join(parts[:length])
            if paths.get(parent) != "directory":
                raise ManifestError(f"Missing directory ancestor for {path!r}.")
    return value


def load_manifest(path: str | Path) -> dict[str, Any]:
    _require_platform()
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise ManifestError("Manifest must be a regular file, not a symbolic link or special file.")
            data = stream.read(MAX_MANIFEST_BYTES + 1)
            after = os.fstat(stream.fileno())
            current = os.lstat(path)
            if _signature(before) != _signature(after) or _signature(after) != _signature(current):
                raise ManifestError("Manifest changed while being read.")
    except OSError as error:
        raise ManifestError(f"Cannot read manifest: {error}") from error
    if len(data) > MAX_MANIFEST_BYTES:
        raise ManifestError("Manifest exceeds the 64 MiB size limit.")
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise ManifestError(f"Invalid manifest JSON: {error}") from error
    return validate_manifest(value)


def prepare_output(source: str | Path, output: str | Path) -> Path:
    try:
        source_path = Path(source).resolve(strict=True)
        output_path = Path(os.path.abspath(output))
        parent = output_path.parent.resolve(strict=True)
        destination = parent / output_path.name
        if destination == source_path or source_path in destination.parents:
            raise IntegrityError("Manifest output must be outside the source directory.")
        if os.path.lexists(destination):
            raise IntegrityError("Manifest output already exists; choose a new output path.")
        if not parent.is_dir():
            raise IntegrityError("Manifest output parent must be an existing directory.")
        return destination
    except (OSError, RuntimeError, ValueError) as error:
        raise IntegrityError(f"Cannot prepare manifest output: {error}") from error


def write_manifest(source: str | Path, output: str | Path, manifest: dict[str, Any]) -> Path:
    _require_platform()
    if os.link not in os.supports_dir_fd or os.unlink not in os.supports_dir_fd:
        raise IntegrityError("This platform does not support atomic manifest creation.")
    destination = prepare_output(source, output)
    data = canonical_json(validate_manifest(manifest))
    if len(data) > MAX_MANIFEST_BYTES:
        raise IntegrityError("Generated manifest exceeds the 64 MiB size limit.")
    parent_fd = os.open(destination.parent, _directory_flags())
    temporary = f".vestigium-{secrets.token_hex(12)}.tmp"
    created = False
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=parent_fd)
        created = True
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        # Nomen finale uno actu creatur; index prior numquam substituitur.
        os.link(temporary, destination.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd, follow_symlinks=False)
    except OSError as error:
        raise IntegrityError(f"Cannot write manifest: {error}") from error
    finally:
        try:
            if created:
                os.unlink(temporary, dir_fd=parent_fd)
        finally:
            os.close(parent_fd)
    return destination


def compare_manifest(manifest: dict[str, Any], result: ScanResult) -> dict[str, Any]:
    # Viae ex indice tantum comparantur; ad res aperiendas non adhibentur.
    validate_manifest(manifest)
    if not result.complete:
        raise IntegrityError("Cannot report a comparison from an incomplete scan.")
    expected = {item["path"]: item for item in manifest["entries"]}
    actual = {item["path"]: item for item in result.entries}
    changed = []
    for path in sorted(expected.keys() & actual.keys()):
        before, after = expected[path], actual[path]
        if before == after:
            continue
        if before["type"] != after["type"]:
            reasons = ["type"]
        else:
            reasons = [field for field in ("sha256", "size", "target") if before.get(field) != after.get(field)]
        changed.append({"path": path, "reasons": reasons, "expected_type": before["type"], "actual_type": after["type"]})
    return {
        "added": sorted(actual.keys() - expected.keys()),
        "missing": sorted(expected.keys() - actual.keys()),
        "changed": changed,
    }
