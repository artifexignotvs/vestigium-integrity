"""Sigillum secreto communi constat; auctoritas personae non probatur."""
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import stat
from .core import (IntegrityError, ManifestError, MAX_MANIFEST_BYTES, HEX_DIGEST,
                   _directory_flags, _require_platform, _signature, _unique_object,
                   canonical_json, compare_manifest, ScanResult, validate_manifest)

SEAL_SCHEMA = "vestigium-seal/v1"
MAX_SEAL_BYTES = MAX_MANIFEST_BYTES + 1024
MAX_KEY_BYTES = 4096
MIN_KEY_BYTES = 32


class AuthenticationError(IntegrityError):
    pass


def _read_regular(path, limit, secret=False):
    """Fasciculus finitus sine nexibus et sine divulgatione viae legitur."""
    _require_platform()
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise IntegrityError("Input must be a regular file, without symbolic links.")
            if secret and before.st_mode & 0o077:
                raise IntegrityError("Key file must have owner-only permissions (mode 0600 or 0400).")
            if before.st_size > limit:
                raise IntegrityError("Input exceeds its byte limit.")
            data = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
            current = os.lstat(path)
            if _signature(before) != _signature(after) or _signature(after) != _signature(current):
                raise IntegrityError("Input changed while being read.")
    except OSError:
        raise IntegrityError("Cannot read a stable regular input file.") from None
    if len(data) > limit:
        raise IntegrityError("Input exceeds its byte limit.")
    return data


def load_key(path):
    """Clavis externa tantum in memoria adhibetur."""
    key = _read_regular(path, MAX_KEY_BYTES, secret=True)
    if len(key) < MIN_KEY_BYTES:
        raise IntegrityError("Key file must contain 32 to 4096 raw bytes.")
    return key


def _key(key):
    if not isinstance(key, bytes) or not MIN_KEY_BYTES <= len(key) <= MAX_KEY_BYTES:
        raise IntegrityError("Key must contain 32 to 4096 raw bytes.")


def _payload(manifest):
    validate_manifest(manifest)
    if len(canonical_json(manifest)) > MAX_MANIFEST_BYTES:
        raise ManifestError("Manifest exceeds the 64 MiB size limit.")
    return {"schema": SEAL_SCHEMA, "algorithm": "hmac-sha256", "manifest": manifest}


def create_seal(manifest, key):
    """Omnia campa indicis et formae sub sigillo continentur."""
    _key(key)
    payload = _payload(manifest)
    return {**payload, "tag": hmac.new(key, canonical_json(payload), hashlib.sha256).hexdigest()}


def validate_seal(envelope):
    """Forma externa ante usum clavis probatur."""
    if not isinstance(envelope, dict) or set(envelope) != {"schema", "algorithm", "manifest", "tag"}:
        raise ManifestError("Invalid seal envelope fields.")
    if envelope["schema"] != SEAL_SCHEMA or envelope["algorithm"] != "hmac-sha256":
        raise ManifestError("Unsupported seal schema or algorithm.")
    if not isinstance(envelope["tag"], str) or not HEX_DIGEST.fullmatch(envelope["tag"]):
        raise ManifestError("Invalid seal tag.")
    return _payload(envelope["manifest"])


def verify_seal(envelope, key):
    """Comparatio temporis constantis falso sigillo exitum negat."""
    _key(key)
    payload = validate_seal(envelope)
    expected = hmac.new(key, canonical_json(payload), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(envelope["tag"], expected):
        raise AuthenticationError("Seal authentication failed; the key or sealed content does not match.")
    return envelope["manifest"]


def load_seal(path):
    data = _read_regular(path, MAX_SEAL_BYTES)
    try:
        envelope = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError):
        raise ManifestError("Invalid seal JSON.") from None
    validate_seal(envelope)
    return envelope


def write_seal(output, envelope):
    """Exitus atomicus creandus est; fasciculus prior non deletur."""
    _require_platform()
    if os.link not in os.supports_dir_fd or os.unlink not in os.supports_dir_fd:
        raise IntegrityError("This platform does not support atomic seal creation.")
    validate_seal(envelope)
    data = canonical_json(envelope)
    if len(data) > MAX_SEAL_BYTES:
        raise IntegrityError("Seal exceeds the byte limit.")
    parent_fd = None
    created = False
    temporary = ".vestigium-seal-" + secrets.token_hex(12) + ".tmp"
    try:
        destination = Path(os.path.abspath(output))
        parent = destination.parent.resolve(strict=True)
        parent_fd = os.open(parent, _directory_flags())
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=parent_fd)
        created = True
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, destination.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd, follow_symlinks=False)
    except (OSError, RuntimeError):
        raise IntegrityError("Cannot create seal; destination must be new and its parent must exist.") from None
    finally:
        if parent_fd is not None:
            try:
                if created:
                    os.unlink(temporary, dir_fd=parent_fd)
            finally:
                os.close(parent_fd)


def diff_manifests(before, after):
    """Indices tantum conferuntur; viae inclusae numquam aperiuntur."""
    before, after = validate_manifest(before), validate_manifest(after)
    changes = compare_manifest(before, ScanResult(after["entries"], []))
    left, right = ({item["path"]: item for item in manifest["entries"]} for manifest in (before, after))
    for change in changes["changed"]:
        change.update(before=left[change["path"]], after=right[change["path"]])
    return {"schema": "vestigium-diff/v1", "status": "different" if any(changes.values()) else "clean", "complete": True, "issues": [], "before_sha256": hashlib.sha256(canonical_json(before)).hexdigest(), "after_sha256": hashlib.sha256(canonical_json(after)).hexdigest(), "changes": changes}
