# Vestigium Integrity

**Know what changed in a directory. Keep a record you can inspect.**

Vestigium Integrity creates a SHA-256 manifest of a local directory and checks a
later copy against it. It reports modified, missing, and added entries, including
empty directories and symbolic links. An unreadable or changing source produces
an explicit incomplete result, never a successful match.

Useful for checking an exported evidence folder, validating a working copy before
analysis, or detecting unexpected changes to a collected set of files.

- Runs offline with the Python standard library; no runtime dependencies.
- Does not write to inspected files or follow symbolic links inside the tree.
- Produces deterministic JSON manifests with relative paths.
- Offers readable reports, JSON reports, and distinct exit codes for automation.
- Rejects malformed manifests, unsafe paths, duplicate entries, and duplicate JSON fields.

## Quick start

Requires Python 3.10 or newer and a POSIX platform with descriptor-relative,
no-follow filesystem operations. Linux is tested. macOS is expected to support
the required operations but has not been tested. Native Windows is unsupported;
use a Linux environment. Unsupported platforms fail explicitly.

Run directly from a checkout; no installation or network access is needed:

```sh
python3 -m vestigium_integrity snapshot /path/to/evidence --output /path/to/trusted/baseline.json
python3 -m vestigium_integrity verify /path/to/evidence /path/to/trusted/baseline.json
```

The output directory must already exist. The manifest must be outside the source
directory, and an existing manifest is never overwritten. Keep the baseline in a
trusted location separate from the files being checked.

Optional installation creates the `vestigium-integrity` command:

```sh
python3 -m pip install .
vestigium-integrity --help
```

Installation uses the packaging tools specified in `pyproject.toml`; a package
installer may download a build dependency. The scanner itself has no networking,
subprocess, or shell-execution functionality. Direct execution needs no package
installation.

## A safe, disposable demonstration

This example creates a new temporary directory and modifies only its sample files:

```sh
demo_dir="$(mktemp -d)"
mkdir "$demo_dir/evidence"
printf 'Initial observation.\n' > "$demo_dir/evidence/note.txt"
printf 'Supporting record.\n' > "$demo_dir/evidence/attachment.txt"

python3 -m vestigium_integrity snapshot "$demo_dir/evidence" --output "$demo_dir/baseline.json"
python3 -m vestigium_integrity verify "$demo_dir/evidence" "$demo_dir/baseline.json"

printf 'Altered observation.\n' > "$demo_dir/evidence/note.txt"
rm "$demo_dir/evidence/attachment.txt"
printf 'Additional record.\n' > "$demo_dir/evidence/extra.txt"

python3 -m vestigium_integrity verify "$demo_dir/evidence" "$demo_dir/baseline.json"
```

The initial check reports `MATCH` with exit code `0`. The final check reports:

```text
DIFFERENCES FOUND
Scanned: 2 files, 0 directories, 0 symbolic links; 40 bytes.
  ADDED: "extra.txt"
  MISSING: "attachment.txt"
  CHANGED: "note.txt" (sha256)
```

The final check exits with code `1`. Its three observations correspond to the
three deliberate changes. The temporary folder remains available for inspection.

## Machine-readable reports

Add `--json` to either command. A valid invocation emits one JSON object on
standard output. Invalid command-line syntax uses the argument parser's normal
error output and exit code `2`.

```sh
python3 -m vestigium_integrity verify /path/to/evidence /path/to/trusted/baseline.json --json
```

A successful verification report looks like this:

```json
{"changes":{"added":[],"changed":[],"missing":[]},"command":"verify","complete":true,"issues":[],"status":"clean","summary":{"bytes":21,"directories":0,"files":1,"symlinks":0}}
```

`changed` contains objects with `path`, `reasons`, `expected_type`, and
`actual_type`. Reasons are `sha256`, `size`, `target`, or `type`. Added and missing
entries are path strings. A rename is reported as one missing and one added path.

| Exit code | Meaning |
| --- | --- |
| `0` | Snapshot created, or completed verification matched. |
| `1` | Completed verification found differences. |
| `2` | Invalid input, unsupported platform, interrupted operation, scan failure, or output failure. |

Verification status is `clean`, `different`, `incomplete`, or `error`. Snapshot
status is `ok`, `incomplete`, or `error`. `complete: false` always means that the
operation did not finish successfully. An incomplete verification uses
`changes: null`; it does not mistake unreadable files for confirmed deletions.
The summary in an incomplete report describes only entries successfully scanned.
No manifest is created from an incomplete scan.

Example CI use:

```sh
python3 -m vestigium_integrity verify "$EVIDENCE_DIR" "$TRUSTED_MANIFEST" --json > integrity-report.json
```

Preserve the command's exit code when integrating it into a pipeline. A report
file by itself does not mean verification passed.

## What the manifest records

The schema is `vestigium-integrity/v1`. Top-level fields are exactly `schema`,
`algorithm`, and `entries`. Entries are sorted by their relative POSIX path.
Generated JSON uses sorted object keys, ASCII escapes, compact separators, UTF-8,
and one final newline. No source-machine path or creation timestamp is embedded,
so identical directory contents produce identical manifests.

| Entry type | Recorded fields |
| --- | --- |
| Regular file | `path`, `type`, `size`, `sha256` |
| Directory | `path`, `type` |
| Symbolic link | `path`, `type`, `target` |

The root directory itself is implicit. Empty directories are included. Symbolic
links to files, directories, missing paths, and paths outside the source are
recorded as links; their destinations are never scanned. A different link target
is a change, but a content change at an unchanged link destination is outside the
manifest's scope. A symbolic link supplied as the source or manifest file is
rejected. Parent components of a user-supplied command-line path are resolved by
the operating system normally.

Names containing a backslash, a NUL, or a leading drive-letter prefix cannot be
represented by this portable path format and make a scan incomplete. Relative
traversal components, absolute paths, empty path components, duplicate entries,
unknown fields, unsupported schemas, missing directory ancestors, invalid
digests, and invalid sizes are rejected during loading. Manifest paths are used
only for comparison: the scanner walks the source independently and never opens
a path supplied by the manifest. Manifests are limited to 64 MiB.

Timestamps, ownership, permissions, extended attributes, alternate data streams,
resource forks, hard-link relationships, sparse-file layout, and deleted files
are not part of the manifest. A metadata-only change between scans will not
necessarily produce a difference. Hard-linked regular files are hashed at each
path. Mounted directories are included; the scanner does not enforce a filesystem
boundary. Special files, such as devices, sockets, and named pipes, produce an
incomplete result rather than being opened for hashing.

## Evidence handling and limits

This is a file-integrity check, not forensic imaging, a digital signature, proof
of origin, or a complete chain-of-custody system. If an attacker can replace both
the files and their manifest, this tool cannot establish that anything changed.
Protect the reference manifest independently, for example in a separately
controlled read-only location.

The scanner opens investigated files only for reading. The operating system may
still update access times when files or directories are read. For strict evidence
preservation, examine an appropriate read-only forensic copy or a source protected
by suitable acquisition controls. Do not interpret this utility as a write blocker.

File identity, size, modification time, and change time are checked before and
after hashing; directory entry lists, metadata, and identities are checked during traversal.
Detected concurrent changes produce an incomplete result. These checks do not
create an atomic point-in-time snapshot of the entire tree and cannot detect every
possible race or privileged modification. A file can change after it has been
hashed. Stop writers or use a stable filesystem snapshot when consistency matters.

Manifest creation uses an atomic, no-overwrite hard-link operation in the output
directory after the scan completes. The destination filesystem must support hard
links. Keep the source and output directory structure stable during an operation;
hostile concurrent directory moves are outside the guarantee. An unexpected process
termination may leave a `.vestigium-*.tmp` file in the output directory. Network
filesystems may provide weaker consistency semantics than local filesystems.

## Development

Run the standard-library test suite from the repository root:

```sh
python3 -m unittest discover -s tests -v
```

Tests cover same-size tampering, additions and deletions, empty directories, type
changes, deterministic serialization, unsafe and malformed manifests, symbolic
links and a link-swap race, inaccessible files, special files, and concurrent
source mutation. They create disposable fixtures and do not need network access.

The project is an early release. Review its scope and validate its behavior in
your own environment before including it in an evidence-handling procedure.

## License

MIT. See [LICENSE](LICENSE).
