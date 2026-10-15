# Security and evidence integrity

Vestigium Integrity checks local file content against a separately trusted
manifest. It is an early release, not a forensic acquisition system, digital
signature, authenticity guarantee, or security certification.

## Trust boundaries

- Protect the original manifest separately. Replacing both the files and an
  unsealed reference manifest defeats this integrity check. Optional HMAC seals
  authenticate the embedded manifest only while the separate shared key remains
  secret. Every key holder can forge a valid seal; this does not identify an author.
- A successful result concerns only recorded paths, regular-file bytes, sizes,
  directory presence, and symbolic-link targets. It does not authenticate
  ownership, permissions, timestamps, extended attributes, or file origins.
- The scanner uses read-only file access, but the operating system may update
  access times. Use appropriate read-only acquisition controls when preservation
  requirements prohibit those updates.
- Symbolic links discovered in the source are recorded and not followed.
  User-supplied path ancestors are resolved normally. Mounted directories remain
  in scope, and manifest paths are never used to open source files.
- Concurrent modifications detected during scanning produce an incomplete
  result. The scan is not an atomic filesystem snapshot; changes after a file is
  read, hostile concurrent directory moves, privileged tampering, and unusual
  filesystem consistency behavior are outside its guarantee.
- Reports and manifests contain filenames and link destinations, which can be
  sensitive. Inspect them before sharing. Run with only the permissions needed
  to read the selected evidence and create the external manifest.
- Seals are not encrypted. Keep the external key out of evidence, source control,
  reports, backups shared with untrusted parties, and public issues. Key files
  require owner-only permissions. The process necessarily holds key bytes in
  memory and does not guarantee their erasure.
- `verify-seal` authenticates a bounded envelope. Only its optional `--source`
  mode then checks filesystem content against the authenticated manifest; failed
  authentication prevents scanning. `diff` compares only two validated manifests;
  it neither opens recorded paths nor authenticates the provenance of either input.

Unsupported filesystem objects, unreadable files, malformed manifests, and
detected races must not produce a clean result. Reports that incorrectly claim a
completed match in these cases are security-relevant defects.

## Reporting a vulnerability

Use the repository's **Security → Report a vulnerability** action if private
reporting is enabled. If it is unavailable, open a minimal public issue asking
for a private reporting channel, without sharing exploit details or sensitive
evidence. No dedicated contact address or response-time commitment is provided.

Include the version, operating system and filesystem, expected and observed
behavior, likely impact, and a minimal reproduction using disposable synthetic
files. Do not attach actual evidence, credentials, private manifests, or private
filenames. Fixes target the latest released version.
