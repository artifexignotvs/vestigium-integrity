# Changelog

## 0.2.0

- Compare two saved manifests without reading their source directories.
- Create and verify optional HMAC-SHA256 envelopes with external owner-only key files.
- Optionally check a directory against the embedded manifest only after its seal authenticates.
- Reject malformed envelopes, unsafe paths, ambiguous JSON, unsupported algorithms,
  excessive entry counts, and overlong path/target fields.
- Preserve version 1 manifests and the existing snapshot/verify interface.
- Add tamper, wrong-key, path traversal, bounds, atomic output, privacy, and CLI tests.

## 0.1.0

- Deterministic directory manifests, no-follow traversal, and explicit incomplete-scan reporting.
