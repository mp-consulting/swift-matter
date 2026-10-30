<!-- What changes, and why. Link the issue: "Closes #…". -->

## Checklist

- [ ] `bin/dev test` and `bin/dev lint` pass; nothing Darwin-only outside `#if canImport(...)` (CI runs Linux)
- [ ] Byte layouts and crypto checked against the specification's examples or known vectors, cited by section
- [ ] Generated constants used, never hand-typed ids; `Definitions.swift` only changed through `bin/dev generate`
- [ ] Peer input narrowed without traps; no passcode, key or PASE/CASE payload logged
- [ ] No new package dependency
- [ ] User-visible changes have a line in `CHANGELOG.md` under `[Unreleased]`
- [ ] Commissioning, sessions, the Interaction Model or discovery changed: `bin/dev interop-python` passes, and which commissioners were tried is said above
