# swift-matter

The Matter protocol (device side, over IP) in Swift: a Matter node that a commissioner (Apple Home, Google Home,
Alexa, SmartThings, Home Assistant, chip-tool) can commission and control, and a bridge API that exposes other devices
as bridged Matter endpoints. Written against the Matter 1.6.1 specifications (Core `23-27349-012`, Application
Clusters `23-27350-011`, Device Library `23-27351-011`). macOS 14+ and Linux. Library `Matter`; the demo bridge is
`matter-bridge-demo`.

## Layout

| Path | What it is |
|---|---|
| `Sources/Matter/TLV` | Matter TLV (Core Appendix A): `TLVValue`/`TLVElement`, `TLVEncoder`/`TLVDecoder`, `TLVStruct` for typed field access |
| `Sources/Matter/Crypto` | `MatterCrypto` (KDF, HMAC, hash, constant-time compare), `AESCCM` (on swift-crypto's AES block function), `PBKDF2`, `P256` (point arithmetic swift-crypto keeps internal: Montgomery field, complete addition formulas, ladder), `SPAKE2Plus` (draft-02, Core §3.10) |
| `Sources/Matter/Certificates` | `DER` (writer and reader), `OID`, `MatterCertificate` (RCAC/ICAC/NOC: TLV ↔ X.509 TBS, signing and verification) |
| `Sources/Matter/Onboarding` | `SetupPayload`: QR code (`MT:` Base38), manual pairing code (Verhoeff), passcode rules |
| `Tests/MatterTests` | Swift Testing suites; vectors from the specification, the SPAKE2+ draft, RFC 3610/7914 and matter.js's tests |
| `bin/dev` | Development commands (`bin/dev help`) |

## Commands

```sh
bin/dev build                 # debug build (scratch path outside ~/Documents on macOS: codesign rejects Finder metadata)
bin/dev test                  # all tests; bin/dev test SPAKE2PlusTests for one suite
bin/dev lint                  # whitespace, tabs, stray prints
bin/dev demo                  # the demo bridge
bin/dev interop               # commission the running demo with matter.js's controller and toggle a light
```

## Rules

- **No Claude attribution in git.** Commit messages and pull requests carry no `Co-Authored-By: Claude` trailer and no
  "Generated with Claude Code" line.
- **Conventional Commits**: `<type>(<scope>): <summary>`, type one of `feat`, `fix`, `perf`, `refactor`, `docs`, `test`,
  `build`, `ci`, `chore`, `style`, `revert`; scope the area (`tlv`, `crypto`, `certificates`, `onboarding`, `messages`,
  `pase`, `case`, `im`, `clusters`, `bridge`, `discovery`, `demo`); summary imperative, no final period.
- **Never guess byte layouts.** Follow the specification and check against known vectors (the spec's examples,
  RFCs, the SPAKE2+ draft, matter.js and connectedhomeip test data). Crypto is never only tested against itself:
  P-256 is checked against swift-crypto, SPAKE2+ against the draft's vectors, certificates against Core §6.5.15.
- **Never log** passcodes, verifiers, keys, session keys, NOC private keys or PASE/CASE payloads (sizes only).
- **No new dependencies** beyond swift-nio, swift-crypto (including `_CryptoExtras`) and swift-log.
- **Keep Linux building**: Darwin-only APIs behind `#if canImport(...)`. Use `[UInt8]` for bytes, not `Data`, except at
  Foundation boundaries.
- Secret comparisons go through `MatterCrypto.equal`; scalar arithmetic on secrets uses the constant-time ladder.
- Tests wait for what they check, never a fixed sleep; time-dependent code (MRP, subscriptions, fail-safe) takes an
  injectable clock or time scale.
- Endpoint numbers of bridged devices are persisted and never reused (Core §9.2.10).
