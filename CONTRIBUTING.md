# Contributing

Bug reports, fixes, new device kinds and interoperability reports are welcome. For anything larger than a fix, open
an issue first so we can agree on the approach before you spend time on it.

## Setting up

You need Swift 6.0 or later, on macOS 14+ or Linux. `bin/dev` wraps the usual commands (`bin/dev help` lists them):

```bash
bin/dev build
bin/dev test                  # all tests; bin/dev test SPAKE2PlusTests for one suite
bin/dev lint                  # trailing whitespace, tabs, stray prints
bin/dev demo --reset          # a bridge of virtual devices to commission with Apple Home or chip-tool
```

On macOS, `bin/dev` builds outside the repository (`~/Library/Caches`): code signing rejects the Finder metadata on
files under `~/Documents`.

Read [docs/specifications.md](docs/specifications.md) to get the Matter specifications; the code cites them by section
(`Core §4.15`).

## Making a change

- **Follow the specification, and check against known vectors.** Never guess a byte layout. Use the specification's
  examples, the RFCs, the SPAKE2+ draft and the test data of matter.js and connectedhomeip. Crypto is never tested
  only against itself.
- **Use the generated constants** (`OnOffCluster.Attribute.onOff`, `DeviceTypes.extendedColorLight`), never
  hand-typed cluster, attribute or device type ids. `bin/dev generate <matter.js>` regenerates them; never edit
  `Definitions.swift` by hand.
- **Peer input never traps.** Narrow integers from the network with `uint(_:as:)` or `exactly:`: one crash takes
  every bridged device down.
- **Never log secrets:** passcodes, pairing codes, verifiers, keys, session keys or PASE and CASE payloads (log
  their sizes).
- **No new dependencies** beyond swift-nio, swift-crypto and swift-log.
- **Keep Linux building:** Darwin-only APIs go behind `#if canImport(...)`. Use `[UInt8]` for bytes, not `Data`,
  except at Foundation boundaries.
- **Tests** use Swift Testing, wait for what they check (`eventually`) rather than a fixed time, and shorten
  protocol timings with a time scale (`ReliabilityParameters.timeScale`, `InteractionServer.setTimeScale`).
  End-to-end tests commission a node over `MemoryNetwork`.

[CLAUDE.md](CLAUDE.md) has the layout of the sources and the full list of rules.

## Interoperability

A change to commissioning, sessions, the Interaction Model or discovery should still pass
`bin/dev interop-python`: it runs the demo and commissions it with connectedhomeip's own controller (it needs
[uv](https://docs.astral.sh/uv/)). CI runs it on every pull request. `bin/dev interop` does the same with a
`chip-tool` you have built. Reports of what works, or not, with Apple Home, Google Home, Alexa, SmartThings or Home
Assistant are welcome as issues.

## Pull requests

- Commit messages and the pull request title follow [Conventional Commits](https://www.conventionalcommits.org):
  `<type>(<scope>): <summary>`, for example `fix(case): salt a resumed session's keys with the ticket's id`. The
  scopes are listed in [CLAUDE.md](CLAUDE.md).
- Changes that users of the library notice get a line in the `[Unreleased]` section of
  [CHANGELOG.md](CHANGELOG.md).
- CI runs the tests and the lint on macOS and Linux, and the interoperability check; all must pass.

## Releases

A release is a tag with the bare version (`0.5.0`, no `v`), which SwiftPM resolves. Move the `[Unreleased]` section of
CHANGELOG.md under the new version and add its compare link, commit, then tag and publish:

```bash
git tag 0.6.0 && git push origin 0.6.0
gh release create 0.6.0 --title 0.6.0 --notes-file <the version's section>
```

## With an AI assistant

[AGENTS.md](AGENTS.md) (the same file as [CLAUDE.md](CLAUDE.md)) gives coding agents the repository's rules. You
remain responsible for what you submit: read the code, and run it.

## Licence

Contributions are under the MIT licence of this repository. Code or vectors taken from another project keep that
project's notice in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
