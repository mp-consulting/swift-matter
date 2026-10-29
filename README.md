# swift-matter

The [Matter](https://csa-iot.org/all-solutions/matter/) smart home protocol in Swift: a Matter node over IP that
Apple Home, Google Home, Amazon Alexa, SmartThings and Home Assistant can commission and control, and a bridge API to
expose other devices as bridged Matter endpoints.

Written against the Matter 1.6.1 specifications. Runs on macOS 14+ and Linux.

## Status

Work in progress. See [CLAUDE.md](CLAUDE.md) for the layout and `bin/dev help` for the development commands.

## Certification

swift-matter is not a certified Matter product. It uses the test vendor ID `0xFFF1` and test attestation
credentials, so commissioners show it as an uncertified device, and some ecosystems only accept it in developer mode.

## Licence

MIT. Portions follow the structure of [matter.js](https://github.com/project-chip/matter.js) and use test vectors from
it and from [connectedhomeip](https://github.com/project-chip/connectedhomeip); see
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
