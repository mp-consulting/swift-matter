#!/usr/bin/env bash
# Commissions a running matter-bridge-demo with connectedhomeip's chip-tool and drives its devices: the check that
# another implementation accepts this one. Needs chip-tool on the PATH (built from project-chip/connectedhomeip, or
# from a package such as Homebrew's chip-tool) and the demo running on this machine:
#
#   bin/dev demo --passcode 20202021 --discriminator 3840 --reset    # in another terminal
#   bin/dev interop [--passcode 20202021] [--node-id 4242]
set -euo pipefail

passcode=20202021
node_id=4242
while [[ $# -gt 0 ]]; do
    case "$1" in
        --passcode) passcode="$2"; shift 2 ;;
        --node-id) node_id="$2"; shift 2 ;;
        *) echo "Unknown option $1" >&2; exit 1 ;;
    esac
done

if ! command -v chip-tool >/dev/null; then
    echo "chip-tool is not installed: build it from https://github.com/project-chip/connectedhomeip (examples/chip-tool)." >&2
    exit 1
fi

# chip-tool keeps its own fabric in /tmp; a fresh one avoids stale pairings.
storage=$(mktemp -d)
trap 'rm -rf "$storage"' EXIT
tool() { chip-tool "$@" --storage-directory "$storage"; }

echo "Commissioning over the network (PASE, attestation with the test PAA, CASE)..."
tool pairing onnetwork "$node_id" "$passcode" --paa-trust-store-path "${PAA_TRUST_STORE:-/dev/null}" --bypass-attestation-verifier true

echo "Reading the bridge's parts and the first bridged device's name..."
tool descriptor read parts-list "$node_id" 1
tool bridgeddevicebasicinformation read node-label "$node_id" 2

echo "Toggling the ceiling light (endpoint 2) and dimming it..."
tool onoff toggle "$node_id" 2
tool levelcontrol move-to-level 64 0 0 0 "$node_id" 2
tool onoff read on-off "$node_id" 2

echo "Reading the thermometer (endpoint 5)..."
tool temperaturemeasurement read measured-value "$node_id" 5

echo "Interop check passed."
