"""Commissions a running matter-bridge-demo with connectedhomeip's Python controller and drives it: the check that
another implementation accepts this one. Run through `bin/dev interop-python`, which installs the controller
(home-assistant-chip-core, a build of connectedhomeip) in a virtual environment of its own.

Usage: python interop.py <work directory>
"""
import asyncio
import os
import re
import sys

import chip.CertificateAuthority
import chip.FabricAdmin
import chip.native
from chip import ChipDeviceCtrl
from chip.ChipStack import ChipStack
import chip.clusters as Clusters

SCRATCH = sys.argv[1]
NODE = 0x4242

# The test PAA the demo's attestation chains to, from the package's own TestCredentials.swift.
credentials = open(os.path.join(os.path.dirname(__file__), "../Sources/Matter/Attestation/TestCredentials.swift")).read()
paa = re.sub(r"[\s\\]", "", re.search(r'paaCertificate = hex\("""(.*?)"""\)', credentials, re.S).group(1))
os.makedirs(f"{SCRATCH}/paa", exist_ok=True)
with open(f"{SCRATCH}/paa/Chip-Test-PAA-FFF1-Cert.der", "wb") as file:
    file.write(bytes.fromhex(paa))
results = []


def check(name, ok, detail=""):
    results.append((name, ok))
    print(("PASS " if ok else "FAIL ") + name + (f": {detail}" if detail else ""), flush=True)


async def main():
    chip.native.Init()
    stack = ChipStack(persistentStoragePath=f"{SCRATCH}/chip-controller.json", enableServerInteractions=False)
    authorities = chip.CertificateAuthority.CertificateAuthorityManager(chipStack=stack)
    authorities.LoadAuthoritiesFromStorage()
    authority = authorities.activeCaList[0] if authorities.activeCaList else authorities.NewCertificateAuthority()
    admin = authority.NewFabricAdmin(vendorId=0xFFF1, fabricId=1)
    controller = admin.NewController(nodeId=112233, paaTrustStorePath=f"{SCRATCH}/paa")

    # Commissioning: discovery over DNS-SD by long discriminator, PASE, attestation against the test PAA, NOC, CASE.
    try:
        await controller.CommissionOnNetwork(nodeId=NODE, setupPinCode=20202021,
                                             filterType=ChipDeviceCtrl.DiscoveryFilterType.LONG_DISCRIMINATOR, filter=3840)
        check("commission on network (PASE, attestation, NOC, CASE)", True)
    except Exception as error:  # noqa: BLE001
        check("commission on network (PASE, attestation, NOC, CASE)", False, repr(error))
        return

    info = await controller.ReadAttribute(NODE, [(0, Clusters.BasicInformation.Attributes.VendorName),
                                                 (0, Clusters.BasicInformation.Attributes.ProductName)])
    basic = info[0][Clusters.BasicInformation]
    check("read Basic Information", basic[Clusters.BasicInformation.Attributes.VendorName] == "swift-matter",
          f"{basic[Clusters.BasicInformation.Attributes.VendorName]} / {basic[Clusters.BasicInformation.Attributes.ProductName]}")

    parts = await controller.ReadAttribute(NODE, [(1, Clusters.Descriptor.Attributes.PartsList)])
    bridged = parts[1][Clusters.Descriptor][Clusters.Descriptor.Attributes.PartsList]
    check("read the Aggregator's PartsList", len(bridged) == 5, f"endpoints {bridged}")

    names = await controller.ReadAttribute(NODE, [(Clusters.BridgedDeviceBasicInformation.Attributes.NodeLabel)])
    labels = sorted(clusters[Clusters.BridgedDeviceBasicInformation][Clusters.BridgedDeviceBasicInformation.Attributes.NodeLabel]
                    for clusters in names.values())
    check("read every bridged device's name (wildcard endpoint)", len(labels) == 5, ", ".join(labels))

    light = bridged[0]
    before = (await controller.ReadAttribute(NODE, [(light, Clusters.OnOff.Attributes.OnOff)]))[light][Clusters.OnOff][Clusters.OnOff.Attributes.OnOff]
    await controller.SendCommand(NODE, light, Clusters.OnOff.Commands.Toggle())
    after = (await controller.ReadAttribute(NODE, [(light, Clusters.OnOff.Attributes.OnOff)]))[light][Clusters.OnOff][Clusters.OnOff.Attributes.OnOff]
    check("invoke OnOff.Toggle and read it back", after == (not before), f"{before} -> {after}")

    await controller.SendCommand(NODE, light, Clusters.LevelControl.Commands.MoveToLevelWithOnOff(
        level=77, transitionTime=0, optionsMask=0, optionsOverride=0))
    level = (await controller.ReadAttribute(NODE, [(light, Clusters.LevelControl.Attributes.CurrentLevel)]))[light][Clusters.LevelControl][Clusters.LevelControl.Attributes.CurrentLevel]
    check("invoke LevelControl.MoveToLevelWithOnOff", level == 77, f"level {level}")

    # A subscription reports a change made by another command.
    subscription = await controller.ReadAttribute(NODE, [(light, Clusters.OnOff.Attributes.OnOff)], reportInterval=(0, 10))
    reported = asyncio.Event()
    subscription.SetAttributeUpdateCallback(lambda path, transaction: reported.set())
    await controller.SendCommand(NODE, light, Clusters.OnOff.Commands.Toggle())
    try:
        await asyncio.wait_for(reported.wait(), timeout=10)
        check("subscription reports a change", True)
    except asyncio.TimeoutError:
        check("subscription reports a change", False, "no report in 10 s")
    subscription.Shutdown()

    fabrics = await controller.ReadAttribute(NODE, [(0, Clusters.OperationalCredentials.Attributes.Fabrics)], fabricFiltered=True)
    check("read the fabric list", len(fabrics[0][Clusters.OperationalCredentials][Clusters.OperationalCredentials.Attributes.Fabrics]) == 1)

    controller.Shutdown()
    stack.Shutdown()


asyncio.run(main())
failed = [name for name, ok in results if not ok]
print(f"\n{len(results) - len(failed)}/{len(results)} passed")
sys.exit(1 if failed else 0)
