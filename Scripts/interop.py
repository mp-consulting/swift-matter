"""Commissions the matter-bridge-demo that `bin/dev interop-python` starts with connectedhomeip's Python controller,
and drives it: the check that another implementation accepts this one. `bin/dev interop-python` installs the
controller (home-assistant-chip-core, a build of connectedhomeip) in a virtual environment of its own; CI runs it.

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


async def scenes(controller, lamp):
    """Scenes Management on the color lamp, with connectedhomeip's own encoding of the commands and structures."""
    Scenes = Clusters.ScenesManagement
    Pair, Set = Scenes.Structs.AttributeValuePairStruct, Scenes.Structs.ExtensionFieldSetStruct

    async def read(cluster, attribute):
        return (await controller.ReadAttribute(NODE, [(lamp, attribute)]))[lamp][cluster][attribute]

    async def state():
        return (await read(Clusters.OnOff, Clusters.OnOff.Attributes.OnOff),
                await read(Clusters.LevelControl, Clusters.LevelControl.Attributes.CurrentLevel),
                await read(Clusters.ColorControl, Clusters.ColorControl.Attributes.ColorTemperatureMireds))

    async def info():
        reply = await controller.ReadAttribute(NODE, [(lamp, Scenes.Attributes.FabricSceneInfo)], fabricFiltered=True)
        return reply[lamp][Scenes][Scenes.Attributes.FabricSceneInfo]

    try:
        await controller.SendCommand(NODE, lamp, Clusters.OnOff.Commands.On())
        await controller.SendCommand(NODE, lamp, Clusters.LevelControl.Commands.MoveToLevel(
            level=120, transitionTime=0, optionsMask=0, optionsOverride=0))
        await controller.SendCommand(NODE, lamp, Clusters.ColorControl.Commands.MoveToColorTemperature(
            colorTemperatureMireds=300, transitionTime=0, optionsMask=0, optionsOverride=0))
        stored = await controller.SendCommand(NODE, lamp, Scenes.Commands.StoreScene(groupID=0, sceneID=1))
        check("Scenes: StoreScene", stored.status == 0 and stored.sceneID == 1, repr(stored))

        evening = [
            Set(clusterID=Clusters.OnOff.id, attributeValueList=[Pair(attributeID=Clusters.OnOff.Attributes.OnOff.attribute_id, valueUnsigned8=0)]),
            Set(clusterID=Clusters.LevelControl.id,
                attributeValueList=[Pair(attributeID=Clusters.LevelControl.Attributes.CurrentLevel.attribute_id, valueUnsigned8=40)]),
            Set(clusterID=Clusters.ColorControl.id, attributeValueList=[
                Pair(attributeID=Clusters.ColorControl.Attributes.ColorTemperatureMireds.attribute_id, valueUnsigned16=400),
                Pair(attributeID=Clusters.ColorControl.Attributes.EnhancedColorMode.attribute_id, valueUnsigned8=2)]),
        ]
        added = await controller.SendCommand(NODE, lamp, Scenes.Commands.AddScene(
            groupID=0, sceneID=2, transitionTime=1500, sceneName="Evening", extensionFieldSetStructs=evening))
        check("Scenes: AddScene", added.status == 0, repr(added))
        view = await controller.SendCommand(NODE, lamp, Scenes.Commands.ViewScene(groupID=0, sceneID=2))
        pairs = {(fields.clusterID, pair.attributeID): pair for fields in view.extensionFieldSetStructs for pair in fields.attributeValueList}
        level = pairs.get((Clusters.LevelControl.id, Clusters.LevelControl.Attributes.CurrentLevel.attribute_id))
        mireds = pairs.get((Clusters.ColorControl.id, Clusters.ColorControl.Attributes.ColorTemperatureMireds.attribute_id))
        check("Scenes: ViewScene sends the scene back", view.status == 0 and view.sceneName == "Evening" and view.transitionTime == 1500
              and level is not None and level.valueUnsigned8 == 40 and mireds is not None and mireds.valueUnsigned16 == 400, repr(view))

        membership = await controller.SendCommand(NODE, lamp, Scenes.Commands.GetSceneMembership(groupID=0))
        check("Scenes: GetSceneMembership", membership.status == 0 and sorted(membership.sceneList) == [1, 2], repr(membership))

        await controller.SendCommand(NODE, lamp, Scenes.Commands.RecallScene(groupID=0, sceneID=2))
        recalled = await state()
        check("Scenes: RecallScene of an added scene", recalled == (False, 40, 400), f"on, level, mireds {recalled}")
        await controller.SendCommand(NODE, lamp, Scenes.Commands.RecallScene(groupID=0, sceneID=1))
        recalled = await state()
        check("Scenes: RecallScene of a stored scene", recalled == (True, 120, 300), f"on, level, mireds {recalled}")
        current = await info()
        check("Scenes: FabricSceneInfo", len(current) == 1 and current[0].sceneCount == 2 and current[0].currentScene == 1
              and current[0].sceneValid, repr(current))

        await controller.SendCommand(NODE, lamp, Clusters.ColorControl.Commands.EnhancedMoveToHueAndSaturation(
            enhancedHue=0x8040, saturation=200, transitionTime=0, optionsMask=0, optionsOverride=0))
        hue = await read(Clusters.ColorControl, Clusters.ColorControl.Attributes.EnhancedCurrentHue)
        check("ColorControl.EnhancedMoveToHueAndSaturation", hue == 0x8040, f"enhanced hue {hue:#x}")

        removed = await controller.SendCommand(NODE, lamp, Scenes.Commands.RemoveAllScenes(groupID=0))
        left = (await info())[0].sceneCount
        check("Scenes: RemoveAllScenes", removed.status == 0 and left == 0, f"{removed!r}, {left} left")
    except Exception as error:  # noqa: BLE001
        check("Scenes", False, repr(error))


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

    await scenes(controller, bridged[1])

    fabrics = await controller.ReadAttribute(NODE, [(0, Clusters.OperationalCredentials.Attributes.Fabrics)], fabricFiltered=True)
    check("read the fabric list", len(fabrics[0][Clusters.OperationalCredentials][Clusters.OperationalCredentials.Attributes.Fabrics]) == 1)

    # Without its session, the controller resumes the last one with the ticket Sigma2 gave it (Sigma1 with resumption).
    controller.ExpireSessions(NODE)
    label = "read after resuming the CASE session"
    try:
        resumed = await asyncio.wait_for(controller.ReadAttribute(NODE, [(0, Clusters.BasicInformation.Attributes.VendorName)]), timeout=20)
        check(label, resumed[0][Clusters.BasicInformation][Clusters.BasicInformation.Attributes.VendorName] == "swift-matter")
    except Exception as error:  # noqa: BLE001
        check(label, False, repr(error))

    controller.Shutdown()
    stack.Shutdown()


asyncio.run(main())
failed = [name for name, ok in results if not ok]
print(f"\n{len(results) - len(failed)}/{len(results)} passed")
sys.exit(1 if failed else 0)
