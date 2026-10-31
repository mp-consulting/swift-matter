import Testing
@testable import Matter

struct SceneTests {
    typealias C = ScenesManagementCluster.Command
    typealias Info = ScenesManagementCluster.SceneInfoStruct
    typealias Pair = ScenesManagementCluster.AttributeValuePairStruct

    /// A response's fields, or nil for a status.
    func fields(_ result: InvokeResult) -> TLVValue? { if case .response(_, let fields) = result { fields } else { nil } }
    func status(_ result: InvokeResult) -> IMStatus? { if case .status(let status) = result { status.status } else { nil } }

    func scene(_ fixture: BridgeTests.Fixture, _ command: CommandID, group: GroupID = 0, _ scene: UInt64, _ more: [TLVElement] = []) async throws -> InvokeResult {
        try await fixture.invoke(2, ScenesManagementCluster.id, command, [.field(0, .unsigned(UInt64(group))), .field(1, .unsigned(scene))] + more)
    }

    func info(_ fixture: BridgeTests.Fixture) async throws -> TLVValue {
        try #require(try await fixture.read(2, ScenesManagementCluster.id, ScenesManagementCluster.Attribute.fabricSceneInfo).elements?.first?.value)
    }

    /// The commands the device got since `count` of them.
    func commands(_ fixture: BridgeTests.Fixture, after count: Int) async -> [DeviceCommand] { Array(await fixture.commands.values.dropFirst(count)) }

    func set(_ cluster: ClusterID, _ pairs: [(AttributeID, UInt8, UInt64)]) -> TLVElement {
        TLVElement(.structure([.field(0, .unsigned(UInt64(cluster))), .field(1, .array(pairs.map { attribute, field, value in
            TLVElement(.structure([.field(Pair.attributeId, .unsigned(UInt64(attribute))), .field(field, .unsigned(value))]))
        }))]))
    }

    @Test func storesAndRecallsALightsState() async throws {
        let fixture = try await BridgeTests.Fixture()
        let commands = fixture.commands
        _ = try await fixture.bridge.add(BridgedDeviceInfo(id: "lamp", name: "Lamp"), kind: .extendedColorLight(mireds: 153...500)) { await commands.append($0) }
        #expect(try await info(fixture)[Info.currentScene]?.uint == 0xFF)
        _ = try await fixture.invoke(2, OnOffCluster.id, OnOffCluster.Command.on)
        _ = try await fixture.invoke(2, LevelControlCluster.id, LevelControlCluster.Command.moveToLevel,
                                     [.field(0, .unsigned(100)), .field(1, .null), .field(2, .unsigned(0)), .field(3, .unsigned(0))])
        _ = try await fixture.invoke(2, ColorControlCluster.id, ColorControlCluster.Command.moveToColorTemperature,
                                     [.field(0, .unsigned(370)), .field(1, .unsigned(0)), .field(2, .unsigned(0)), .field(3, .unsigned(0))])

        let stored = try #require(fields(try await scene(fixture, C.storeScene, 1)))
        #expect(stored[0]?.uint == 0 && stored[1]?.uint == 0 && stored[2]?.uint == 1)
        var current = try await info(fixture)
        #expect(current[Info.sceneCount]?.uint == 1 && current[Info.currentScene]?.uint == 1 && current[Info.sceneValid] == .bool(true))
        #expect(current[Info.remainingCapacity]?.uint == UInt64(Scenes.capacityPerFabric - 1))

        // ViewScene sends the state back as attribute value pairs.
        let view = try #require(fields(try await scene(fixture, C.viewScene, 1)))
        #expect(view[0]?.uint == 0 && view[3]?.uint == 0 && view[4] == .utf8(""))
        let sets = try #require(view[5]?.elements)
        func value(_ cluster: ClusterID, _ attribute: AttributeID, _ field: UInt8) -> UInt64? {
            sets.first { $0.value[0]?.uint == UInt64(cluster) }?.value[1]?.elements?.first { $0.value[Pair.attributeId]?.uint == UInt64(attribute) }?.value[field]?.uint
        }
        #expect(value(OnOffCluster.id, OnOffCluster.Attribute.onOff, Pair.valueUnsigned8) == 1)
        #expect(value(LevelControlCluster.id, LevelControlCluster.Attribute.currentLevel, Pair.valueUnsigned8) == 100)
        #expect(value(ColorControlCluster.id, ColorControlCluster.Attribute.colorTemperatureMireds, Pair.valueUnsigned16) == 370)
        #expect(value(ColorControlCluster.id, ColorControlCluster.Attribute.enhancedColorMode, Pair.valueUnsigned8) == 2)

        // A command changes the light: the scene is no longer its state.
        _ = try await fixture.invoke(2, OnOffCluster.id, OnOffCluster.Command.off)
        _ = try await fixture.invoke(2, ColorControlCluster.id, ColorControlCluster.Command.moveToHueAndSaturation,
                                     [.field(0, .unsigned(30)), .field(1, .unsigned(200)), .field(2, .unsigned(0)), .field(3, .unsigned(0)), .field(4, .unsigned(0))])
        #expect(try await info(fixture)[Info.sceneValid] == .bool(false))

        // Recalling sets the level and color before turning the light on.
        let before = await commands.values.count
        #expect(status(try await scene(fixture, C.recallScene, 1)) == .success)
        #expect(await self.commands(fixture, after: before) == [.setLevel(100), .setColorTemperature(mireds: 370), .setOn(true)])
        #expect(try await fixture.read(2, ColorControlCluster.id, ColorControlCluster.Attribute.colorMode) == .unsigned(2))
        current = try await info(fixture)
        #expect(current[Info.currentScene]?.uint == 1 && current[Info.sceneValid] == .bool(true))
        #expect(status(try await scene(fixture, C.recallScene, 9)) == .notFound)
    }

    @Test func addsViewsAndRemovesScenes() async throws {
        let fixture = try await BridgeTests.Fixture()
        let commands = fixture.commands
        _ = try await fixture.bridge.add(BridgedDeviceInfo(id: "lamp", name: "Lamp"), kind: .dimmableLight) { await commands.append($0) }
        typealias OnOff = OnOffCluster.Attribute
        typealias Level = LevelControlCluster.Attribute
        // Off at 50, named, with a transition; a set for Color Control, which the light has not, is left out.
        let evening = [set(OnOffCluster.id, [(OnOff.onOff, Pair.valueUnsigned8, 0)]), set(LevelControlCluster.id, [(Level.currentLevel, Pair.valueUnsigned8, 50)]),
                       set(ColorControlCluster.id, [(ColorControlCluster.Attribute.currentX, Pair.valueUnsigned16, 1000)])]
        let added = try #require(fields(try await scene(fixture, C.addScene, 4, [.field(2, .unsigned(1500)), .field(3, .utf8("Evening")), .field(4, .array(evening))])))
        #expect(added[0]?.uint == 0)
        let view = try #require(fields(try await scene(fixture, C.viewScene, 4)))
        #expect(view[3]?.uint == 1500 && view[4] == .utf8("Evening") && view[5]?.elements?.count == 2)

        // Recalling an off scene turns the light off before setting its level.
        let before = await commands.values.count
        #expect(status(try await scene(fixture, C.recallScene, 4)) == .success)
        #expect(await self.commands(fixture, after: before) == [.setOn(false), .setLevel(50)])

        // A level out of range is null for the nullable CurrentLevel, sent back as 0xFF; a boolean other than 0 or 1 is false.
        let odd = [set(OnOffCluster.id, [(OnOff.onOff, Pair.valueUnsigned8, 7)]), set(LevelControlCluster.id, [(Level.currentLevel, Pair.valueUnsigned8, 0)])]
        _ = try await scene(fixture, C.addScene, 5, [.field(2, .unsigned(0)), .field(3, .utf8("")), .field(4, .array(odd))])
        let oddView = try #require(fields(try await scene(fixture, C.viewScene, 5))?[5]?.elements)
        #expect(oddView.compactMap { $0.value[1]?.elements?.first?.value[Pair.valueUnsigned8]?.uint } == [0, 0xFF])
        // A pair for an attribute scenes do not keep, or with the wrong field, is an invalid command.
        for bad in [set(OnOffCluster.id, [(OnOff.globalSceneControl, Pair.valueUnsigned8, 1)]), set(LevelControlCluster.id, [(Level.currentLevel, Pair.valueUnsigned16, 9)])] {
            let refused = try #require(fields(try await scene(fixture, C.addScene, 6, [.field(2, .unsigned(0)), .field(3, .utf8("")), .field(4, .array([bad]))])))
            #expect(refused[0]?.uint == UInt64(IMStatus.invalidCommand.rawValue))
        }
        // A name over 16 bytes is out of range, not cut.
        let long = try #require(fields(try await scene(fixture, C.addScene, 6, [.field(2, .unsigned(0)), .field(3, .utf8("Seventeen bytes!!")), .field(4, .array([]))])))
        #expect(long[0]?.uint == UInt64(IMStatus.constraintError.rawValue))
        // Scene 255 is out of range and echoed; a group the endpoint is not in is invalid.
        let outOfRange = try #require(fields(try await scene(fixture, C.viewScene, 255)))
        #expect(outOfRange[0]?.uint == UInt64(IMStatus.constraintError.rawValue) && outOfRange[2]?.uint == 255)
        #expect(fields(try await scene(fixture, C.storeScene, group: 7, 1))?[0]?.uint == UInt64(IMStatus.invalidCommand.rawValue))

        // A fabric holds less than half the table.
        for id in 6...10 { #expect(fields(try await scene(fixture, C.storeScene, UInt64(id)))?[0]?.uint == 0) }
        #expect(fields(try await scene(fixture, C.storeScene, 11))?[0]?.uint == UInt64(IMStatus.resourceExhausted.rawValue))
        let membership = try #require(fields(try await fixture.invoke(2, ScenesManagementCluster.id, C.getSceneMembership, [.field(0, .unsigned(0))])))
        #expect(membership[1]?.uint == 0 && membership[3]?.elements?.compactMap(\.value.uint) == [4, 5, 6, 7, 8, 9, 10])

        // CopyScene copies one scene to another id; RemoveScene and RemoveAllScenes clear them.
        _ = try await scene(fixture, C.removeScene, 10)
        let copied = try #require(fields(try await fixture.invoke(2, ScenesManagementCluster.id, C.copyScene, [
            .field(0, .unsigned(0)), .field(1, .unsigned(0)), .field(2, .unsigned(4)), .field(3, .unsigned(0)), .field(4, .unsigned(12)),
        ])))
        #expect(copied[0]?.uint == 0 && copied[2]?.uint == 4)
        #expect(fields(try await scene(fixture, C.viewScene, 12))?[4] == .utf8("Evening"))
        #expect(fields(try await scene(fixture, C.removeScene, 10))?[0]?.uint == UInt64(IMStatus.notFound.rawValue))
        _ = try await fixture.invoke(2, ScenesManagementCluster.id, C.removeAllScenes, [.field(0, .unsigned(0))])
        #expect(try await info(fixture)[Info.sceneCount]?.uint == 0)
    }

    @Test func keepsScenesAcrossRestartsAndDropsThemWithTheirGroup() async throws {
        let fixture = try await BridgeTests.Fixture()
        _ = try await fixture.bridge.add(BridgedDeviceInfo(id: "lamp", name: "Lamp"), kind: .onOffLight)
        try await GroupTests().installGroup(fixture)
        #expect(fields(try await scene(fixture, C.storeScene, group: GroupTests.group, 3))?[0]?.uint == 0)
        #expect(fields(try await scene(fixture, C.storeScene, 1))?[0]?.uint == 0)

        let reloaded = await Scenes(storage: fixture.base.storage)
        #expect(await reloaded.ids(group: GroupTests.group, endpoint: 2, fabric: 1) == [3])
        #expect(await reloaded.scene(.init(fabric: 1, endpoint: 2, group: 0, scene: 1))?.values[OnOffCluster.id]?[OnOffCluster.Attribute.onOff] == .bool(false))

        // Leaving the group removes its scenes; removing the fabric removes the rest.
        _ = try await fixture.invoke(2, GroupsCluster.id, GroupsCluster.Command.removeGroup, [.field(0, .unsigned(UInt64(GroupTests.group)))])
        #expect(await fixture.base.node.scenes.ids(group: GroupTests.group, endpoint: 2, fabric: 1).isEmpty)
        try await fixture.base.node.removeFabric(1)
        #expect(await fixture.base.node.scenes.count(endpoint: 2, fabric: 1) == 0)
    }

    @Test func storesTheGlobalSceneWhenTurnedOffWithAnEffect() async throws {
        let fixture = try await BridgeTests.Fixture()
        let commands = fixture.commands
        _ = try await fixture.bridge.add(BridgedDeviceInfo(id: "lamp", name: "Lamp"), kind: .dimmableLight) { await commands.append($0) }
        _ = try await fixture.invoke(2, LevelControlCluster.id, LevelControlCluster.Command.moveToLevelWithOnOff,
                                     [.field(0, .unsigned(80)), .field(1, .null), .field(2, .unsigned(0)), .field(3, .unsigned(0))])
        _ = try await fixture.invoke(2, OnOffCluster.id, OnOffCluster.Command.offWithEffect, [.field(0, .unsigned(0)), .field(1, .unsigned(0))])
        #expect(try await fixture.read(2, OnOffCluster.id, OnOffCluster.Attribute.globalSceneControl) == .bool(false))
        _ = try await fixture.invoke(2, LevelControlCluster.id, LevelControlCluster.Command.moveToLevel,
                                     [.field(0, .unsigned(30)), .field(1, .null), .field(2, .unsigned(0)), .field(3, .unsigned(0))])

        let before = await commands.values.count
        _ = try await fixture.invoke(2, OnOffCluster.id, OnOffCluster.Command.onWithRecallGlobalScene)
        #expect(await self.commands(fixture, after: before) == [.setLevel(80), .setOn(true), .setOn(true)])
        #expect(try await fixture.read(2, OnOffCluster.id, OnOffCluster.Attribute.globalSceneControl) == .bool(true))
        #expect(try await info(fixture)[Info.currentScene]?.uint == 0)
    }

    @Test func keepsAnEnhancedHue() async throws {
        let fixture = try await BridgeTests.Fixture()
        let commands = fixture.commands
        _ = try await fixture.bridge.add(BridgedDeviceInfo(id: "lamp", name: "Lamp"), kind: .extendedColorLight(mireds: 153...500)) { await commands.append($0) }
        typealias Color = ColorControlCluster.Attribute
        let features = try await fixture.read(2, ColorControlCluster.id, GlobalAttribute.featureMap).uint ?? 0
        #expect(ColorControlCluster.Feature(rawValue: UInt32(features)).contains(.enhancedHue))
        _ = try await fixture.invoke(2, ColorControlCluster.id, ColorControlCluster.Command.enhancedMoveToHueAndSaturation,
                                     [.field(0, .unsigned(0x8040)), .field(1, .unsigned(200)), .field(2, .unsigned(0)), .field(3, .unsigned(0)), .field(4, .unsigned(0))])
        #expect(await commands.values.last == .setHueSaturation(hue: 128, saturation: 200))
        #expect(try await fixture.read(2, ColorControlCluster.id, Color.enhancedCurrentHue) == .unsigned(0x8040))
        #expect(try await fixture.read(2, ColorControlCluster.id, Color.enhancedColorMode) == .unsigned(3))
        _ = try await scene(fixture, C.storeScene, 2)

        _ = try await fixture.invoke(2, ColorControlCluster.id, ColorControlCluster.Command.moveToColorTemperature,
                                     [.field(0, .unsigned(250)), .field(1, .unsigned(0)), .field(2, .unsigned(0)), .field(3, .unsigned(0))])
        let before = await commands.values.count
        #expect(status(try await scene(fixture, C.recallScene, 2)) == .success)
        #expect(await self.commands(fixture, after: before) == [.setOn(false), .setLevel(254), .setHueSaturation(hue: 128, saturation: 200)])
        #expect(try await fixture.read(2, ColorControlCluster.id, Color.enhancedCurrentHue) == .unsigned(0x8040))
    }
}
