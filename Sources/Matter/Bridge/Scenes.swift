/// Scenes Management (Application Clusters §1.4): the node's scene table, and the cluster that keeps the state of an
/// endpoint's lighting clusters (On/Off, Level Control, Color Control) as scenes and recalls it.

public typealias SceneID = UInt8

/// The node's scene table: each fabric's scenes on each endpoint, with their names, transition times and the
/// attribute values they set. Persisted; a fabric's scenes go with the fabric, an endpoint's with the endpoint.
public actor Scenes {
    /// Scenes per endpoint (SceneTableSize). A fabric holds less than half of them, so another fabric keeps room.
    public static let tableSize = 16
    public static let capacityPerFabric = (tableSize - 1) / 2

    struct Key: Hashable {
        var fabric: FabricIndex
        var endpoint: EndpointNumber
        /// 0 for a scene outside any group.
        var group: GroupID
        var scene: SceneID
    }

    struct Scene: Equatable {
        /// At most 16 bytes.
        var name: String
        /// Milliseconds, at most 60 000 000.
        var transitionTime: UInt32
        /// The scene attributes of each cluster, as the cluster holds them (`.bool`, `.unsigned`, `.null`).
        var values: [ClusterID: [AttributeID: TLVValue]]
    }

    private var scenes: [Key: Scene] = [:]
    private let storage: any MatterStorage

    public init(storage: any MatterStorage) async {
        self.storage = storage
        if let data = await storage.value(for: StorageKey.scenes), let decoded = try? Self.decode(data) { scenes = decoded }
    }

    func scene(_ key: Key) -> Scene? { scenes[key] }

    /// A group's scenes on an endpoint, in order.
    func ids(group: GroupID, endpoint: EndpointNumber, fabric: FabricIndex) -> [SceneID] {
        scenes.keys.filter { $0.fabric == fabric && $0.endpoint == endpoint && $0.group == group }.map(\.scene).sorted()
    }

    func count(endpoint: EndpointNumber, fabric: FabricIndex) -> Int {
        scenes.keys.count { $0.fabric == fabric && $0.endpoint == endpoint }
    }

    /// How many more scenes the fabric may add on the endpoint: its own share, within what the table has left.
    func remainingCapacity(endpoint: EndpointNumber, fabric: FabricIndex) -> Int {
        let onEndpoint = scenes.keys.filter { $0.endpoint == endpoint }
        let own = onEndpoint.count { $0.fabric == fabric }
        return max(0, min(Self.capacityPerFabric - own, Self.tableSize - onEndpoint.count))
    }

    /// Adds or replaces a scene; a new one needs room.
    func set(_ scene: Scene, for key: Key) async -> IMStatus {
        guard scenes[key] != nil || remainingCapacity(endpoint: key.endpoint, fabric: key.fabric) > 0 else { return .resourceExhausted }
        scenes[key] = scene
        return await saved()
    }

    func remove(_ key: Key) async -> IMStatus {
        guard scenes.removeValue(forKey: key) != nil else { return .notFound }
        return await saved()
    }

    /// Removes a group's scenes on an endpoint (RemoveAllScenes, and a group the endpoint leaves).
    func removeGroup(_ group: GroupID, endpoint: EndpointNumber, fabric: FabricIndex) async -> IMStatus {
        await remove { $0.fabric == fabric && $0.endpoint == endpoint && $0.group == group }
    }

    /// Forgets a removed fabric's scenes.
    public func removeFabric(_ fabric: FabricIndex) async { _ = await remove { $0.fabric == fabric } }

    /// The node leaves an endpoint: its scenes go (a bridged device removed).
    public func removeEndpoint(_ endpoint: EndpointNumber) async { _ = await remove { $0.endpoint == endpoint } }

    private func remove(where matches: (Key) -> Bool) async -> IMStatus {
        let before = scenes.count
        scenes = scenes.filter { !matches($0.key) }
        return scenes.count == before ? .success : await saved()
    }

    private func saved() async -> IMStatus {
        do {
            try await storage.setValue(TLVEncoder.encode(Self.encode(scenes)), for: StorageKey.scenes)
            return .success
        } catch {
            return .failure
        }
    }

    static func encode(_ scenes: [Key: Scene]) -> TLVValue {
        let keys = scenes.keys.sorted { ($0.fabric, $0.endpoint, $0.group, $0.scene) < ($1.fabric, $1.endpoint, $1.group, $1.scene) }
        return .array(keys.map { key in
            let scene = scenes[key]!
            return TLVElement(.structure([
                .field(0, .unsigned(UInt64(key.fabric))), .field(1, .unsigned(UInt64(key.endpoint))), .field(2, .unsigned(UInt64(key.group))),
                .field(3, .unsigned(UInt64(key.scene))), .field(4, .utf8(scene.name)), .field(5, .unsigned(UInt64(scene.transitionTime))),
                .field(6, .array(scene.values.keys.sorted().map { cluster in
                    TLVElement(.structure([
                        .field(0, .unsigned(UInt64(cluster))),
                        .field(1, .array(scene.values[cluster]!.sorted { $0.key < $1.key }.map { attribute, value in
                            TLVElement(.structure([.field(0, .unsigned(UInt64(attribute))), .field(1, value)]))
                        })),
                    ]))
                })),
            ]))
        })
    }

    static func decode(_ data: [UInt8]) throws -> [Key: Scene] {
        var scenes: [Key: Scene] = [:]
        for entry in try TLVDecoder.decode(data).value.elements ?? [] {
            let fields = try TLVStruct(entry.value)
            let key = Key(fabric: try fields.uint(0, as: FabricIndex.self), endpoint: try fields.uint(1, as: EndpointNumber.self),
                          group: try fields.uint(2, as: GroupID.self), scene: try fields.uint(3, as: SceneID.self))
            var values: [ClusterID: [AttributeID: TLVValue]] = [:]
            for cluster in try fields.elements(6) {
                let clusterFields = try TLVStruct(cluster.value)
                var attributes: [AttributeID: TLVValue] = [:]
                for pair in try clusterFields.elements(1) {
                    guard let id = pair.value[0]?.uint.flatMap(AttributeID.init(exactly:)), let value = pair.value[1] else { continue }
                    attributes[id] = value
                }
                values[try clusterFields.uint(0, as: ClusterID.self)] = attributes
            }
            scenes[key] = Scene(name: try fields.string(4), transitionTime: try fields.uint(5, as: UInt32.self), values: values)
        }
        return scenes
    }
}

/// What an endpoint's scenes hold and do: the scene attributes of its clusters (those with the S quality the endpoint
/// supports), how a recall applies them through the clusters' own commands, and the scene each fabric last stored or
/// recalled, valid until a command changes the device.
actor SceneEndpoint {
    /// How a scene attribute travels in an AttributeValuePairStruct: its field, and the values it may take.
    struct Attribute {
        enum Kind { case bool, uint8, uint16 }
        var kind: Kind
        var range: ClosedRange<UInt64>
        var nullable = false

        var field: UInt8 {
            typealias Pair = ScenesManagementCluster.AttributeValuePairStruct
            return kind == .uint16 ? Pair.valueUnsigned16 : Pair.valueUnsigned8
        }

        /// A received value as the attribute takes it: a boolean other than 0 or 1 is null, or false; a
        /// number outside the range is null, or the closest value in it.
        func value(_ received: UInt64) -> TLVValue {
            if kind == .bool { return received <= 1 ? .bool(received == 1) : nullable ? .null : .bool(false) }
            if range.contains(received) { return .unsigned(received) }
            return nullable ? .null : .unsigned(min(max(received, range.lowerBound), range.upperBound))
        }

        /// A stored value as it is sent: null as the type's maximum.
        func received(_ value: TLVValue) -> UInt64 {
            if let bool = value.bool { return bool ? 1 : 0 }
            return value.uint ?? (kind == .uint16 ? 0xFFFF : 0xFF)
        }
    }

    /// The scene attributes of the clusters scenes cover (Application Clusters §1.5.6, §1.6.6, §3.2.7).
    static let attributes: [ClusterID: [AttributeID: Attribute]] = {
        typealias Color = ColorControlCluster.Attribute
        return [
            OnOffCluster.id: [OnOffCluster.Attribute.onOff: Attribute(kind: .bool, range: 0...1)],
            LevelControlCluster.id: [LevelControlCluster.Attribute.currentLevel: Attribute(kind: .uint8, range: 1...254, nullable: true)],
            ColorControlCluster.id: [
                Color.currentSaturation: Attribute(kind: .uint8, range: 0...254), Color.currentX: Attribute(kind: .uint16, range: 0...0xFEFF),
                Color.currentY: Attribute(kind: .uint16, range: 0...0xFEFF), Color.colorTemperatureMireds: Attribute(kind: .uint16, range: 0...0xFEFF),
                Color.enhancedCurrentHue: Attribute(kind: .uint16, range: 0...0xFFFF), Color.enhancedColorMode: Attribute(kind: .uint8, range: 0...3),
            ],
        ]
    }()

    private struct Member {
        weak var cluster: AttributeCluster?
        var attributes: [AttributeID: Attribute]
    }

    struct Current {
        var group: GroupID
        var scene: SceneID
        var valid: Bool
    }

    private var members: [ClusterID: Member] = [:]
    /// The Scenes Management cluster, told when FabricSceneInfo changes.
    private weak var owner: AttributeCluster?
    private var current: [FabricIndex: Current] = [:]

    init() {}

    func setOwner(_ cluster: AttributeCluster) { owner = cluster }

    /// Takes the endpoint's clusters that scenes cover, with the scene attributes each supports.
    func adopt(_ clusters: [any ClusterHandler]) async {
        for case let cluster as AttributeCluster in clusters {
            guard var attributes = Self.attributes[cluster.id] else { continue }
            for id in attributes.keys where await cluster.value(id) == nil { attributes[id] = nil }
            // A color temperature is within the light's physical range.
            if let low = await cluster.value(ColorControlCluster.Attribute.colorTempPhysicalMinMireds)?.uint,
               let high = await cluster.value(ColorControlCluster.Attribute.colorTempPhysicalMaxMireds)?.uint, low <= high {
                attributes[ColorControlCluster.Attribute.colorTemperatureMireds]?.range = low...high
            }
            members[cluster.id] = Member(cluster: cluster, attributes: attributes)
        }
    }

    var endpoint: EndpointNumber? { get async { await owner?.endpoint } }

    // MARK: - Values

    /// The endpoint's state now, for StoreScene.
    func values() async -> [ClusterID: [AttributeID: TLVValue]] {
        var values: [ClusterID: [AttributeID: TLVValue]] = [:]
        for (id, member) in members {
            guard let cluster = member.cluster else { continue }
            for attribute in member.attributes.keys {
                if let value = await cluster.value(attribute) { values[id, default: [:]][attribute] = value }
            }
        }
        return values
    }

    /// AddScene's ExtensionFieldSetStructs: sets for clusters not on the endpoint are left out, the last set
    /// of a cluster and the last pair of an attribute win; nil when a pair is malformed or names an attribute the
    /// endpoint does not keep in scenes.
    func decode(_ sets: [TLVElement]) -> [ClusterID: [AttributeID: TLVValue]]? {
        typealias Set = ScenesManagementCluster.ExtensionFieldSetStruct
        typealias Pair = ScenesManagementCluster.AttributeValuePairStruct
        var values: [ClusterID: [AttributeID: TLVValue]] = [:]
        for set in sets {
            guard let id = set.value[Set.clusterId]?.uint.flatMap(ClusterID.init(exactly:)), let pairs = set.value[Set.attributeValueList]?.elements
            else { return nil }
            guard let member = members[id] else { continue }
            var attributes: [AttributeID: TLVValue] = [:]
            for pair in pairs {
                guard let attributeID = pair.value[Pair.attributeId]?.uint.flatMap(AttributeID.init(exactly:)),
                      let attribute = member.attributes[attributeID], pair.value.elements?.count == 2,
                      let received = pair.value[attribute.field]?.uint else { return nil }
                attributes[attributeID] = attribute.value(received)
            }
            values[id] = attributes
        }
        return values
    }

    /// A scene's values as ExtensionFieldSetStructs, for ViewScene.
    func encode(_ values: [ClusterID: [AttributeID: TLVValue]]) -> TLVValue {
        typealias Set = ScenesManagementCluster.ExtensionFieldSetStruct
        typealias Pair = ScenesManagementCluster.AttributeValuePairStruct
        return .array(values.keys.sorted().compactMap { id in
            guard let member = members[id] else { return nil }
            let pairs = values[id]!.sorted { $0.key < $1.key }.compactMap { attributeID, value -> TLVElement? in
                guard let attribute = member.attributes[attributeID] else { return nil }
                return TLVElement(.structure([.field(Pair.attributeId, .unsigned(UInt64(attributeID))),
                                              .field(attribute.field, .unsigned(attribute.received(value)))]))
            }
            return pairs.isEmpty ? nil : TLVElement(.structure([.field(Set.clusterId, .unsigned(UInt64(id))), .field(Set.attributeValueList, .array(pairs))]))
        })
    }

    // MARK: - Recall

    /// Applies a scene through the clusters' commands, so the device is told as for any command. A light turned off is
    /// turned off first and one turned on last, so its level and color are set before it lights.
    func recall(_ values: [ClusterID: [AttributeID: TLVValue]], context: AccessContext) async throws {
        typealias Color = ColorControlCluster.Attribute
        func invoke(_ cluster: ClusterID, _ command: CommandID, _ fields: [TLVElement] = []) async throws {
            guard let target = members[cluster]?.cluster else { return }
            if case .status(let status) = try await target.invoke(command, fields: .structure(fields), context: context), status.status != .success {
                throw status
            }
        }
        /// TransitionTime 0, OptionsMask and OptionsOverride 0, after a command's own fields.
        func fields(_ values: UInt64...) -> [TLVElement] {
            (values + [0, 0, 0]).enumerated().map { .field(UInt8($0.offset), .unsigned($0.element)) }
        }

        let on = values[OnOffCluster.id]?[OnOffCluster.Attribute.onOff]?.bool
        if on == false { try await invoke(OnOffCluster.id, OnOffCluster.Command.off) }
        if let level = values[LevelControlCluster.id]?[LevelControlCluster.Attribute.currentLevel]?.uint {
            // MoveToLevel's TransitionTime is nullable: null takes the light's default.
            try await invoke(LevelControlCluster.id, LevelControlCluster.Command.moveToLevel,
                             [.field(0, .unsigned(level)), .field(1, .null), .field(2, .unsigned(0)), .field(3, .unsigned(0))])
        }
        let color = values[ColorControlCluster.id] ?? [:]
        let mireds = color[Color.colorTemperatureMireds]?.uint, x = color[Color.currentX]?.uint, y = color[Color.currentY]?.uint
        let hue = color[Color.enhancedCurrentHue]?.uint, saturation = color[Color.currentSaturation]?.uint
        // Without EnhancedColorMode, the color is the one the scene has.
        typealias Mode = ColorControlCluster.EnhancedColorModeEnum
        let mode = color[Color.enhancedColorMode]?.uint
            ?? (mireds != nil ? Mode.colorTemperatureMireds : x != nil ? Mode.currentXAndCurrentY : Mode.enhancedCurrentHueAndCurrentSaturation)
        typealias C = ColorControlCluster.Command
        switch mode {
        case Mode.colorTemperatureMireds:
            if let mireds { try await invoke(ColorControlCluster.id, C.moveToColorTemperature, fields(mireds)) }
        case Mode.currentXAndCurrentY:
            if let x, let y { try await invoke(ColorControlCluster.id, C.moveToColor, fields(x, y)) }
        default:
            let saturation = saturation ?? 0
            switch (hue, mode == Mode.currentHueAndCurrentSaturation) {
            case (let hue?, true): try await invoke(ColorControlCluster.id, C.moveToHueAndSaturation, fields(hue >> 8, saturation))
            // EnhancedMoveToHueAndSaturation has no direction field: hue, saturation, transition time.
            case (let hue?, false): try await invoke(ColorControlCluster.id, C.enhancedMoveToHueAndSaturation, fields(hue, saturation))
            case (nil, _) where color[Color.currentSaturation] != nil:
                try await invoke(ColorControlCluster.id, C.moveToSaturation, fields(saturation))
            default: break
            }
        }
        if on == true { try await invoke(OnOffCluster.id, OnOffCluster.Command.on) }
    }

    // MARK: - The global scene (On/Off's OffWithEffect and OnWithRecallGlobalScene)

    /// The accessing fabric's scene 0 outside any group.
    private func globalKey(_ context: AccessContext) async -> (Scenes, Scenes.Key)? {
        guard let scenes = context.scenes, let fabric = context.fabricIndex, let endpoint = await endpoint else { return nil }
        return (scenes, Scenes.Key(fabric: fabric, endpoint: endpoint, group: 0, scene: 0))
    }

    /// Stores the endpoint's state as the global scene; a full table leaves it unstored.
    func storeGlobal(context: AccessContext) async {
        guard let (scenes, key) = await globalKey(context) else { return }
        var scene = await scenes.scene(key) ?? Scenes.Scene(name: "", transitionTime: 0, values: [:])
        scene.values = await values()
        _ = await scenes.set(scene, for: key)
        await owner?.changed([ScenesManagementCluster.Attribute.fabricSceneInfo])
    }

    /// Recalls the global scene, when there is one.
    func recallGlobal(context: AccessContext) async throws {
        guard let (scenes, key) = await globalKey(context), let scene = await scenes.scene(key) else { return }
        try await recall(scene.values, context: context)
        await activate(group: 0, scene: 0, fabric: key.fabric)
    }

    // MARK: - The current scene

    func current(fabric: FabricIndex) -> Current? { current[fabric] }

    /// The scene the fabric stored or recalled is the endpoint's state; any other fabric's is no longer valid.
    func activate(group: GroupID, scene: SceneID, fabric: FabricIndex) async {
        for index in current.keys { current[index]?.valid = false }
        current[fabric] = Current(group: group, scene: scene, valid: true)
        await owner?.changed([ScenesManagementCluster.Attribute.fabricSceneInfo])
    }

    /// A command changed the device: no scene is valid any more.
    func invalidate() async {
        guard current.values.contains(where: \.valid) else { return }
        for index in current.keys { current[index]?.valid = false }
        await owner?.changed([ScenesManagementCluster.Attribute.fabricSceneInfo])
    }

    /// The device's handler, invalidating the current scene after each command that changes the device.
    nonisolated func invalidating(_ handler: @escaping DeviceCommandHandler) -> DeviceCommandHandler {
        { [self] command in
            try await handler(command)
            if case .identify = command { return }
            await invalidate()
        }
    }
}

extension DeviceClusters {
    /// Scenes Management (Application Clusters §1.4) over the node's `Scenes`, with scene names. A scene in a group
    /// needs the endpoint to be in the group (the Groups cluster); group 0 is outside any group.
    static func scenes(_ state: SceneEndpoint) async -> AttributeCluster {
        typealias A = ScenesManagementCluster.Attribute
        typealias C = ScenesManagementCluster.Command
        let cluster = AttributeCluster(ScenesManagementCluster.definition, featureMap: ScenesManagementCluster.Feature.sceneNames.rawValue,
                                       attributes: [A.sceneTableSize: .unsigned(UInt64(Scenes.tableSize))])
        await state.setOwner(cluster)

        /// The table, the accessing fabric and the endpoint, or the status a command fails with without them.
        @Sendable func scope(_ context: AccessContext) async throws -> (Scenes, FabricIndex, EndpointNumber) {
            guard let scenes = context.scenes, let fabric = context.fabricIndex, let endpoint = await state.endpoint else {
                throw StatusError(.unsupportedAccess)
            }
            return (scenes, fabric, endpoint)
        }
        /// A request's fields; malformed ones are an invalid command.
        @Sendable func request(_ fields: TLVValue) throws -> TLVStruct {
            guard case .structure = fields else { throw StatusError(.invalidCommand) }
            return try TLVStruct(fields)
        }
        @Sendable func number(_ request: TLVStruct, _ tag: UInt8) throws -> UInt64 {
            guard let value = request[tag]?.uint else { throw StatusError(.invalidCommand) }
            return value
        }
        @Sendable func group(_ request: TLVStruct, _ tag: UInt8) throws -> GroupID {
            guard let group = GroupID(exactly: try number(request, tag)) else { throw StatusError(.invalidCommand) }
            return group
        }
        /// Group 0, or a group the endpoint is in for the accessing fabric.
        @Sendable func valid(_ group: GroupID, _ endpoint: EndpointNumber, _ fabric: FabricIndex, _ context: AccessContext) async -> Bool {
            if group == 0 { return true }
            return await context.groups?.name(of: group, endpoint: endpoint, fabric: fabric) != nil
        }
        /// Status, GroupID and SceneID: most responses' fields; SceneID echoes what was asked, even out of range.
        @Sendable func response(_ command: CommandID, _ status: IMStatus, _ group: GroupID, _ scene: UInt64? = nil, _ more: [TLVElement] = []) -> InvokeResult {
            var fields: [TLVElement] = [.field(0, .unsigned(UInt64(status.rawValue))), .field(1, .unsigned(UInt64(group)))]
            if let scene { fields.append(.field(2, .unsigned(scene))) }
            return .response(command, .structure(fields + more))
        }
        @Sendable func changed() async { await cluster.changed([A.fabricSceneInfo]) }

        await cluster.provide(A.fabricSceneInfo) { [weak cluster] context in
            typealias Info = ScenesManagementCluster.SceneInfoStruct
            guard let fabric = context.fabricIndex, let scenes = context.scenes, let endpoint = await cluster?.endpoint else { return .array([]) }
            let current = await state.current(fabric: fabric)
            // A scene removed since it was stored or recalled is no longer the endpoint's state.
            let exists = if let current { await scenes.scene(.init(fabric: fabric, endpoint: endpoint, group: current.group, scene: current.scene)) != nil } else { false }
            return .array([TLVElement(.structure([
                .field(Info.sceneCount, .unsigned(UInt64(await scenes.count(endpoint: endpoint, fabric: fabric)))),
                // 0xFF: no scene stored or recalled yet.
                .field(Info.currentScene, .unsigned(UInt64(current?.scene ?? 0xFF))), .field(Info.currentGroup, .unsigned(UInt64(current?.group ?? 0))),
                .field(Info.sceneValid, .bool(exists && current?.valid == true)),
                .field(Info.remainingCapacity, .unsigned(UInt64(await scenes.remainingCapacity(endpoint: endpoint, fabric: fabric)))),
                .field(Info.fabricIndex, .unsigned(UInt64(fabric))),
            ]))])
        }

        await cluster.handle([
            C.addScene: { _, fields, context in
                let request = try request(fields)
                let group = try group(request, 0), scene = try number(request, 1)
                let transitionTime = try number(request, 2)
                guard let name = request[3]?.string, let sets = request[4]?.elements else { throw StatusError(.invalidCommand) }
                guard scene <= 254, transitionTime <= 60_000_000 else { return response(C.addSceneResponse, .constraintError, group, scene) }
                let (scenes, fabric, endpoint) = try await scope(context)
                guard await valid(group, endpoint, fabric, context), let values = await state.decode(sets) else {
                    return response(C.addSceneResponse, .invalidCommand, group, scene)
                }
                let status = await scenes.set(Scenes.Scene(name: name.utf8Prefix(16), transitionTime: UInt32(transitionTime), values: values),
                                              for: .init(fabric: fabric, endpoint: endpoint, group: group, scene: SceneID(scene)))
                await changed()
                return response(C.addSceneResponse, status, group, scene)
            },
            C.viewScene: { _, fields, context in
                let request = try request(fields)
                let group = try group(request, 0), scene = try number(request, 1)
                guard scene <= 254 else { return response(C.viewSceneResponse, .constraintError, group, scene) }
                let (scenes, fabric, endpoint) = try await scope(context)
                guard await valid(group, endpoint, fabric, context) else { return response(C.viewSceneResponse, .invalidCommand, group, scene) }
                guard let stored = await scenes.scene(.init(fabric: fabric, endpoint: endpoint, group: group, scene: SceneID(scene))) else {
                    return response(C.viewSceneResponse, .notFound, group, scene)
                }
                return response(C.viewSceneResponse, .success, group, scene, [
                    .field(3, .unsigned(UInt64(stored.transitionTime))), .field(4, .utf8(stored.name)), .field(5, await state.encode(stored.values)),
                ])
            },
            C.removeScene: { _, fields, context in
                let request = try request(fields)
                let group = try group(request, 0), scene = try number(request, 1)
                guard scene <= 254 else { return response(C.removeSceneResponse, .constraintError, group, scene) }
                let (scenes, fabric, endpoint) = try await scope(context)
                guard await valid(group, endpoint, fabric, context) else { return response(C.removeSceneResponse, .invalidCommand, group, scene) }
                let status = await scenes.remove(.init(fabric: fabric, endpoint: endpoint, group: group, scene: SceneID(scene)))
                await changed()
                return response(C.removeSceneResponse, status, group, scene)
            },
            C.removeAllScenes: { _, fields, context in
                let group = try group(try request(fields), 0)
                let (scenes, fabric, endpoint) = try await scope(context)
                guard await valid(group, endpoint, fabric, context) else { return response(C.removeAllScenesResponse, .invalidCommand, group) }
                let status = await scenes.removeGroup(group, endpoint: endpoint, fabric: fabric)
                await changed()
                return response(C.removeAllScenesResponse, status, group)
            },
            C.storeScene: { _, fields, context in
                let request = try request(fields)
                let group = try group(request, 0), scene = try number(request, 1)
                guard scene <= 254 else { return response(C.storeSceneResponse, .constraintError, group, scene) }
                let (scenes, fabric, endpoint) = try await scope(context)
                guard await valid(group, endpoint, fabric, context) else { return response(C.storeSceneResponse, .invalidCommand, group, scene) }
                // An existing scene keeps its name and transition time; a new one has neither.
                let key = Scenes.Key(fabric: fabric, endpoint: endpoint, group: group, scene: SceneID(scene))
                var stored = await scenes.scene(key) ?? Scenes.Scene(name: "", transitionTime: 0, values: [:])
                stored.values = await state.values()
                let status = await scenes.set(stored, for: key)
                if status == .success { await state.activate(group: group, scene: SceneID(scene), fabric: fabric) }
                await changed()
                return response(C.storeSceneResponse, status, group, scene)
            },
            C.recallScene: { _, fields, context in
                let request = try request(fields)
                let group = try group(request, 0), scene = try number(request, 1)
                // TransitionTime is optional and nullable; transitions complete at once.
                if let transitionTime = request[2]?.uint, transitionTime > 60_000_000 { throw StatusError(.constraintError) }
                guard scene <= 254 else { throw StatusError(.constraintError) }
                let (scenes, fabric, endpoint) = try await scope(context)
                guard await valid(group, endpoint, fabric, context) else { throw StatusError(.invalidCommand) }
                guard let stored = await scenes.scene(.init(fabric: fabric, endpoint: endpoint, group: group, scene: SceneID(scene))) else {
                    throw StatusError(.notFound)
                }
                try await state.recall(stored.values, context: context)
                await state.activate(group: group, scene: SceneID(scene), fabric: fabric)
                return .success
            },
            C.getSceneMembership: { _, fields, context in
                let group = try group(try request(fields), 0)
                let (scenes, fabric, endpoint) = try await scope(context)
                // Capacity is null when the group is not valid; 0xFE would mean "at least one", never needed here.
                guard await valid(group, endpoint, fabric, context) else {
                    return .response(C.getSceneMembershipResponse, .structure([
                        .field(0, .unsigned(UInt64(IMStatus.invalidCommand.rawValue))), .field(1, .null), .field(2, .unsigned(UInt64(group))),
                    ]))
                }
                let ids = await scenes.ids(group: group, endpoint: endpoint, fabric: fabric)
                return .response(C.getSceneMembershipResponse, .structure([
                    .field(0, .unsigned(UInt64(IMStatus.success.rawValue))),
                    .field(1, .unsigned(UInt64(min(await scenes.remainingCapacity(endpoint: endpoint, fabric: fabric), 0xFE)))),
                    .field(2, .unsigned(UInt64(group))), .field(3, .array(ids.map { TLVElement(.unsigned(UInt64($0))) })),
                ]))
            },
            C.copyScene: { _, fields, context in
                let request = try request(fields)
                let mode = try number(request, 0)
                let fromGroup = try group(request, 1), fromScene = try number(request, 2)
                let toGroup = try group(request, 3), toScene = try number(request, 4)
                @Sendable func copied(_ status: IMStatus) -> InvokeResult { response(C.copySceneResponse, status, fromGroup, fromScene) }
                let (scenes, fabric, endpoint) = try await scope(context)
                guard await valid(fromGroup, endpoint, fabric, context), await valid(toGroup, endpoint, fabric, context) else {
                    return copied(.invalidCommand)
                }
                func key(_ group: GroupID, _ scene: SceneID) -> Scenes.Key { .init(fabric: fabric, endpoint: endpoint, group: group, scene: scene) }
                func copy() async -> IMStatus {
                    // CopyAllScenes (bit 0 of the mode): every scene of the group, under the same ids in the other group.
                    if mode & 1 == 1 {
                        for id in await scenes.ids(group: fromGroup, endpoint: endpoint, fabric: fabric) {
                            guard let scene = await scenes.scene(key(fromGroup, id)) else { continue }
                            let status = await scenes.set(scene, for: key(toGroup, id))
                            if status != .success { return status }
                        }
                        return .success
                    }
                    guard fromScene <= 254, toScene <= 254 else { return .constraintError }
                    guard let scene = await scenes.scene(key(fromGroup, SceneID(fromScene))) else { return .notFound }
                    return await scenes.set(scene, for: key(toGroup, SceneID(toScene)))
                }
                let status = await copy()
                await changed()
                return copied(status)
            },
        ])
        return cluster
    }
}
