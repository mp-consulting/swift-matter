/// What a closure seals, as its Closure namespace tag says it (Standard Namespaces, Closure, 0x44).
public enum ClosureKind: UInt8, Sendable, CaseIterable {
    case covering = 0
    case window = 1
    case barrier = 2
    case cabinet = 3
    case gate = 4
    case garageDoor = 5
    case door = 6

    static let namespace: UInt8 = 0x44
}

/// Where a closure is, as it reports it (Closure Control's CurrentPositionEnum, Application Clusters §5.4.6.1).
public enum ClosurePosition: UInt64, Sendable {
    case fullyClosed = 0
    case fullyOpened = 1
    case partiallyOpened = 2
}

extension DeviceKind {
    /// A closure that opens and closes as a whole (Device Library §8.5): Closure Control with Positioning. MoveTo asks
    /// the handler to open or close it, Stop to stop; the closure reports where it is with `DeviceState.closure`.
    public static func closure(_ kind: ClosureKind) -> DeviceKind {
        DeviceKind(deviceTypes: [DeviceTypes.closure], tags: [SemanticTag(namespace: ClosureKind.namespace, tag: kind.rawValue)]) { handler in
            await base(handler, actuator: false) + [await DeviceClusters.closureControl(handler)]
        }
    }
}

/// Closure Control (Application Clusters §5.4) with the Positioning feature only: fully closed, or open.
extension DeviceClusters {
    static func closureControl(_ handler: @escaping DeviceCommandHandler) async -> AttributeCluster {
        typealias A = ClosureControlCluster.Attribute
        typealias C = ClosureControlCluster.Command
        typealias Main = ClosureControlCluster.MainStateEnum
        typealias Target = ClosureControlCluster.TargetPositionEnum
        let cluster = AttributeCluster(ClosureControlCluster.definition, featureMap: ClosureControlCluster.Feature.positioning.rawValue, attributes: [
            A.countdownTime: .null, A.mainState: .unsigned(Main.stopped), A.currentErrorList: .array([]),
            // Unknown until the closure says where it is; no target after a start (§5.4.7.4, §5.4.7.5).
            A.overallCurrentState: .null, A.overallTargetState: .null,
        ])
        await cluster.handle(C.moveTo) { cluster, fields, _ in
            let state = await cluster.value(A.mainState)?.uint
            guard state == Main.moving || state == Main.waitingForMotion || state == Main.stopped else { throw StatusError(.invalidInState) }
            // Without a position the target's stands; without a target, nothing moves (§5.4.8.2.1).
            let target = await cluster.value(A.overallTargetState)?[ClosureControlCluster.OverallTargetStateStruct.position]?.uint
            guard let requested = fields[0]?.uint ?? target else { return .success }
            guard requested <= Target.moveToSignaturePosition else { throw StatusError(.constraintError) }
            // Every target other than fully closed opens it: this closure knows only open and closed.
            let open = requested != Target.moveToFullyClosed
            await cluster.set(A.overallTargetState, .structure([.field(ClosureControlCluster.OverallTargetStateStruct.position, .unsigned(requested))]))
            let current = await cluster.value(A.overallCurrentState)?[ClosureControlCluster.OverallCurrentStateStruct.position]?.uint
            if let current, (current == ClosurePosition.fullyClosed.rawValue) == !open {
                await cluster.set(A.mainState, .unsigned(Main.stopped))
                return .success
            }
            try await deliver(.setClosureOpen(open), to: handler)
            await cluster.set(A.mainState, .unsigned(Main.moving))
            return .success
        }
        await cluster.handle(C.stop) { cluster, _, _ in
            // Always a success (§5.4.8.1); the closure reports where it stopped.
            try? await handler(.stopClosure)
            if let state = await cluster.value(A.mainState)?.uint, state == Main.moving || state == Main.waitingForMotion {
                await cluster.set(A.mainState, .unsigned(Main.stopped))
            }
            return .success
        }
        return cluster
    }

    /// The closure reached a position (nil: it does not know), or is moving: OverallCurrentState with its secure
    /// state, MainState, and the events of the change (§5.4.9).
    static func setClosure(_ cluster: AttributeCluster, position: ClosurePosition?, moving: Bool) async {
        typealias A = ClosureControlCluster.Attribute
        typealias S = ClosureControlCluster.OverallCurrentStateStruct
        typealias Main = ClosureControlCluster.MainStateEnum
        let previous = await cluster.value(A.overallCurrentState)
        let wasMoving = await cluster.value(A.mainState)?.uint == Main.moving
        // Secure only when fully closed: with Positioning alone that is the whole condition (§5.4.6.5.4).
        let secure: TLVValue = position.map { .bool($0 == .fullyClosed) } ?? .null
        let state: TLVValue = .structure([.field(S.position, position.map { .unsigned($0.rawValue) } ?? .null), .field(S.secureState, secure)])
        await cluster.set([A.overallCurrentState: state, A.mainState: .unsigned(moving ? Main.moving : Main.stopped)])
        if previous?[S.secureState] != secure, secure != .null {
            await cluster.emit(ClosureControlCluster.Event.secureStateChanged, data: .structure([.field(0, secure)]))
        }
        if wasMoving, !moving {
            await cluster.emit(ClosureControlCluster.Event.movementCompleted, data: .structure([]))
        }
    }
}
