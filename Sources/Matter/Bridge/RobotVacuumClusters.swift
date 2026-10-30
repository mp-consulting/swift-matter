/// What a robot vacuum is doing, as it reports it (RVC Operational State, Application Clusters §7.4).
public enum RobotState: Hashable, Sendable, CaseIterable {
    case stopped
    case running
    case paused
    /// Stuck, or unable to start or finish: OperationalError says so.
    case error
    case seekingCharger
    case charging
    case docked

    var operationalState: UInt64 {
        typealias S = RvcOperationalStateCluster.OperationalStateEnum
        return switch self {
        case .stopped: S.stopped
        case .running: S.running
        case .paused: S.paused
        case .error: S.error
        case .seekingCharger: S.seekingCharger
        case .charging: S.charging
        case .docked: S.docked
        }
    }

    /// Cleaning, in RVC Run Mode's terms: under way or paused.
    var isCleaning: Bool { self == .running || self == .paused }

    init?(operationalState: UInt64?) {
        guard let state = Self.allCases.first(where: { $0.operationalState == operationalState }) else { return nil }
        self = state
    }
}

/// The robot vacuum's clusters: RVC Run Mode with an Idle and a Cleaning mode (the tags §7.2 requires), and RVC
/// Operational State with Pause, Resume and GoHome. Commands reach the handler; the robot reports where it is with
/// `DeviceState.robot`.
extension DeviceClusters {
    static let idleMode: UInt64 = 0
    static let cleaningMode: UInt64 = 1

    static func rvcRunMode(_ handler: @escaping DeviceCommandHandler) async -> AttributeCluster {
        typealias A = RvcRunModeCluster.Attribute
        typealias C = RvcRunModeCluster.Command
        typealias Option = RvcRunModeCluster.ModeOptionStruct
        typealias Tag = RvcRunModeCluster.ModeTagStruct
        func mode(_ label: String, _ number: UInt64, tag: UInt64) -> TLVElement {
            TLVElement(.structure([
                .field(Option.label, .utf8(label)), .field(Option.mode, .unsigned(number)),
                .field(Option.modeTags, .array([TLVElement(.structure([.field(Tag.value, .unsigned(tag))]))])),
            ]))
        }
        let cluster = AttributeCluster(RvcRunModeCluster.definition, attributes: [
            A.supportedModes: .array([mode("Idle", idleMode, tag: RvcRunModeCluster.ModeTag.idle),
                                      mode("Cleaning", cleaningMode, tag: RvcRunModeCluster.ModeTag.cleaning)]),
            A.currentMode: .unsigned(idleMode),
        ])
        await cluster.handle(C.changeToMode) { cluster, fields, _ in
            typealias Status = RvcRunModeCluster.ModeChangeStatus
            func response(_ status: UInt64) -> InvokeResult { .response(C.changeToModeResponse, .structure([.field(0, .unsigned(status))])) }
            guard let new = fields[0]?.uint, new == idleMode || new == cleaningMode else { return response(Status.unsupportedMode) }
            guard await cluster.value(A.currentMode)?.uint != new else { return response(Status.success) }
            do {
                try await handler(new == cleaningMode ? .startCleaning : .stopCleaning)
            } catch {
                return response(Status.genericFailure)
            }
            return response(Status.success)
        }
        return cluster
    }

    static func rvcOperationalState(_ handler: @escaping DeviceCommandHandler) async -> AttributeCluster {
        typealias A = RvcOperationalStateCluster.Attribute
        typealias C = RvcOperationalStateCluster.Command
        typealias Error = RvcOperationalStateCluster.ErrorStateEnum
        let cluster = AttributeCluster(RvcOperationalStateCluster.definition, attributes: [
            A.phaseList: .null, A.currentPhase: .null,
            A.operationalStateList: .array(RobotState.allCases.map { TLVElement(.structure([.field(0, .unsigned($0.operationalState))])) }),
            A.operationalState: .unsigned(RobotState.docked.operationalState),
            A.operationalError: errorState(Error.noError),
        ])
        /// Runs a command the current state allows, answering OperationalCommandResponse (§1.14.6.5).
        @Sendable func command(_ cluster: AttributeCluster, allowed: Set<RobotState>, _ deviceCommand: DeviceCommand) async -> InvokeResult {
            var outcome = Error.commandInvalidInState
            if let current = RobotState(operationalState: await cluster.value(A.operationalState)?.uint), allowed.contains(current) {
                do {
                    try await handler(deviceCommand)
                    outcome = Error.noError
                } catch {
                    outcome = Error.unableToStartOrResume
                }
            }
            return .response(C.operationalCommandResponse, .structure([.field(0, errorState(outcome))]))
        }
        await cluster.handle(C.pause) { cluster, _, _ in await command(cluster, allowed: [.running, .seekingCharger], .pauseCleaning) }
        await cluster.handle(C.resume) { cluster, _, _ in await command(cluster, allowed: [.paused], .resumeCleaning) }
        await cluster.handle(C.goHome) { cluster, _, _ in
            await command(cluster, allowed: [.stopped, .running, .paused, .error], .returnToDock)
        }
        return cluster
    }

    static func errorState(_ id: UInt64) -> TLVValue {
        .structure([.field(RvcOperationalStateCluster.ErrorStateStruct.errorStateId, .unsigned(id))])
    }

    /// The robot reached a state: both clusters follow, with OperationalError on an error and OperationCompletion when
    /// a cleaning run ends (§1.14.7).
    static func setRobot(_ state: RobotState, runMode: AttributeCluster?, operational: AttributeCluster?) async {
        typealias A = RvcOperationalStateCluster.Attribute
        typealias Error = RvcOperationalStateCluster.ErrorStateEnum
        await runMode?.set(RvcRunModeCluster.Attribute.currentMode, .unsigned(state.isCleaning ? cleaningMode : idleMode))
        guard let operational else { return }
        let previous = await operational.value(A.operationalState)?.uint
        guard previous != state.operationalState else { return }
        let error = state == .error ? Error.unableToCompleteOperation : Error.noError
        await operational.set([A.operationalState: .unsigned(state.operationalState), A.operationalError: errorState(error)])
        if state == .error {
            await operational.emit(RvcOperationalStateCluster.Event.operationalError, data: .structure([.field(0, errorState(error))]))
        }
        if RobotState(operationalState: previous)?.isCleaning == true, !state.isCleaning {
            await operational.emit(RvcOperationalStateCluster.Event.operationCompletion, data: .structure([.field(0, .unsigned(error))]))
        }
    }
}
