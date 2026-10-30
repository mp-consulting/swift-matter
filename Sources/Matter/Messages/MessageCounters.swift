/// Message counters (Core §4.6).

public enum MessageCounter {
    /// A fresh counter starts at a random value in [1, 2^28] (Core §4.6.1.1).
    public static func initialValue() -> UInt32 {
        UInt32.random(in: 1...(1 << 28))
    }

    public static let windowSize: UInt32 = 32
}

/// The duplicate detection state for one sender (Core §4.6.5): the largest counter seen and a bitmap of the 32
/// before it.
public struct MessageReceptionState: Sendable {
    public enum Policy: Sendable {
        /// Secure unicast sessions: counters only move forward; anything behind the window is a duplicate.
        case strict
        /// Unsecured and group messages: counters behind the window mean the sender restarted, and are accepted.
        case rolling
    }

    private(set) var maxCounter: UInt32?
    /// Bit i set: max - (i + 1) was seen.
    private var window: UInt32 = 0
    /// Whether the maximum itself was seen: not when it was learnt rather than received.
    private var maxSeen = true
    let policy: Policy

    public init(policy: Policy) { self.policy = policy }

    /// A state that accepts only counters above `maxCounter` (a freshly established session: the peer's counter is
    /// synchronized to 0).
    public init(policy: Policy, synchronizedTo maxCounter: UInt32) {
        self.policy = policy
        self.maxCounter = maxCounter
        window = .max
    }

    /// A peer's counter learnt from it (MCSP, Core §4.18.5): its maximum, with the bitmap cleared. The spec calls it
    /// the peer's "current" counter, which may be the last one it used or the next: the maximum counts as not seen
    /// yet, so the message that triggered the synchronization is new either way, once.
    public init(policy: Policy, learnt maxCounter: UInt32) {
        self.policy = policy
        self.maxCounter = maxCounter
        window = 0
        maxSeen = false
    }

    /// Whether `counter` is new; records it if so.
    public mutating func accept(_ counter: UInt32) -> Bool {
        guard let max = maxCounter else {
            maxCounter = counter
            window = 0
            return true
        }
        if counter == max, !maxSeen {
            maxSeen = true
            return true
        }
        switch policy {
        case .strict:
            if counter > max {
                shift(by: counter - max)
                maxCounter = counter
                return true
            }
            return markInWindow(offset: max - counter)
        case .rolling:
            // Distances are modulo 2^32: ahead when within 2^31 above the maximum.
            let ahead = counter &- max
            if ahead != 0 && ahead < 1 << 31 {
                shift(by: ahead)
                maxCounter = counter
                return true
            }
            let behind = max &- counter
            if behind == 0 { return false }
            if behind <= MessageCounter.windowSize { return markInWindow(offset: behind) }
            // Behind the window: the sender restarted; start over from this counter.
            maxCounter = counter
            window = 0
            return true
        }
    }

    private mutating func shift(by distance: UInt32) {
        // The old maximum becomes "distance" behind the new one, marked seen if it was; the new one is seen.
        let old: UInt32 = maxSeen ? 1 : 0
        window = distance >= MessageCounter.windowSize ? (distance == MessageCounter.windowSize ? old << 31 : 0)
            : (window << distance) | (old << (distance - 1))
        maxSeen = true
    }

    /// `offset` = max - counter, at least 1 for a counter inside the window.
    private mutating func markInWindow(offset: UInt32) -> Bool {
        guard offset >= 1, offset <= MessageCounter.windowSize else { return false }
        let bit: UInt32 = 1 << (offset - 1)
        if window & bit != 0 { return false }
        window |= bit
        return true
    }
}
