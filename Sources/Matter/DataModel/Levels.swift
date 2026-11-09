import Foundation

extension LevelControlCluster {
    /// A brightness in percent (0–100, HomeKit's and most apps') as a light's CurrentLevel: 1–254 (Application
    /// Clusters §1.6.6.2, a lighting device's MinLevel is 1).
    public static func level(percent: Double) -> UInt8 {
        UInt8(max(1, min(254, (min(max(percent, 0), 100) * 254 / 100).rounded())))
    }

    /// A CurrentLevel as a brightness in percent, at least 1 so a dimmed light stays on.
    public static func percent(level: UInt64) -> Int {
        max(1, Int((Double(min(level, 254)) * 100 / 254).rounded()))
    }
}
