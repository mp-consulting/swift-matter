import Foundation

/// Where a node keeps what must survive a restart: fabrics, ACLs, its attestation, endpoint numbers.
public protocol MatterStorage: Sendable {
    func value(for key: String) async -> [UInt8]?
    func setValue(_ value: [UInt8]?, for key: String) async throws
}

/// Storage in memory, for tests.
public actor MemoryStorage: MatterStorage {
    private var values: [String: [UInt8]] = [:]

    public init() {}

    public func value(for key: String) -> [UInt8]? { values[key] }
    public func setValue(_ value: [UInt8]?, for key: String) { values[key] = value }
    public var keys: [String] { values.keys.sorted() }
}

/// Storage in a directory: one file per key, readable only by the owner (they hold private keys).
public actor FileStorage: MatterStorage {
    public let directory: URL

    public init(directory: URL) throws {
        self.directory = directory
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
    }

    private func url(_ key: String) -> URL {
        // Keys are the node's own names; anything outside [A-Za-z0-9._-] is escaped so a key cannot leave the directory.
        let safe = key.unicodeScalars.map { scalar -> String in
            CharacterSet.alphanumerics.contains(scalar) && scalar.isASCII || "._-".unicodeScalars.contains(scalar)
                ? String(scalar) : "%" + zeroPadded(scalar.value, width: 2, radix: 16)
        }.joined()
        return directory.appendingPathComponent(safe.hasPrefix(".") ? "%2E" + safe.dropFirst() : safe)
    }

    public func value(for key: String) -> [UInt8]? {
        (try? Data(contentsOf: url(key))).map(Array.init)
    }

    public func setValue(_ value: [UInt8]?, for key: String) throws {
        let file = url(key)
        guard let value else {
            try? FileManager.default.removeItem(at: file)
            return
        }
        let temporary = file.appendingPathExtension("tmp")
        FileManager.default.createFile(atPath: temporary.path, contents: Data(value), attributes: [.posixPermissions: 0o600])
        _ = try FileManager.default.replaceItemAt(file, withItemAt: temporary)
    }
}

/// The keys the node and the bridge keep in storage.
public enum StorageKey {
    public static let fabrics = "fabrics"
    public static let accessControl = "acl"
    public static let setup = "setup"
    public static let attestation = "attestation"
    public static let uniqueID = "unique-id"
    public static let bridgeEndpoints = "bridge-endpoints"
}
