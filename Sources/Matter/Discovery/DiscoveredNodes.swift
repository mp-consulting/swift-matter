import Foundation


/// What a commissioner reads from the DNS-SD records nodes advertise (Core §4.3): a commissionable node's TXT record
/// (§4.3.1) and an operational node's instance name (§4.3.2). The browsing itself is the platform's (dns_sd, Avahi).

/// A node with a commissioning window open, as its `_matterc._udp` TXT record describes it (Core §4.3.1.2-§4.3.1.13).
public struct CommissionableNodeInfo: Hashable, Sendable {
    /// D: the 12-bit long discriminator.
    public var discriminator: UInt16
    /// CM (Core §4.3.1.7): 0 not in commissioning mode, 1 its own passcode (the Basic Commissioning Method), 2 a passcode
    /// an administrator gave with OpenCommissioningWindow, 3 Joint Fabric commissioning (OpenJointCommissioningWindow).
    public var commissioningMode: UInt8
    /// VP: the vendor id, and the product id when given ("4476+32768").
    public var vendorID: UInt16?
    public var productID: UInt16?
    /// DT: its primary device type.
    public var deviceType: UInt32?
    /// DN: the name it gives itself, when it gives one.
    public var deviceName: String?
    /// PH and PI: how to put it in pairing mode, when it says.
    public var pairingHint: UInt16?
    public var pairingInstruction: String?
    /// SII, SAI, SAT and T: its MRP intervals, for the unsecured messages that establish a session with it.
    public var parameters: SessionParameters

    /// The record's fields; nil without a valid long discriminator, which every commissionable record carries.
    public init?(txt: [String: String]) {
        guard let discriminator = txt["D"].flatMap(UInt16.init), discriminator <= 0x0FFF else { return nil }
        self.discriminator = discriminator
        commissioningMode = txt["CM"].flatMap(UInt8.init) ?? 0
        if let vp = txt["VP"] {
            let parts = vp.split(separator: "+", maxSplits: 1)
            vendorID = parts.first.flatMap { UInt16($0) }
            productID = parts.count > 1 ? UInt16(parts[1]) : nil
        }
        deviceType = txt["DT"].flatMap(UInt32.init)
        deviceName = txt["DN"].flatMap { $0.isEmpty ? nil : String($0.prefix(32)) }
        pairingHint = txt["PH"].flatMap(UInt16.init)
        pairingInstruction = txt["PI"].flatMap { $0.isEmpty ? nil : String($0.prefix(128)) }
        parameters = SessionParameters(txt: txt)
    }

    /// Whether a commissioner may take it in with a passcode (CM 1 or 2). CM 3, Joint Fabric commissioning, needs
    /// verification steps of its own that this commissioner does not run.
    public var isCommissionable: Bool { commissioningMode == 1 || commissioningMode == 2 }

    /// The upper four bits of the discriminator, all a manual pairing code carries (Core §5.1.4.1).
    public var shortDiscriminator: UInt8 { UInt8(discriminator >> 8) }

    /// Whether this node may be the one a pairing code is for: the discriminator, and the vendor and product ids when
    /// both the code and the record have them. Two nodes may still share a short discriminator.
    public func matches(_ code: PairingCode) -> Bool {
        switch code.discriminator {
        case .long(let long): guard long == discriminator else { return false }
        case .short(let short): guard short == shortDiscriminator else { return false }
        }
        if let vendor = code.vendorID, let own = vendorID, vendor != 0, vendor != own { return false }
        if let product = code.productID, let own = productID, product != 0, product != own { return false }
        return true
    }
}

/// A pairing code as a person gives it: the QR code's text (`MT:…`) or the 11- or 21-digit manual code.
public struct PairingCode: Hashable, Sendable {
    public enum Discriminator: Hashable, Sendable {
        /// The 12-bit discriminator, from a QR code.
        case long(UInt16)
        /// Its upper four bits, from a manual code.
        case short(UInt8)
    }

    public var passcode: UInt32
    public var discriminator: Discriminator
    public var vendorID: UInt16?
    public var productID: UInt16?

    /// Reads either form; spaces and dashes in a manual code are ignored. Throws `SetupPayloadError` for a code that is
    /// not one (a wrong check digit, an invalid passcode).
    public init(_ text: String) throws {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.uppercased().hasPrefix("MT:") {
            let payload = try SetupPayload(qrCode: trimmed)
            passcode = payload.passcode
            discriminator = .long(payload.discriminator)
            vendorID = payload.vendorID
            productID = payload.productID
        } else {
            let manual = try ManualPairingCode(trimmed)
            passcode = manual.passcode
            discriminator = .short(manual.shortDiscriminator)
            vendorID = manual.vendorID
            productID = manual.productID
        }
    }
}

/// An operational node's DNS-SD instance name (Core §4.3.2.1): its compressed fabric id and node id, each as 16
/// uppercase hexadecimal digits, joined by a dash ("2906C908D115D362-8FC7772401CD0696").
public enum OperationalInstanceName {
    public static func make(compressedFabricID: [UInt8], nodeID: NodeID) -> String {
        "\(hexString(compressedFabricID))-\(zeroPadded(nodeID, width: 16, radix: 16))"
    }

    /// The fabric and the node an instance name stands for; nil for one that is not of that form.
    public static func parse(_ name: String) -> (compressedFabricID: [UInt8], nodeID: NodeID)? {
        let parts = name.split(separator: "-")
        guard parts.count == 2, parts[0].count == 16, parts[1].count == 16,
              let fabric = UInt64(parts[0], radix: 16), let node = UInt64(parts[1], radix: 16) else { return nil }
        let bytes = (0..<8).map { UInt8(truncatingIfNeeded: fabric >> (56 - 8 * $0)) }
        return (bytes, node)
    }
}
