import Foundation

/// Indicator of Compromise (IOC).
enum IndicatorType: String, Codable, CaseIterable, Sendable {
    case ipv4 = "IPv4"
    case ipv6 = "IPv6"
    case domain = "Domain"
    case url = "URL"
    case email = "Email"
    case fileHashMD5 = "MD5"
    case fileHashSHA1 = "SHA-1"
    case fileHashSHA256 = "SHA-256"
    case cve = "CVE"
    case other = "Other"
}

struct Indicator: Identifiable, Codable, Equatable, Sendable {
    let id: UUID
    let type: IndicatorType
    let value: String
    let confidence: Int?  // 0-100
    let context: String?  // surrounding context / description
    let firstSeen: Date?
    let lastSeen: Date?

    init(
        id: UUID = UUID(),
        type: IndicatorType,
        value: String,
        confidence: Int? = nil,
        context: String? = nil,
        firstSeen: Date? = nil,
        lastSeen: Date? = nil
    ) {
        self.id = id
        self.type = type
        self.value = value
        self.confidence = confidence
        self.context = context
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen
    }
}
