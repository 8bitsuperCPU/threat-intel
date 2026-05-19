import Foundation

/// Represents a user-configured threat intelligence source.
/// Stored in SQLite; API keys stored separately in Keychain.
enum SourceType: String, Codable, CaseIterable, Sendable {
    case otx = "AlienVault OTX"
    case abuseIPDB = "AbuseIPDB"
    case sans = "SANS Internet Storm Center"
    case rss = "RSS/Atom Feed"
    case custom = "Custom API"
}

struct ThreatSource: Identifiable, Codable, Equatable, Sendable {
    let id: UUID
    var name: String
    var type: SourceType
    var baseURL: String
    var isEnabled: Bool
    var lastFetchedAt: Date?
    var lastError: String?
    var rateLimitPerMinute: Int
    let createdAt: Date
    var updatedAt: Date

    init(
        id: UUID = UUID(),
        name: String,
        type: SourceType,
        baseURL: String,
        isEnabled: Bool = true,
        rateLimitPerMinute: Int = 30,
        createdAt: Date = Date(),
        updatedAt: Date = Date()
    ) {
        self.id = id
        self.name = name
        self.type = type
        self.baseURL = baseURL
        self.isEnabled = isEnabled
        self.rateLimitPerMinute = rateLimitPerMinute
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.lastFetchedAt = nil
        self.lastError = nil
    }
}
