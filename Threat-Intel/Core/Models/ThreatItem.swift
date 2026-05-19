import Foundation

/// Unified threat item presented on the dashboard.
/// Normalised from all source types (OTX pulses, AbuseIPDB reports, RSS entries, etc.).
enum ThreatSeverity: String, Codable, CaseIterable, Sendable {
    case critical = "Critical"
    case high = "High"
    case medium = "Medium"
    case low = "Low"
    case informational = "Informational"

    var sortOrder: Int {
        switch self {
        case .critical: return 0
        case .high: return 1
        case .medium: return 2
        case .low: return 3
        case .informational: return 4
        }
    }
}

struct ThreatItem: Identifiable, Codable, Equatable, Sendable {
    let id: UUID
    let sourceID: UUID
    let sourceName: String
    let title: String
    let description: String
    let severity: ThreatSeverity
    let url: String?
    let indicators: [Indicator]
    let publishedAt: Date
    let ingestedAt: Date
    let contentHash: String  // SHA256 for deduplication

    init(
        id: UUID = UUID(),
        sourceID: UUID,
        sourceName: String,
        title: String,
        description: String,
        severity: ThreatSeverity = .medium,
        url: String? = nil,
        indicators: [Indicator] = [],
        publishedAt: Date,
        contentHash: String
    ) {
        self.id = id
        self.sourceID = sourceID
        self.sourceName = sourceName
        self.title = title
        self.description = description
        self.severity = severity
        self.url = url
        self.indicators = indicators
        self.publishedAt = publishedAt
        self.ingestedAt = Date()
        self.contentHash = contentHash
    }
}
