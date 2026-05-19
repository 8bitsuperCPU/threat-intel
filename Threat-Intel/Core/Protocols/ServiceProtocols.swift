import Foundation

// MARK: - Source Service Protocol

/// Each threat intel source implements this protocol.
/// The app discovers all available sources at startup and invokes them by type.
protocol SourceServiceProtocol: Sendable {
    var sourceType: SourceType { get }

    /// Fetch threat items from this source since a given date (nil = full fetch).
    func fetch(since: Date?) async throws -> [ThreatItem]

    /// Validate that the source is reachable and configured correctly.
    func validate() async throws -> Bool
}

// MARK: - Threat Repository Protocol

/// Persistence layer for threat items, indicators, and feed entries.
protocol ThreatRepositoryProtocol: Sendable {
    // Threat items
    func save(threatItems: [ThreatItem]) async throws -> Int  // returns count inserted (deduped)
    func fetchThreats(limit: Int, offset: Int, severity: ThreatSeverity?, sourceName: String?) async throws -> [ThreatItem]
    func searchThreats(query: String, limit: Int, severity: ThreatSeverity?) async throws -> [ThreatItem]
    func threatCount() async throws -> Int
    func deleteAllThreats() async throws

    // Feed entries
    func save(feedEntries: [FeedEntry]) async throws -> Int
    func fetchFeedEntries(feedSourceID: UUID, limit: Int) async throws -> [FeedEntry]

    // Indicators
    func save(indicators: [Indicator], for threatID: UUID) async throws
    func searchIndicators(value: String) async throws -> [Indicator]

    // Deduplication
    func existingContentHashes(_ hashes: [String]) async throws -> Set<String>
    func existingGUIDs(_ guids: [String], for feedSourceID: UUID) async throws -> Set<String>
}

// MARK: - Source Manager Protocol

/// Manages user-configured threat sources — CRUD + enable/disable.
protocol SourceManagerProtocol: Sendable {
    func allSources() async throws -> [ThreatSource]
    func add(source: ThreatSource) async throws
    func update(source: ThreatSource) async throws
    func delete(sourceID: UUID) async throws
    func toggle(sourceID: UUID, enabled: Bool) async throws
}

// MARK: - Keychain Protocol

protocol KeychainProtocol: Sendable {
    func save(key: String, value: String) throws
    func read(key: String) throws -> String?
    func delete(key: String) throws
}
