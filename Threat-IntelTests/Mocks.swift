import XCTest
import Foundation
@testable import Threat_Intel

/// Mock keychain that stores values in-memory for testing.
final class MockKeychain: KeychainProtocol, @unchecked Sendable {
    private var storage: [String: String] = [:]

    func save(key: String, value: String) throws {
        storage[key] = value
    }

    func read(key: String) throws -> String? {
        storage[key]
    }

    func delete(key: String) throws {
        storage.removeValue(forKey: key)
    }
}

/// Mock repository that stores threat items in-memory for testing.
final class MockThreatRepository: ThreatRepositoryProtocol, @unchecked Sendable {
    private var threats: [ThreatItem] = []
    private var feedEntries: [FeedEntry] = []

    func save(threatItems: [ThreatItem]) async throws -> Int {
        let newHashes = Set(threatItems.map(\.contentHash))
        let existing = Set(threats.map(\.contentHash))
        let trulyNew = threatItems.filter { !existing.contains($0.contentHash) }
        threats.append(contentsOf: trulyNew)
        return trulyNew.count
    }

    func fetchThreats(limit: Int, offset: Int, severity: ThreatSeverity?) async throws -> [ThreatItem] {
        var result = threats.sorted { $0.publishedAt > $1.publishedAt }
        if let severity = severity {
            result = result.filter { $0.severity == severity }
        }
        return Array(result.dropFirst(offset).prefix(limit))
    }

    func searchThreats(query: String, limit: Int) async throws -> [ThreatItem] {
        threats.filter {
            $0.title.localizedCaseInsensitiveContains(query) ||
            $0.description.localizedCaseInsensitiveContains(query)
        }
    }

    func threatCount() async throws -> Int { threats.count }

    func save(feedEntries: [FeedEntry]) async throws -> Int {
        let existing = Set(self.feedEntries.map(\.guid))
        let new = feedEntries.filter { !existing.contains($0.guid) }
        self.feedEntries.append(contentsOf: new)
        return new.count
    }

    func fetchFeedEntries(feedSourceID: UUID, limit: Int) async throws -> [FeedEntry] {
        feedEntries.filter { $0.feedSourceID == feedSourceID }
    }

    func save(indicators: [Indicator], for threatID: UUID) async throws {}

    func searchIndicators(value: String) async throws -> [Indicator] { [] }

    func existingContentHashes(_ hashes: [String]) async throws -> Set<String> {
        Set(threats.map(\.contentHash).filter { hashes.contains($0) })
    }

    func existingGUIDs(_ guids: [String], for feedSourceID: UUID) async throws -> Set<String> {
        Set(feedEntries.filter { $0.feedSourceID == feedSourceID }.map(\.guid).filter { guids.contains($0) })
    }
}

/// Mock source manager for testing.
final class MockSourceManager: SourceManagerProtocol, @unchecked Sendable {
    var sources: [ThreatSource] = []

    func allSources() async throws -> [ThreatSource] { sources }
    func add(source: ThreatSource) async throws { sources.append(source) }
    func update(source: ThreatSource) async throws {
        if let idx = sources.firstIndex(where: { $0.id == source.id }) {
            sources[idx] = source
        }
    }
    func delete(sourceID: UUID) async throws {
        sources.removeAll { $0.id == sourceID }
    }
    func toggle(sourceID: UUID, enabled: Bool) async throws {
        if let idx = sources.firstIndex(where: { $0.id == sourceID }) {
            var updated = sources[idx]
            updated.isEnabled = enabled
            sources[idx] = updated
        }
    }
}
