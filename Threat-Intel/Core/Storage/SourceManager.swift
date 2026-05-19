import Foundation
import GRDB
import OSLog

/// Manages user-configured threat sources — CRUD via SQLite.
final class SourceManager: SourceManagerProtocol, Sendable {
    private let db: DatabaseManager
    private let keychain: KeychainProtocol

    init(db: DatabaseManager = .shared, keychain: KeychainProtocol = KeychainManager.shared) {
        self.db = db
        self.keychain = keychain
    }

    func allSources() async throws -> [ThreatSource] {
        do {
            return try await db.queue.read { db in
                try ThreatSource.order(ThreatSource.Columns.name.asc).fetchAll(db)
            }
        } catch {
            Logger(subsystem: "com.philtronic.Threat-Intel", category: "SourceManager")
                .error("allSources failed: \(error.localizedDescription)")
            return []
        }
    }

    func add(source: ThreatSource) async throws {
        try await db.queue.write { db in
            try source.insert(db)
        }
    }

    func update(source: ThreatSource) async throws {
        var updated = source
        updated.updatedAt = Date()
        try await db.queue.write { db in
            try updated.update(db)
        }
    }

    func delete(sourceID: UUID) async throws {
        // Remove associated API key from Keychain
        try? keychain.delete(key: sourceID.uuidString)

        try await db.queue.write { db in
            try db.execute(sql: "DELETE FROM indicator WHERE threatID IN (SELECT id FROM threat_item WHERE sourceID = ?)", arguments: [sourceID.uuidString])
            try db.execute(sql: "DELETE FROM threat_item WHERE sourceID = ?", arguments: [sourceID.uuidString])
            try db.execute(sql: "DELETE FROM feed_entry WHERE feedSourceID = ?", arguments: [sourceID.uuidString])
            try ThreatSource.deleteOne(db, key: sourceID.uuidString)
        }
    }

    func toggle(sourceID: UUID, enabled: Bool) async throws {
        try await db.queue.write { db in
            try db.execute(
                sql: "UPDATE threat_source SET isEnabled = ?, updatedAt = ? WHERE id = ?",
                arguments: [enabled, Date(), sourceID.uuidString]
            )
        }
    }

    // MARK: - API Key Management

    func saveAPIKey(_ key: String, for sourceID: UUID) throws {
        try keychain.save(key: sourceID.uuidString, value: key)
    }

    func getAPIKey(for sourceID: UUID) throws -> String? {
        try keychain.read(key: sourceID.uuidString)
    }

    func deleteAPIKey(for sourceID: UUID) throws {
        try keychain.delete(key: sourceID.uuidString)
    }
}
