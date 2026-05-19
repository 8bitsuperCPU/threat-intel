import Foundation
import GRDB
import OSLog

/// SQLite-backed repository for all threat data.
/// Uses GRDB for type-safe queries, migrations, and observation.
final class DatabaseManager: @unchecked Sendable {
    static let shared = DatabaseManager()

    private var dbQueue: DatabaseQueue!
    private let logger = Logger(subsystem: "com.philtronic.Threat-Intel", category: "Database")

    private init() {
        setupDatabase()
    }

    // MARK: - Setup

    private func setupDatabase() {
        // Try Application Support first (sandbox-safe), fall back to home directory
        let appSupport = FileManager.default.urls(
            for: .applicationSupportDirectory, in: .userDomainMask
        ).first!

        let dbDir: URL
        if let dir = ensureDirectory(at: appSupport.appendingPathComponent("ThreatIntel")) {
            dbDir = dir
        } else {
            // Fallback: ~/.threatintel/ — always writable outside sandbox
            let fallback = FileManager.default.homeDirectoryForCurrentUser
                .appendingPathComponent(".threatintel")
            dbDir = ensureDirectory(at: fallback) ?? fallback
        }

        let dbPath = dbDir.appendingPathComponent("threats.sqlite").path
        logger.info("Database path: \(dbPath)")

        do {
            dbQueue = try DatabaseQueue(path: dbPath)
            try migrate()
            logger.info("Database ready — \(dbPath)")
        } catch {
            logger.error("Database init failed: \(error.localizedDescription)")
            // Last resort: in-memory DB so the app doesn't crash
            dbQueue = try! DatabaseQueue()
            logger.warning("Falling back to in-memory database (data will not persist)")
        }
    }

    private func ensureDirectory(at url: URL) -> URL? {
        let fm = FileManager.default
        if fm.fileExists(atPath: url.path) { return url }
        do {
            try fm.createDirectory(at: url, withIntermediateDirectories: true)
            return url
        } catch {
            logger.error("Cannot create \(url.path): \(error.localizedDescription)")
            return nil
        }
    }

    private func migrate() throws {
        var migrator = DatabaseMigrator()

        migrator.registerMigration("v1_create_sources") { db in
            try db.create(table: "threat_source") { t in
                t.column("id", .text).primaryKey()
                t.column("name", .text).notNull()
                t.column("type", .text).notNull()
                t.column("baseURL", .text).notNull()
                t.column("isEnabled", .boolean).notNull().defaults(to: true)
                t.column("lastFetchedAt", .datetime)
                t.column("lastError", .text)
                t.column("rateLimitPerMinute", .integer).notNull().defaults(to: 30)
                t.column("createdAt", .datetime).notNull()
                t.column("updatedAt", .datetime).notNull()
            }
        }

        migrator.registerMigration("v2_create_threat_items") { db in
            try db.create(table: "threat_item") { t in
                t.column("id", .text).primaryKey()
                t.column("sourceID", .text).notNull().references("threat_source", onDelete: .cascade)
                t.column("sourceName", .text).notNull()
                t.column("title", .text).notNull()
                t.column("description", .text).notNull()
                t.column("severity", .text).notNull()
                t.column("url", .text)
                t.column("publishedAt", .datetime).notNull()
                t.column("ingestedAt", .datetime).notNull()
                t.column("contentHash", .text).notNull().unique()
            }
            try db.create(index: "idx_threat_contentHash", on: "threat_item", columns: ["contentHash"])
            try db.create(index: "idx_threat_sourceID", on: "threat_item", columns: ["sourceID"])
            try db.create(index: "idx_threat_severity", on: "threat_item", columns: ["severity"])
            try db.create(index: "idx_threat_publishedAt", on: "threat_item", columns: ["publishedAt"])
        }

        migrator.registerMigration("v3_create_indicators") { db in
            try db.create(table: "indicator") { t in
                t.column("id", .text).primaryKey()
                t.column("threatID", .text).notNull().references("threat_item", onDelete: .cascade)
                t.column("type", .text).notNull()
                t.column("value", .text).notNull()
                t.column("confidence", .integer)
                t.column("context", .text)
                t.column("firstSeen", .datetime)
                t.column("lastSeen", .datetime)
            }
            try db.create(index: "idx_indicator_value", on: "indicator", columns: ["value"])
            try db.create(index: "idx_indicator_threatID", on: "indicator", columns: ["threatID"])
        }

        migrator.registerMigration("v4_create_feed_entries") { db in
            try db.create(table: "feed_entry") { t in
                t.column("id", .text).primaryKey()
                t.column("feedSourceID", .text).notNull().references("threat_source", onDelete: .cascade)
                t.column("guid", .text).notNull()
                t.column("title", .text).notNull()
                t.column("summary", .text).notNull()
                t.column("link", .text)
                t.column("author", .text)
                t.column("publishedAt", .datetime).notNull()
                t.column("updatedAt", .datetime)
                t.column("contentHash", .text).notNull()
                t.column("ingestedAt", .datetime).notNull()
            }
            try db.create(index: "idx_feed_guid", on: "feed_entry", columns: ["feedSourceID", "guid"])
            try db.create(index: "idx_feed_contentHash", on: "feed_entry", columns: ["contentHash"])
        }

        try! migrator.migrate(dbQueue)
    }

    // MARK: - Accessors

    var queue: DatabaseQueue { dbQueue }
}
