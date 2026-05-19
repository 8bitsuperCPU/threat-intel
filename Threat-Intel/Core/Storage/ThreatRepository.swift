import Foundation
import GRDB
import OSLog

/// GRDB-backed implementation of ThreatRepositoryProtocol.
final class ThreatRepository: ThreatRepositoryProtocol, Sendable {
    private let db: DatabaseManager
    private let logger = Logger(subsystem: "com.philtronic.Threat-Intel", category: "Repository")

    init(db: DatabaseManager = .shared) {
        self.db = db
    }

    // MARK: - Threat Items

    func save(threatItems: [ThreatItem]) async throws -> Int {
        logger.debug("save() called with \(threatItems.count) items")

        // 1. Deduplicate within batch by contentHash
        var seen: Set<String> = []
        let uniqueItems = threatItems.filter { seen.insert($0.contentHash).inserted }
        logger.debug("After intra-batch dedup: \(uniqueItems.count) unique items (was \(threatItems.count))")

        // 2. Filter out items that already exist in DB
        let itemsToInsert = try await filterNew(items: uniqueItems)
        logger.debug("After DB dedup: \(itemsToInsert.count) items to insert")
        guard !itemsToInsert.isEmpty else { return 0 }

        var actualInserted = 0
        try await db.queue.write { db in
            for item in itemsToInsert {
                // INSERT OR IGNORE to survive intra-batch collision edge cases
                try db.execute(
                    sql: """
                    INSERT OR IGNORE INTO threat_item
                    (id, sourceID, sourceName, title, description, severity, url, publishedAt, ingestedAt, contentHash)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    arguments: [
                        item.id.uuidString, item.sourceID.uuidString, item.sourceName,
                        item.title, item.description, item.severity.rawValue, item.url,
                        item.publishedAt, item.ingestedAt, item.contentHash,
                    ]
                )
                actualInserted += 1
                // Save associated indicators
                for indicator in item.indicators {
                    try db.execute(
                        sql: """
                        INSERT OR IGNORE INTO indicator (id, threatID, type, value, confidence, context, firstSeen, lastSeen)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        arguments: [
                            indicator.id.uuidString, item.id.uuidString, indicator.type.rawValue,
                            indicator.value, indicator.confidence, indicator.context,
                            indicator.firstSeen, indicator.lastSeen,
                        ]
                    )
                }
            }
        }
        logger.info("Saved \(actualInserted) threats (attempted \(itemsToInsert.count))")
        return actualInserted
    }

    func fetchThreats(limit: Int, offset: Int, severity: ThreatSeverity? = nil, sourceName: String? = nil) async throws -> [ThreatItem] {
        do {
            return try await db.queue.read { db in
                var request = ThreatItem
                    .order(ThreatItem.Columns.publishedAt.desc)
                    .limit(limit, offset: offset)

                if let severity = severity {
                    request = request.filter(ThreatItem.Columns.severity == severity.rawValue)
                }

                if let sourceName = sourceName {
                    request = request.filter(ThreatItem.Columns.sourceName == sourceName)
                }

                return try request.fetchAll(db)
            }
        } catch {
            logger.error("fetchThreats failed: \(error.localizedDescription)")
            // Return empty on decode/read errors to avoid crashing the UI
            return []
        }
    }

    func searchThreats(query: String, limit: Int, severity: ThreatSeverity?) async throws -> [ThreatItem] {
        let pattern = "%\(query)%"
        return try await db.queue.read { db in
            var request = ThreatItem
                .filter(ThreatItem.Columns.title.like(pattern) || ThreatItem.Columns.description.like(pattern))
                .order(ThreatItem.Columns.publishedAt.desc)
                .limit(limit)

            if let severity = severity {
                request = request.filter(ThreatItem.Columns.severity == severity.rawValue)
            }

            return try request.fetchAll(db)
        }
    }

    func threatCount() async throws -> Int {
        try await db.queue.read { db in try ThreatItem.fetchCount(db) }
    }

    func deleteAllThreats() async throws {
        try await db.queue.write { db in
            try db.execute(sql: "DELETE FROM indicator")
            try db.execute(sql: "DELETE FROM threat_item")
        }
    }

    // MARK: - Feed Entries

    func save(feedEntries: [FeedEntry]) async throws -> Int {
        let guids = try await existingGUIDs(feedEntries.map(\.guid), for: feedEntries.first?.feedSourceID ?? UUID())
        let newEntries = feedEntries.filter { !guids.contains($0.guid) }
        guard !newEntries.isEmpty else { return 0 }

        try await db.queue.write { db in
            for entry in newEntries {
                try entry.insert(db)
            }
        }
        return newEntries.count
    }

    func fetchFeedEntries(feedSourceID: UUID, limit: Int) async throws -> [FeedEntry] {
        try await db.queue.read { db in
            try FeedEntry
                .filter(FeedEntry.Columns.feedSourceID == feedSourceID.uuidString)
                .order(FeedEntry.Columns.publishedAt.desc)
                .limit(limit)
                .fetchAll(db)
        }
    }

    // MARK: - Indicators

    func save(indicators: [Indicator], for threatID: UUID) async throws {
        try await db.queue.write { db in
            for var indicator in indicators {
                try db.execute(
                    sql: """
                    INSERT OR IGNORE INTO indicator (id, threatID, type, value, confidence, context, firstSeen, lastSeen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    arguments: [
                        indicator.id.uuidString, threatID.uuidString, indicator.type.rawValue,
                        indicator.value, indicator.confidence, indicator.context,
                        indicator.firstSeen, indicator.lastSeen,
                    ]
                )
            }
        }
    }

    func searchIndicators(value: String) async throws -> [Indicator] {
        let pattern = "%\(value)%"
        return try await db.queue.read { db in
            try Row.fetchAll(db, sql: "SELECT * FROM indicator WHERE value LIKE ? LIMIT 100", arguments: [pattern])
                .map { row in
                    Indicator(
                        id: UUID(uuidString: row["id"]) ?? UUID(),
                        type: IndicatorType(rawValue: row["type"]) ?? .other,
                        value: row["value"],
                        confidence: row["confidence"],
                        context: row["context"],
                        firstSeen: row["firstSeen"],
                        lastSeen: row["lastSeen"]
                    )
                }
        }
    }

    // MARK: - Deduplication

    func existingContentHashes(_ hashes: [String]) async throws -> Set<String> {
        guard !hashes.isEmpty else { return [] }
        return try await db.queue.read { db in
            let rows = try Row.fetchAll(
                db,
                sql: "SELECT contentHash FROM threat_item WHERE contentHash IN (\(hashes.map { "'\($0)'" }.joined(separator: ",")))"
            )
            return Set(rows.map { $0["contentHash"] })
        }
    }

    func existingGUIDs(_ guids: [String], for feedSourceID: UUID) async throws -> Set<String> {
        guard !guids.isEmpty else { return [] }
        return try await db.queue.read { db in
            let rows = try Row.fetchAll(
                db,
                sql: "SELECT guid FROM feed_entry WHERE feedSourceID = ? AND guid IN (\(guids.map { "'\($0)'" }.joined(separator: ",")))",
                arguments: [feedSourceID.uuidString]
            )
            return Set(rows.map { $0["guid"] })
        }
    }

    // MARK: - Helpers

    private func filterNew(items: [ThreatItem]) async throws -> [ThreatItem] {
        let hashes = Set(items.map(\.contentHash))
        logger.debug("filterNew: \(hashes.count) unique hashes, checking against DB")
        if let firstHash = items.first?.contentHash {
            logger.debug("Sample hash: \(firstHash)")
        }
        let existing = try await existingContentHashes(Array(hashes))
        logger.debug("filterNew: \(existing.count) hashes already in DB")
        return items.filter { !existing.contains($0.contentHash) }
    }
}

// MARK: - GRDB Record Conformance

extension ThreatSource: TableRecord, FetchableRecord, PersistableRecord {
    static let databaseTableName = "threat_source"

    enum Columns: String, ColumnExpression {
        case id, name, type, baseURL, isEnabled, lastFetchedAt, lastError
        case rateLimitPerMinute, createdAt, updatedAt
    }

    public func encode(to container: inout PersistenceContainer) throws {
        container["id"] = id.uuidString
        container["name"] = name
        container["type"] = type.rawValue
        container["baseURL"] = baseURL
        container["isEnabled"] = isEnabled
        container["lastFetchedAt"] = lastFetchedAt
        container["lastError"] = lastError
        container["rateLimitPerMinute"] = rateLimitPerMinute
        container["createdAt"] = createdAt
        container["updatedAt"] = updatedAt
    }
}

extension ThreatItem: TableRecord, FetchableRecord, PersistableRecord {
    static let databaseTableName = "threat_item"

    enum Columns: String, ColumnExpression {
        case id, sourceID, sourceName, title, description, severity
        case url, publishedAt, ingestedAt, contentHash
    }

    /// Decode from a database row — maps text columns back to native types
    /// and sets `indicators` to empty (loaded separately via the repository).
    public nonisolated init(row: Row) {
        let idString: String = row["id"]
        id = UUID(uuidString: idString) ?? UUID()
        let sidString: String = row["sourceID"]
        sourceID = UUID(uuidString: sidString) ?? UUID()
        sourceName = row["sourceName"]
        title = row["title"]
        description = row["description"]
        let sevString: String = row["severity"]
        severity = ThreatSeverity(rawValue: sevString) ?? .medium
        url = row["url"]
        publishedAt = row["publishedAt"]
        ingestedAt = row["ingestedAt"]
        contentHash = row["contentHash"]
        indicators = []
    }

    public func encode(to container: inout PersistenceContainer) throws {
        container["id"] = id.uuidString
        container["sourceID"] = sourceID.uuidString
        container["sourceName"] = sourceName
        container["title"] = title
        container["description"] = description
        container["severity"] = severity.rawValue
        container["url"] = url
        container["publishedAt"] = publishedAt
        container["ingestedAt"] = ingestedAt
        container["contentHash"] = contentHash
    }
}

extension FeedEntry: TableRecord, FetchableRecord, PersistableRecord {
    static let databaseTableName = "feed_entry"

    enum Columns: String, ColumnExpression {
        case id, feedSourceID, guid, title, summary, link
        case author, publishedAt, updatedAt, contentHash, ingestedAt
    }

    public func encode(to container: inout PersistenceContainer) throws {
        container["id"] = id.uuidString
        container["feedSourceID"] = feedSourceID.uuidString
        container["guid"] = guid
        container["title"] = title
        container["summary"] = summary
        container["link"] = link
        container["author"] = author
        container["publishedAt"] = publishedAt
        container["updatedAt"] = updatedAt
        container["contentHash"] = contentHash
        container["ingestedAt"] = ingestedAt
    }
}
