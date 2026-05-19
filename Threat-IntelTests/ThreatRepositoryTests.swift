import XCTest
@testable import Threat_Intel

final class ThreatRepositoryTests: XCTestCase {
    var repository: ThreatRepository!
    var mockRepo: MockThreatRepository!

    override func setUp() {
        repository = ThreatRepository(db: .shared)
        mockRepo = MockThreatRepository()
    }

    // MARK: - Deduplication Tests

    func testDeduplicationByContentHash() async throws {
        let item1 = ThreatItem(
            sourceID: UUID(), sourceName: "Test", title: "Same Content",
            description: "Identical description", severity: .medium,
            publishedAt: Date(), contentHash: HashUtil.sha256("Same Content\nIdentical description")
        )
        let item2 = ThreatItem(
            sourceID: UUID(), sourceName: "Test", title: "Same Content",
            description: "Identical description", severity: .medium,
            publishedAt: Date(), contentHash: HashUtil.sha256("Same Content\nIdentical description")
        )

        let count1 = try await mockRepo.save(threatItems: [item1])
        XCTAssertEqual(count1, 1, "First save should insert 1")

        let count2 = try await mockRepo.save(threatItems: [item2])
        XCTAssertEqual(count2, 0, "Duplicate should insert 0")
    }

    func testUniqueContentInserted() async throws {
        let item1 = ThreatItem(
            sourceID: UUID(), sourceName: "Test", title: "Item One",
            description: "Description one", severity: .high,
            publishedAt: Date(), contentHash: "hash_alpha"
        )
        let item2 = ThreatItem(
            sourceID: UUID(), sourceName: "Test", title: "Item Two",
            description: "Description two", severity: .low,
            publishedAt: Date(), contentHash: "hash_beta"
        )

        let count1 = try await mockRepo.save(threatItems: [item1])
        let count2 = try await mockRepo.save(threatItems: [item2])

        XCTAssertEqual(count1 + count2, 2, "Both unique items should be inserted")
    }

    // MARK: - Fetch Tests

    func testFetchBySeverity() async throws {
        let critical = makeThreat(severity: .critical, hash: "hash_crit")
        let low = makeThreat(severity: .low, hash: "hash_low")

        _ = try await mockRepo.save(threatItems: [critical, low])

        let fetched = try await mockRepo.fetchThreats(limit: 10, offset: 0, severity: .critical)
        XCTAssertEqual(fetched.count, 1)
        XCTAssertEqual(fetched.first?.severity, .critical)
    }

    func testSearchThreats() async throws {
        let ransomware = ThreatItem(
            sourceID: UUID(), sourceName: "Test", title: "Ransomware Attack",
            description: "New ransomware variant detected", severity: .critical,
            publishedAt: Date(), contentHash: "hash_ransom"
        )
        let normal = ThreatItem(
            sourceID: UUID(), sourceName: "Test", title: "Regular Update",
            description: "Standard security update", severity: .low,
            publishedAt: Date(), contentHash: "hash_normal"
        )

        _ = try await mockRepo.save(threatItems: [ransomware, normal])

        let results = try await mockRepo.searchThreats(query: "ransomware", limit: 10)
        XCTAssertEqual(results.count, 1)
        XCTAssertTrue(results.first?.title.contains("Ransomware") ?? false)
    }

    // MARK: - Feed Entry Dedup Tests

    func testFeedEntryDeduplication() async throws {
        let feedID = UUID()
        let entry1 = FeedEntry(
            feedSourceID: feedID, guid: "guid-001",
            title: "Same Entry", summary: "Same summary",
            publishedAt: Date(), contentHash: "feed_hash_1"
        )
        let entry2 = FeedEntry(
            feedSourceID: feedID, guid: "guid-001",
            title: "Same Entry", summary: "Same summary",
            publishedAt: Date(), contentHash: "feed_hash_1"
        )

        let count1 = try await mockRepo.save(feedEntries: [entry1])
        let count2 = try await mockRepo.save(feedEntries: [entry2])

        XCTAssertEqual(count1, 1)
        XCTAssertEqual(count2, 0, "Duplicate GUID should not be inserted")
    }

    // MARK: - Helpers

    private func makeThreat(severity: ThreatSeverity, hash: String) -> ThreatItem {
        ThreatItem(
            sourceID: UUID(), sourceName: "Test",
            title: "Test \(severity.rawValue)",
            description: "Test description",
            severity: severity,
            publishedAt: Date(),
            contentHash: hash
        )
    }
}
