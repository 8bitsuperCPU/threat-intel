import XCTest
@testable import Threat_Intel

final class SourceManagerTests: XCTestCase {
    var sourceManager: SourceManager!
    var mockKeychain: MockKeychain!

    override func setUp() {
        mockKeychain = MockKeychain()
        sourceManager = SourceManager(db: .shared, keychain: mockKeychain)
    }

    func testAddSource() async throws {
        let source = ThreatSource(name: "Test Feed", type: .rss, baseURL: "https://example.com/feed.xml")
        try await sourceManager.add(source: source)

        let sources = try await sourceManager.allSources()
        XCTAssertEqual(sources.count, 1)
        XCTAssertEqual(sources.first?.name, "Test Feed")
    }

    func testDeleteSource() async throws {
        let source = ThreatSource(name: "Delete Me", type: .otx, baseURL: "https://otx.alienvault.com")
        try await sourceManager.add(source: source)

        try await sourceManager.delete(sourceID: source.id)
        let sources = try await sourceManager.allSources()
        // Source should be removed (count may include other test sources)
        XCTAssertFalse(sources.contains(where: { $0.id == source.id }))
    }

    func testToggleSource() async throws {
        let source = ThreatSource(name: "Toggle Test", type: .rss, baseURL: "https://example.com/feed.xml")
        try await sourceManager.add(source: source)

        try await sourceManager.toggle(sourceID: source.id, enabled: false)
        let sources = try await sourceManager.allSources()
        let toggled = sources.first(where: { $0.id == source.id })
        XCTAssertEqual(toggled?.isEnabled, false)
    }

    func testAPIKeyStorage() async throws {
        let sourceID = UUID()
        let apiKey = "test-api-key-12345"

        try sourceManager.saveAPIKey(apiKey, for: sourceID)
        let retrieved = try sourceManager.getAPIKey(for: sourceID)
        XCTAssertEqual(retrieved, apiKey)

        try sourceManager.deleteAPIKey(for: sourceID)
        let afterDelete = try sourceManager.getAPIKey(for: sourceID)
        XCTAssertNil(afterDelete)
    }
}
