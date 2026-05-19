import XCTest
@testable import Threat_Intel

final class HashUtilTests: XCTestCase {

    func testSHA256Consistency() {
        let hash1 = HashUtil.sha256("test content")
        let hash2 = HashUtil.sha256("test content")
        XCTAssertEqual(hash1, hash2, "Same input should produce same hash")
    }

    func testSHA256Differentiation() {
        let hash1 = HashUtil.sha256("content A")
        let hash2 = HashUtil.sha256("content B")
        XCTAssertNotEqual(hash1, hash2, "Different inputs should produce different hashes")
    }

    func testSHA256Length() {
        let hash = HashUtil.sha256("anything")
        XCTAssertEqual(hash.count, 64, "SHA256 should be 64 hex characters")
    }

    func testCanonicalizeURL() {
        let url1 = "https://EXAMPLE.com/path?b=2&a=1#fragment"
        let canonical = HashUtil.canonicalizeURL(url1)
        XCTAssertNotNil(canonical)
        XCTAssertFalse(canonical?.contains("#fragment") ?? true, "Fragment should be stripped")
        XCTAssertTrue(canonical?.hasPrefix("https://example.com") ?? false, "Scheme/host should be lowercased")
    }

    func testCanonicalizeURLInvalid() {
        let result = HashUtil.canonicalizeURL("not a url at all")
        XCTAssertNil(result)
    }
}
