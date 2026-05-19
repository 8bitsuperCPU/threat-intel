import Foundation

extension Array where Element == ThreatItem {
    /// Remove duplicates by contentHash, keeping the first occurrence.
    func deduplicated() -> [ThreatItem] {
        var seen: Set<String> = []
        return filter { seen.insert($0.contentHash).inserted }
    }
}

extension Array where Element == FeedEntry {
    func deduplicated() -> [FeedEntry] {
        var seen: Set<String> = []
        return filter { seen.insert($0.contentHash).inserted }
    }
}
