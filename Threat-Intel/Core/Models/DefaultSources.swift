import Foundation

/// Seeds default threat intelligence feeds on first app launch.
/// Checks DB for existing sources instead of relying on UserDefaults (sandbox-safe).
enum DefaultSources {
    static let feeds: [(name: String, url: String)] = [
        ("SANS ISC", "https://isc.sans.edu/rssfeed.xml"),
        ("Week in OSINT", "https://medium.com/feed/week-in-osint"),
        ("Bellingcat", "https://www.bellingcat.com/feed/"),
        ("IntelTechniques", "https://inteltechniques.com/blog/feed/"),
        ("OpenPhish", "https://openphish.com/feed.txt"),
        ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
    ]

    /// Seed default sources only if no sources exist in the DB.
    /// Returns true if seeding occurred.
    static func seedIfNeeded(using sourceManager: SourceManagerProtocol) async -> Bool {
        guard let existing = try? await sourceManager.allSources(), existing.isEmpty else {
            return false
        }

        for feed in feeds {
            let source = ThreatSource(
                name: feed.name,
                type: .rss,
                baseURL: feed.url,
                rateLimitPerMinute: 10
            )
            do {
                try await sourceManager.add(source: source)
            } catch {
                print("[DefaultSources] Failed to add '\(feed.name)': \(error.localizedDescription)")
            }
        }

        return true
    }

    /// Backlog depth (days) — persisted in UserDefaults. Default 10, min 3, max 25.
    static var backlogDepth: Int {
        get { UserDefaults.standard.object(forKey: "backlogDepth").flatMap { $0 as? Int } ?? 10 }
        set {
            let clamped = min(max(newValue, 3), 25)
            UserDefaults.standard.set(clamped, forKey: "backlogDepth")
        }
    }

    /// Ingestion window: only fetch content published in the last N days (from backlogDepth).
    static var ingestionWindowStart: Date {
        Calendar.current.date(byAdding: .day, value: -backlogDepth, to: Date()) ?? Date()
    }
}
