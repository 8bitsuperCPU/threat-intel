import Foundation

/// AbuseIPDB reputation service — free tier (1,000 checks/day, 5 blacklists/day).
/// Free tier constraints:
///   - BLACKLIST: 5 requests/day, capped at 10,000 IPs, confidenceMinimum always 100
///   - CHECK:    1,000 requests/day
///   - BULK:     5 requests/day (unused)
///
/// Strategy: cache blacklist for 6 hours, fetch once per session at most.
/// CHECK endpoint used sparingly for validation only.
final class AbuseIPDBService: SourceServiceProtocol, Sendable {
    let sourceType: SourceType = .abuseIPDB
    private let client: APIClient
    private let apiKey: String
    private let baseURL = "https://api.abuseipdb.com/api/v2"

    /// Blacklist cache TTL: 6 hours between fetches.
    private var lastBlacklistFetch: Date?
    private var cachedBlacklist: [ThreatItem] = []

    init(apiKey: String, client: APIClient = APIClient()) {
        self.apiKey = apiKey
        self.client = client
    }

    func fetch(since: Date?) async throws -> [ThreatItem] {
        // Respect 5/day blacklist limit: cache for 6 hours
        let now = Date()
        if let lastFetch = lastBlacklistFetch,
           now.timeIntervalSince(lastFetch) < 6 * 3600,
           !cachedBlacklist.isEmpty {
            return cachedBlacklist
        }

        // Free tier: no confidenceMinimum param (defaults to 100)
        // Use limit=100 to keep response small and parse fast
        guard let url = URL(string: "\(baseURL)/blacklist?limit=100") else {
            return cachedBlacklist
        }

        let (data, isModified) = try await client.fetch(
            url: url,
            headers: ["Key": apiKey, "Accept": "application/json"]
        )
        guard isModified, !data.isEmpty else { return cachedBlacklist }

        let items = try parseBlacklist(data: data)
        self.cachedBlacklist = items
        self.lastBlacklistFetch = now
        return items
    }

    func validate() async throws -> Bool {
        // Use blacklist with limit=1 as lightweight validation
        guard let url = URL(string: "\(baseURL)/blacklist?limit=1") else { return false }
        do {
            let (data, _) = try await client.fetch(
                url: url,
                headers: ["Key": apiKey, "Accept": "application/json"]
            )
            let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
            // Valid response has "data" array or "meta" key
            return (json?["data"] as? [[String: Any]]) != nil || json?["meta"] != nil
        } catch APIClientError.httpError(let code, _) where code == 429 {
            // Rate limited — key is likely valid, just out of quota
            return true
        } catch {
            return false
        }
    }

    // MARK: - Parsing

    private func parseBlacklist(data: Data) throws -> [ThreatItem] {
        let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        guard let blacklistData = json?["data"] as? [[String: Any]] else { return [] }

        return blacklistData.compactMap { entry in
            guard let ipAddress = entry["ipAddress"] as? String,
                  let abuseConfidenceScore = entry["abuseConfidenceScore"] as? Int
            else { return nil }

            // On free tier confidenceMinimum is always 100, so everything is high-confidence
            let countryCode = entry["countryCode"] as? String ?? "??"
            let totalReports = entry["totalReports"] as? Int ?? 0
            let lastReportedAt = entry["lastReportedAt"] as? String

            let severity: ThreatSeverity = abuseConfidenceScore >= 95 ? .critical
                : abuseConfidenceScore >= 85 ? .high
                : abuseConfidenceScore >= 70 ? .medium
                : .low

            let contentHash = HashUtil.sha256("abuseipdb:\(ipAddress):\(abuseConfidenceScore)")

            let publishedAt: Date = {
                if let reported = lastReportedAt {
                    return ISO8601DateFormatter().date(from: reported) ?? Date()
                }
                return Date()
            }()

            return ThreatItem(
                sourceID: UUID(),
                sourceName: "AbuseIPDB",
                title: "\(ipAddress) (\(countryCode)) [Conf: \(abuseConfidenceScore)%]",
                description: "Abuse confidence: \(abuseConfidenceScore)%. Reports: \(totalReports). Last reported: \(lastReportedAt ?? "unknown").",
                severity: severity,
                url: "https://www.abuseipdb.com/check/\(ipAddress)",
                indicators: [
                    Indicator(type: .ipv4, value: ipAddress, confidence: abuseConfidenceScore)
                ],
                publishedAt: publishedAt,
                contentHash: contentHash
            )
        }
    }
}
