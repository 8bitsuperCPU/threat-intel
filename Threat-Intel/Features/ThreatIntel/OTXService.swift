import Foundation

/// AlienVault OTX pulse ingestion service.
final class OTXService: SourceServiceProtocol, Sendable {
    let sourceType: SourceType = .otx
    private let client: APIClient
    private let apiKey: String
    private let baseURL = "https://otx.alienvault.com/api/v1"

    init(apiKey: String, client: APIClient = APIClient()) {
        self.apiKey = apiKey
        self.client = client
    }

    func fetch(since: Date?) async throws -> [ThreatItem] {
        var items: [ThreatItem] = []

        // Fetch recent pulses — use general endpoints that don't require special subscription scope
        let endpoints = ["/pulses/general?limit=50", "/pulses/subscribed?limit=50"]

        for endpoint in endpoints {
            guard let url = URL(string: "\(baseURL)\(endpoint)") else { continue }
            do {
                let (data, isModified) = try await client.fetch(
                    url: url,
                    headers: ["X-OTX-API-KEY": apiKey],
                    lastModified: since?.ISO8601Format()
                )
                guard isModified, !data.isEmpty else { continue }

                let parsed = try parsePulses(data: data)
                items.append(contentsOf: parsed)
            } catch {
                // Continue to next endpoint on individual failure
                continue
            }
        }

        return items
    }

    func validate() async throws -> Bool {
        guard let url = URL(string: "\(baseURL)/pulses/subscribed?limit=1") else { return false }
        do {
            let (data, _) = try await client.fetch(url: url, headers: ["X-OTX-API-KEY": apiKey])
            let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
            return json?["results"] != nil
        } catch {
            return false
        }
    }

    // MARK: - Parsing

    private func parsePulses(data: Data) throws -> [ThreatItem] {
        let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        guard let results = json?["results"] as? [[String: Any]] else { return [] }

        return results.compactMap { pulse in
            guard let id = pulse["id"] as? String,
                  let name = pulse["name"] as? String,
                  let description = pulse["description"] as? String,
                  let created = pulse["created"] as? String
            else { return nil }

            let isoFormatter = ISO8601DateFormatter()
            let publishedAt = isoFormatter.date(from: created) ?? Date()

            let contentHash = HashUtil.sha256("\(name)\n\(description)")

            var indicators: [Indicator] = []
            if let iocs = pulse["indicators"] as? [[String: Any]] {
                indicators = iocs.compactMap { ioc in
                    guard let iocType = ioc["type"] as? String,
                          let iocValue = ioc["indicator"] as? String
                    else { return nil }
                    return Indicator(
                        type: mapIndicatorType(iocType),
                        value: iocValue,
                        confidence: ioc["content"] != nil ? 70 : 50
                    )
                }
            }

            return ThreatItem(
                sourceID: UUID(),
                sourceName: "AlienVault OTX",
                title: name,
                description: description,
                severity: mapSeverity(pulse),
                url: "https://otx.alienvault.com/pulse/\(id)",
                indicators: indicators,
                publishedAt: publishedAt,
                contentHash: contentHash
            )
        }
    }

    private func mapIndicatorType(_ otxType: String) -> IndicatorType {
        switch otxType.lowercased() {
        case "ipv4", "ipv4-addr": return .ipv4
        case "ipv6", "ipv6-addr": return .ipv6
        case "domain", "hostname": return .domain
        case "url", "uri": return .url
        case "email": return .email
        case "filehash-md5": return .fileHashMD5
        case "filehash-sha1": return .fileHashSHA1
        case "filehash-sha256": return .fileHashSHA256
        case "cve": return .cve
        default: return .other
        }
    }

    private func mapSeverity(_ pulse: [String: Any]) -> ThreatSeverity {
        let tags = (pulse["tags"] as? [String]) ?? []
        let lower = tags.map { $0.lowercased() }

        if lower.contains(where: { $0.contains("apt") || $0.contains("ransomware") }) {
            return .critical
        }
        if lower.contains(where: { $0.contains("malware") || $0.contains("exploit") }) {
            return .high
        }
        if lower.contains(where: { $0.contains("phishing") || $0.contains("vulnerability") }) {
            return .medium
        }
        return .informational
    }
}
