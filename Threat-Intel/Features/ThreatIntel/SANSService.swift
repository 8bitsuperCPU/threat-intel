import Foundation

/// SANS Internet Storm Center scraper.
/// Fetches the daily handler diary and threat feeds.
final class SANSService: SourceServiceProtocol, Sendable {
    let sourceType: SourceType = .sans
    private let client: APIClient
    private let baseURL: String

    private let sansFeeds = [
        "/api/threatfeed",
        "/api/infocon",
    ]

    init(baseURL: String = "https://isc.sans.edu", client: APIClient = APIClient()) {
        self.baseURL = baseURL
        self.client = client
    }

    func fetch(since: Date?) async throws -> [ThreatItem] {
        var items: [ThreatItem] = []

        // 1. Fetch threat feed (JSON API available)
        if let feedURL = URL(string: "\(baseURL)/api/threatfeeds") {
            let (data, isModified) = try await client.fetch(
                url: feedURL,
                lastModified: since?.ISO8601Format()
            )
            if isModified, !data.isEmpty {
                items.append(contentsOf: try parseThreatFeed(data: data))
            }
        }

        // 2. Scrape the handler diary page (HTML)
        if let diaryURL = URL(string: "\(baseURL)/diary/rss") {
            let (data, isModified) = try await client.fetch(
                url: diaryURL,
                lastModified: since?.ISO8601Format()
            )
            if isModified, !data.isEmpty {
                items.append(contentsOf: try parseDiaryRSS(data: data))
            }
        }

        return items
    }

    func validate() async throws -> Bool {
        guard let url = URL(string: "\(baseURL)/api/infocon") else { return false }
        do {
            let (data, _) = try await client.fetch(url: url)
            return !data.isEmpty
        } catch {
            return false
        }
    }

    // MARK: - Parsing

    private func parseThreatFeed(data: Data) throws -> [ThreatItem] {
        let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        guard let entries = json?["data"] as? [[String: Any]] else { return [] }

        return entries.compactMap { entry in
            guard let ip = entry["ip"] as? String,
                  let count = entry["count"] as? Int,
                  let firstSeen = entry["firstseen"] as? String
            else { return nil }

            let ports = (entry["ports"] as? [Int]) ?? []
            let summary = "SANS ISC reported IP: \(ip) with \(count) hits on ports: \(ports.map(String.init).joined(separator: ", "))"

            let severity: ThreatSeverity = count > 1000 ? .critical
                : count > 500 ? .high
                : count > 100 ? .medium
                : .low

            let isoFormatter = ISO8601DateFormatter()
            let publishedAt = isoFormatter.date(from: firstSeen) ?? Date()
            let contentHash = HashUtil.sha256("sans:\(ip):\(count):\(firstSeen)")

            return ThreatItem(
                sourceID: UUID(),
                sourceName: "SANS ISC",
                title: "\(ip) — \(count) hits",
                description: summary,
                severity: severity,
                url: "https://isc.sans.edu/ipinfo/\(ip)",
                indicators: [
                    Indicator(type: .ipv4, value: ip, confidence: min(count, 100), firstSeen: publishedAt)
                ],
                publishedAt: publishedAt,
                contentHash: contentHash
            )
        }
    }

    private func parseDiaryRSS(data: Data) throws -> [ThreatItem] {
        // Leverage RSS parser from RSSFeedService
        let parser = SANSXMLParser(data: data)
        parser.parse()
        let entries = parser.parsedEntries

        return entries.map { entry in
            let contentHash = HashUtil.sha256("sans-diary:\(entry.title)")

            let severity: ThreatSeverity = {
                let combined = "\(entry.title) \(entry.description)".lowercased()
                if combined.contains("critical") || combined.contains("ransomware") { return .critical }
                if combined.contains("vulnerability") || combined.contains("exploit") { return .high }
                if combined.contains("phishing") || combined.contains("malware") { return .medium }
                return .informational
            }()

            return ThreatItem(
                sourceID: UUID(),
                sourceName: "SANS ISC Diary",
                title: entry.title,
                description: entry.description,
                severity: severity,
                url: entry.link,
                indicators: extractIOCs(from: entry.description),
                publishedAt: entry.pubDate ?? Date(),
                contentHash: contentHash
            )
        }
    }

    private func extractIOCs(from text: String) -> [Indicator] {
        var indicators: [Indicator] = []

        let ipv4Pattern = #"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"#
        let cvePattern = #"CVE-\d{4}-\d{4,}"#

        if let ipv4Regex = try? NSRegularExpression(pattern: ipv4Pattern) {
            let matches = ipv4Regex.matches(in: text, range: NSRange(text.startIndex..., in: text))
            for match in matches.prefix(10) {
                if let range = Range(match.range, in: text) {
                    indicators.append(Indicator(type: .ipv4, value: String(text[range])))
                }
            }
        }

        if let cveRegex = try? NSRegularExpression(pattern: cvePattern) {
            let matches = cveRegex.matches(in: text, range: NSRange(text.startIndex..., in: text))
            for match in matches.prefix(10) {
                if let range = Range(match.range, in: text) {
                    indicators.append(Indicator(type: .cve, value: String(text[range])))
                }
            }
        }

        return indicators
    }
}

// MARK: - Simple XML Parser for SANS RSS

private final class SANSXMLParser: NSObject, XMLParserDelegate {
    struct Entry {
        let title: String
        let description: String
        let link: String?
        let pubDate: Date?
    }

    private let data: Data
    private(set) var parsedEntries: [Entry] = []

    private var currentElement = ""
    private var currentTitle = ""
    private var currentDescription = ""
    private var currentLink = ""
    private var currentPubDate = ""
    private var inItem = false

    private let dateFormatters: [DateFormatter] = {
        let formats = [
            "EEE, dd MMM yyyy HH:mm:ss Z",
            "EEE, dd MMM yyyy HH:mm:ss zzz",
            "yyyy-MM-dd'T'HH:mm:ssZ",
        ]
        return formats.map { fmt in
            let df = DateFormatter()
            df.locale = Locale(identifier: "en_US_POSIX")
            df.dateFormat = fmt
            return df
        }
    }()

    init(data: Data) { self.data = data }

    func parse() {
        let parser = XMLParser(data: data)
        parser.delegate = self
        parser.parse()
    }

    func parser(_ parser: XMLParser, didStartElement elementName: String, namespaceURI: String?, qualifiedName: String?, attributes: [String: String] = [:]) {
        currentElement = elementName
        if elementName == "item" || elementName == "entry" {
            inItem = true
            currentTitle = ""
            currentDescription = ""
            currentLink = ""
            currentPubDate = ""
        }
    }

    func parser(_ parser: XMLParser, foundCharacters string: String) {
        guard inItem else { return }
        switch currentElement {
        case "title": currentTitle += string
        case "description", "summary": currentDescription += string
        case "link": if currentLink.isEmpty { currentLink += string }
        case "pubDate", "published": currentPubDate += string
        default: break
        }
    }

    func parser(_ parser: XMLParser, didEndElement elementName: String, namespaceURI: String?, qualifiedName: String?) {
        if elementName == "item" || elementName == "entry" {
            let pubDate = parseDate(currentPubDate.trimmingCharacters(in: .whitespacesAndNewlines))
            parsedEntries.append(Entry(
                title: currentTitle.trimmingCharacters(in: .whitespacesAndNewlines),
                description: currentDescription.trimmingCharacters(in: .whitespacesAndNewlines),
                link: currentLink.trimmingCharacters(in: .whitespacesAndNewlines),
                pubDate: pubDate
            ))
            inItem = false
        }
        currentElement = ""
    }

    private func parseDate(_ string: String) -> Date? {
        for df in dateFormatters {
            if let date = df.date(from: string) { return date }
        }
        return ISO8601DateFormatter().date(from: string)
    }
}
