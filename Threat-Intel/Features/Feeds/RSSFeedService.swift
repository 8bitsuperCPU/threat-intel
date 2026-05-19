import Foundation

/// RSS/Atom feed ingestion service.
/// Parses feeds using Foundation XMLParser with Codable-like strategies.
final class RSSFeedService: SourceServiceProtocol, Sendable {
    let sourceType: SourceType = .rss
    private let client: APIClient
    private let feedURL: String

    init(feedURL: String, client: APIClient = APIClient()) {
        self.feedURL = feedURL
        self.client = client
    }

    func fetch(since: Date?) async throws -> [ThreatItem] {
        guard let url = URL(string: feedURL) else { return [] }

        let (data, isModified) = try await client.fetch(url: url, lastModified: since?.ISO8601Format())
        guard isModified, !data.isEmpty else { return [] }

        return try parseFeed(data: data)
    }

    func validate() async throws -> Bool {
        guard let url = URL(string: feedURL) else { return false }
        do {
            let (data, _) = try await client.fetch(url: url)
            return !data.isEmpty
        } catch {
            return false
        }
    }

    private func parseFeed(data: Data) throws -> [ThreatItem] {
        let parser = RSSParser(data: data)
        parser.parse()
        let entries = parser.parsedEntries

        return entries.map { entry in
            let contentHash = HashUtil.sha256("\(entry.title)\n\(entry.description)")

            let severity: ThreatSeverity = {
                let combined = "\(entry.title) \(entry.description)".lowercased()
                if combined.contains("critical") || combined.contains("emergency") { return .critical }
                if combined.contains("high") || combined.contains("severe") { return .high }
                if combined.contains("medium") || combined.contains("moderate") { return .medium }
                if combined.contains("low") { return .low }
                return .informational
            }()

            return ThreatItem(
                sourceID: UUID(),
                sourceName: entry.feedTitle ?? "RSS Feed",
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

        // IPv4 extraction
        let ipv4Pattern = #"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"#
        if let ipv4Regex = try? NSRegularExpression(pattern: ipv4Pattern) {
            let matches = ipv4Regex.matches(in: text, range: NSRange(text.startIndex..., in: text))
            for match in matches.prefix(10) {
                if let range = Range(match.range, in: text) {
                    indicators.append(Indicator(type: .ipv4, value: String(text[range])))
                }
            }
        }

        // CVE extraction
        let cvePattern = #"CVE-\d{4}-\d{4,}"#
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

// MARK: - XML RSS Parser

private final class RSSParser: NSObject, XMLParserDelegate {
    struct ParsedEntry {
        let title: String
        let description: String
        let link: String?
        let pubDate: Date?
        let feedTitle: String?
    }

    private let data: Data
    private(set) var parsedEntries: [ParsedEntry] = []

    private var currentElement = ""
    private var currentTitle = ""
    private var currentDescription = ""
    private var currentLink = ""
    private var currentPubDate = ""
    private var currentFeedTitle: String?
    private var inItem = false
    private var inChannel = false

    private let dateFormatter: DateFormatter = {
        let df = DateFormatter()
        df.locale = Locale(identifier: "en_US_POSIX")
        return df
    }()

    init(data: Data) {
        self.data = data
    }

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

            // Atom link
            if elementName == "entry", let href = attributes["href"] {
                currentLink = href
            }
        }
        if elementName == "channel" || elementName == "feed" {
            inChannel = true
        }
    }

    func parser(_ parser: XMLParser, foundCharacters string: String) {
        switch currentElement {
        case "title":
            if !inItem && inChannel { currentFeedTitle = (currentFeedTitle ?? "") + string }
            else if inItem { currentTitle += string }
        case "description", "summary", "content":
            if inItem { currentDescription += string }
        case "link":
            if inItem && currentLink.isEmpty { currentLink += string }
        case "pubDate", "published", "updated":
            if inItem { currentPubDate += string }
        default: break
        }
    }

    func parser(_ parser: XMLParser, didEndElement elementName: String, namespaceURI: String?, qualifiedName: String?) {
        if elementName == "item" || elementName == "entry" {
            let pubDate = parseDate(currentPubDate.trimmingCharacters(in: .whitespacesAndNewlines))
            parsedEntries.append(ParsedEntry(
                title: currentTitle.trimmingCharacters(in: .whitespacesAndNewlines),
                description: currentDescription.trimmingCharacters(in: .whitespacesAndNewlines),
                link: currentLink.trimmingCharacters(in: .whitespacesAndNewlines),
                pubDate: pubDate,
                feedTitle: currentFeedTitle
            ))
            inItem = false
        }
        if elementName == "channel" || elementName == "feed" {
            inChannel = false
        }
        currentElement = ""
    }

    private func parseDate(_ string: String) -> Date? {
        let formats = [
            "EEE, dd MMM yyyy HH:mm:ss Z",
            "EEE, dd MMM yyyy HH:mm:ss zzz",
            "yyyy-MM-dd'T'HH:mm:ssZ",
            "yyyy-MM-dd'T'HH:mm:ss.SSSZ",
            "yyyy-MM-dd HH:mm:ss",
        ]
        for fmt in formats {
            dateFormatter.dateFormat = fmt
            if let date = dateFormatter.date(from: string) { return date }
        }
        return ISO8601DateFormatter().date(from: string)
    }
}
