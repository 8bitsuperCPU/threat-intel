import Foundation

/// Parsed RSS/Atom feed entry.
struct FeedEntry: Identifiable, Codable, Equatable, Sendable {
    let id: UUID
    let feedSourceID: UUID
    let guid: String          // Feed-level unique ID for dedup
    let title: String
    let summary: String
    let link: String?
    let author: String?
    let publishedAt: Date
    let updatedAt: Date?
    let categories: [String]
    let contentHash: String   // SHA256 of title+summary for cross-feed dedup
    let ingestedAt: Date

    init(
        id: UUID = UUID(),
        feedSourceID: UUID,
        guid: String,
        title: String,
        summary: String,
        link: String? = nil,
        author: String? = nil,
        publishedAt: Date,
        updatedAt: Date? = nil,
        categories: [String] = [],
        contentHash: String
    ) {
        self.id = id
        self.feedSourceID = feedSourceID
        self.guid = guid
        self.title = title
        self.summary = summary
        self.link = link
        self.author = author
        self.publishedAt = publishedAt
        self.updatedAt = updatedAt
        self.categories = categories
        self.contentHash = contentHash
        self.ingestedAt = Date()
    }
}
