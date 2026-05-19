import Foundation
import OSLog

/// Orchestrates ingestion across all configured sources.
/// Runs each source in parallel, deduplicates results, and persists via repository.
final class IngestionOrchestrator: Sendable {
    private let sourceManager: SourceManagerProtocol
    private let repository: ThreatRepositoryProtocol
    private let client: APIClient
    private let logger = Logger(subsystem: "com.philtronic.Threat-Intel", category: "Ingestion")

    /// Captures both per-source status and raw items for direct display.
    struct TaskResult: Sendable {
        let state: FeedIngestionState
        let items: [ThreatItem]
    }

    init(
        sourceManager: SourceManagerProtocol,
        repository: ThreatRepositoryProtocol,
        client: APIClient = APIClient()
    ) {
        self.sourceManager = sourceManager
        self.repository = repository
        self.client = client
    }

    /// Run full ingestion across all enabled sources.
    /// Returns (per-source results, all items ingested).
    func ingestAll() async -> (results: [FeedIngestionState], items: [ThreatItem]) {
        let sources: [ThreatSource]
        do {
            sources = try await sourceManager.allSources()
        } catch {
            logger.error("Failed to load sources: \(error.localizedDescription)")
            return (results: [.failed(sourceName: "all", error: error.localizedDescription)], items: [])
        }

        let enabledSources = sources.filter(\.isEnabled)
        logger.info("Starting ingestion across \(enabledSources.count) enabled sources")
        guard !enabledSources.isEmpty else {
            logger.notice("No enabled sources configured")
            return (results: [.completed(sourceName: "all", newCount: 0)], items: [])
        }

        return await withTaskGroup(of: TaskResult.self) { group in
            for source in enabledSources {
                group.addTask {
                    await self.ingestWithItems(source: source)
                }
            }

            var results: [FeedIngestionState] = []
            var allItems: [ThreatItem] = []
            for await taskResult in group {
                results.append(taskResult.state)
                allItems.append(contentsOf: taskResult.items)
            }
            return (results: results, items: allItems)
        }
    }

    /// Ingest from a single source (for backward compat — returns state only).
    private func ingest(source: ThreatSource) async -> FeedIngestionState {
        let result = await ingestWithItems(source: source)
        return result.state
    }

    /// Ingest from a source, returning both status and raw items.
    private func ingestWithItems(source: ThreatSource) async -> TaskResult {
        logger.info("Fetching from '\(source.name)' (\(source.type.rawValue))")

        do {
            let service = try await buildService(for: source)

            let since = source.lastFetchedAt ?? DefaultSources.ingestionWindowStart
            let items = try await service.fetch(since: since)
            logger.debug("'\(source.name)' returned \(items.count) raw items")

            let cutoff = DefaultSources.ingestionWindowStart
            let windowedItems = items.filter { $0.publishedAt >= cutoff }
            logger.debug("'\\(source.name)': \\(windowedItems.count) items within 10-day window")

            guard !windowedItems.isEmpty else {
                logger.info("'\(source.name)': no new items in window")
                return TaskResult(state: .completed(sourceName: source.name, newCount: 0), items: [])
            }

            // Assign sourceID to items
            let taggedItems = windowedItems.map { item -> ThreatItem in
                ThreatItem(
                    id: item.id,
                    sourceID: source.id,
                    sourceName: item.sourceName,
                    title: item.title,
                    description: item.description,
                    severity: item.severity,
                    url: item.url,
                    indicators: item.indicators,
                    publishedAt: item.publishedAt,
                    contentHash: item.contentHash
                )
            }

            let newCount = try await repository.save(threatItems: taggedItems)

            // Update lastFetchedAt
            var updated = source
            updated.lastFetchedAt = Date()
            updated.lastError = nil
            try await sourceManager.update(source: updated)

            logger.info("'\(source.name)': saved \(newCount) new threats")
            return TaskResult(state: .completed(sourceName: source.name, newCount: newCount), items: taggedItems)

        } catch {
            logger.error("'\(source.name)': fetch failed — \(error.localizedDescription)")
            var failed = source
            failed.lastError = error.localizedDescription
            try? await sourceManager.update(source: failed)
            return TaskResult(state: .failed(sourceName: source.name, error: error.localizedDescription), items: [])
        }
    }

    /// Build the appropriate service for a source type.
    private func buildService(for source: ThreatSource) async throws -> any SourceServiceProtocol {
        let sourceManager = self.sourceManager  // Capture as concrete type

        switch source.type {
        case .otx:
            let apiKey = try (sourceManager as? SourceManager)?.getAPIKey(for: source.id) ?? ""
            return OTXService(apiKey: apiKey, client: client)

        case .abuseIPDB:
            let apiKey = try (sourceManager as? SourceManager)?.getAPIKey(for: source.id) ?? ""
            return AbuseIPDBService(apiKey: apiKey, client: client)

        case .rss:
            return RSSFeedService(feedURL: source.baseURL, client: client)

        case .sans:
            return SANSService(baseURL: source.baseURL.isEmpty ? "https://isc.sans.edu" : source.baseURL, client: client)

        case .custom:
            return RSSFeedService(feedURL: source.baseURL, client: client)
        }
    }
}
