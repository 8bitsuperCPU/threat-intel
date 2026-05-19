import Foundation
import Observation

@Observable
@MainActor
final class DashboardViewModel {
    private let repository: ThreatRepositoryProtocol
    private let orchestrator: IngestionOrchestrator
    private let sourceManager: SourceManagerProtocol

    private var didAutoIngest = false
    private var loadTask: Task<Void, Never>?

    var state: DashboardState = .idle
    var threatItems: [ThreatItem] = []
    var recentFailedSources: [String] = []
    var searchQuery = ""
    var selectedSeverity: ThreatSeverity?
    var filteredSourceName: String?
    var totalThreatCount = 0
    var isRefreshing = false
    var lastIngestionResults: [FeedIngestionState] = []
    var rawFeedItems: [ThreatItem] = []      // In-memory items bypassing DB

    init(
        repository: ThreatRepositoryProtocol,
        orchestrator: IngestionOrchestrator,
        sourceManager: SourceManagerProtocol
    ) {
        self.repository = repository
        self.orchestrator = orchestrator
        self.sourceManager = sourceManager
    }

    func loadDashboard() async {
        state = .loading
        do {
            // Always do a background refresh to populate ingestion results
            if !didAutoIngest {
                didAutoIngest = true
                // Fire-and-forget refresh — existing data shows immediately,
                // ingestion results appear when the refresh completes
                Task { await refreshAll() }
            }

            let items = try await repository.fetchThreats(limit: 200, offset: 0, severity: selectedSeverity, sourceName: filteredSourceName)
            threatItems = items
            totalThreatCount = try await repository.threatCount()

            let sources = try await sourceManager.allSources()
            recentFailedSources = sources.filter { $0.lastError != nil }.map(\.name)

            // Show raw feed items if DB is empty but we have in-memory data
            if items.isEmpty && !rawFeedItems.isEmpty {
                threatItems = rawFeedItems
                totalThreatCount = rawFeedItems.count
                state = .loaded(items: rawFeedItems, lastUpdated: Date())
                return
            }

            if items.isEmpty {
                state = .empty
            } else if !recentFailedSources.isEmpty {
                state = .partial(items: items, failedSources: recentFailedSources)
            } else {
                state = .loaded(items: items, lastUpdated: items.first?.ingestedAt ?? Date())
            }
        } catch {
            state = .error(error.localizedDescription)
        }
    }

    func refreshAll() async {
        guard !isRefreshing else { return }
        isRefreshing = true
        state = .loading

        let (results, items) = await orchestrator.ingestAll()
        lastIngestionResults = results
        rawFeedItems = items.deduplicated()

        let failures = results.compactMap { result -> String? in
            if case .failed(let name, _) = result { return name }
            return nil
        }
        recentFailedSources = failures

        await loadDashboard()
        isRefreshing = false
    }

    func search() async {
        guard !searchQuery.isEmpty else {
            selectedSeverity = nil
            filteredSourceName = nil
            await loadDashboard()
            return
        }
        state = .loading
        do {
            let items = try await repository.searchThreats(query: searchQuery, limit: 200, severity: selectedSeverity)
            threatItems = items
            state = items.isEmpty ? .empty : .loaded(items: items, lastUpdated: Date())
        } catch {
            state = .error(error.localizedDescription)
        }
    }

    func filter(by severity: ThreatSeverity?) {
        selectedSeverity = severity
        filteredSourceName = nil
        Task { await loadDashboard() }
    }

    func filterBySource(name: String?) {
        filteredSourceName = (filteredSourceName == name) ? nil : name
        selectedSeverity = nil
        Task { await loadDashboard() }
    }
}
