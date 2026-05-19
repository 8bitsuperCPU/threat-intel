import Foundation

// MARK: - Dashboard State Machine

enum DashboardState: Equatable, Sendable {
    case idle
    case loading
    case loaded(items: [ThreatItem], lastUpdated: Date)
    case partial(items: [ThreatItem], failedSources: [String])
    case empty
    case error(String)
}

// MARK: - Source Configuration State

enum SourceConfigState: Equatable, Sendable {
    case idle
    case loading
    case loaded(sources: [ThreatSource])
    case saving
    case saved(source: ThreatSource)
    case deleting
    case error(String)
}

// MARK: - Feed Ingestion State

enum FeedIngestionState: Equatable, Sendable {
    case idle
    case fetching(sourceName: String)
    case parsing(sourceName: String, entryCount: Int)
    case deduplicating(sourceName: String)
    case completed(sourceName: String, newCount: Int)
    case failed(sourceName: String, error: String)
}

// MARK: - Background Sync State

enum BackgroundSyncState: Equatable, Sendable {
    case idle
    case running(progress: Double, currentSource: String)
    case completed(lastRun: Date)
    case failed(String)
}
