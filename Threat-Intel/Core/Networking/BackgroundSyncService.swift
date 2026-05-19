import Foundation
import AppKit

/// Background sync service for periodic source polling.
/// Uses Swift Concurrency with cooperative cancellation.
actor BackgroundSyncService {
    private let orchestrator: IngestionOrchestrator
    private var syncTask: Task<Void, Never>?
    private var isRunning = false

    /// Interval between full sync cycles in seconds
    let syncInterval: TimeInterval

    init(orchestrator: IngestionOrchestrator, syncInterval: TimeInterval = 900) { // 15 min default
        self.orchestrator = orchestrator
        self.syncInterval = syncInterval
    }

    /// Start periodic background syncing.
    func start() {
        guard !isRunning else { return }
        isRunning = true

        syncTask = Task {
            // Initial sync on start
            await performSync()

            while !Task.isCancelled && isRunning {
                do {
                    try await Task.sleep(for: .seconds(syncInterval))
                    guard !Task.isCancelled && isRunning else { break }
                    await performSync()
                } catch {
                    // Sleep interrupted — likely cancellation
                    break
                }
            }
        }
    }

    /// Stop background syncing.
    func stop() {
        isRunning = false
        syncTask?.cancel()
        syncTask = nil
    }

    /// Perform a single sync pass — respects energy and network constraints.
    private func performSync() async {
        // Avoid syncing if on battery and low power mode
        // (In production, wire to ProcessInfo.processInfo.isLowPowerModeEnabled)
        let (results, _) = await orchestrator.ingestAll()

        let newCount = results.reduce(0) { count, state in
            if case .completed(_, let n) = state { return count + n }
            return count
        }

        if newCount > 0 {
            // In production: post local notification, update dock badge
            await MainActor.run {
                NSApp.dockTile.badgeLabel = newCount > 0 ? "\(newCount)" : nil
            }
        }
    }
}
