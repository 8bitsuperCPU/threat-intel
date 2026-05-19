import Foundation
import Observation

/// Central dependency injection container.
/// All services are protocol-bound for testability.
@MainActor
@Observable
final class DependencyContainer {
    // Storage layer
    let database: DatabaseManager
    let keychain: KeychainProtocol
    let repository: ThreatRepositoryProtocol
    let sourceManager: SourceManagerProtocol

    // Networking
    let apiClient: APIClient
    let orchestrator: IngestionOrchestrator

    // Background sync
    let backgroundSync: BackgroundSyncService

    // ViewModels (created lazily to avoid init cycle)
    private(set) var dashboardVM: DashboardViewModel?
    private(set) var sourceConfigVM: SourceConfigViewModel?

    /// Whether first-launch setup has completed (default feed seeding).
    private(set) var isSetupComplete = false

    init() {
        self.database = .shared
        self.keychain = KeychainManager.shared
        let sourceMgr = SourceManager(db: database, keychain: keychain)
        self.sourceManager = sourceMgr
        let repo = ThreatRepository(db: database)
        self.repository = repo
        self.apiClient = APIClient()
        self.orchestrator = IngestionOrchestrator(
            sourceManager: sourceManager,
            repository: repository,
            client: apiClient
        )
        self.backgroundSync = BackgroundSyncService(orchestrator: orchestrator)
    }

    /// Seed default feeds if first launch. Call before creating ViewModels.
    func setupIfNeeded() async {
        guard !isSetupComplete else { return }
        _ = await DefaultSources.seedIfNeeded(using: sourceManager)
        isSetupComplete = true
    }

    func makeDashboardViewModel() -> DashboardViewModel {
        let vm = DashboardViewModel(
            repository: repository,
            orchestrator: orchestrator,
            sourceManager: sourceManager
        )
        self.dashboardVM = vm
        return vm
    }

    func makeSourceConfigViewModel() -> SourceConfigViewModel {
        let vm = SourceConfigViewModel(
            sourceManager: sourceManager,
            repository: repository
        )
        self.sourceConfigVM = vm
        return vm
    }
}
