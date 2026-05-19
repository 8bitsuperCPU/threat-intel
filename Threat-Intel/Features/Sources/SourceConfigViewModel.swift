import Foundation
import Observation

@Observable
@MainActor
final class SourceConfigViewModel {
    private let sourceManager: SourceManagerProtocol
    private let repository: ThreatRepositoryProtocol

    var state: SourceConfigState = .idle
    var sources: [ThreatSource] = []

    // Editor fields
    var editingSource: ThreatSource?
    var editorName = ""
    var editorType: SourceType = .otx
    var editorURL = ""
    var editorAPIKey = ""
    var editorRateLimit = 30
    var editorIsNew = true

    var errorMessage: String?
    var isClearingCache = false

    var backlogDepth: Int {
        get { DefaultSources.backlogDepth }
        set { DefaultSources.backlogDepth = newValue }
    }

    init(sourceManager: SourceManagerProtocol, repository: ThreatRepositoryProtocol) {
        self.sourceManager = sourceManager
        self.repository = repository
    }

    func loadSources() async {
        state = .loading
        do {
            sources = try await sourceManager.allSources()
            state = .loaded(sources: sources)
        } catch {
            state = .error(error.localizedDescription)
        }
    }

    func beginAdd() {
        editingSource = nil
        editorName = ""
        editorType = .otx
        editorURL = ""
        editorAPIKey = ""
        editorRateLimit = 30
        editorIsNew = true
        errorMessage = nil
    }

    func beginEdit(_ source: ThreatSource) {
        editingSource = source
        editorName = source.name
        editorType = source.type
        editorURL = source.baseURL
        editorAPIKey = ""
        editorRateLimit = source.rateLimitPerMinute
        editorIsNew = false
        errorMessage = nil
    }

    func saveSource() async {
        guard !editorName.isEmpty else {
            errorMessage = "Source name is required"
            return
        }

        if editorType == .rss || editorType == .sans || editorType == .custom {
            guard !editorURL.isEmpty, URL(string: editorURL) != nil else {
                errorMessage = "Valid URL is required"
                return
            }
        }

        state = .saving
        errorMessage = nil

        do {
            if editorIsNew {
                let source = ThreatSource(
                    name: editorName,
                    type: editorType,
                    baseURL: editorURL,
                    rateLimitPerMinute: editorRateLimit
                )
                try await sourceManager.add(source: source)

                // Save API key if provided
                if !editorAPIKey.isEmpty {
                    try (sourceManager as? SourceManager)?.saveAPIKey(editorAPIKey, for: source.id)
                }

                state = .saved(source: source)
            } else if let existing = editingSource {
                var updated = existing
                updated.name = editorName
                updated.type = editorType
                updated.baseURL = editorURL
                updated.rateLimitPerMinute = editorRateLimit
                try await sourceManager.update(source: updated)

                if !editorAPIKey.isEmpty {
                    try (sourceManager as? SourceManager)?.saveAPIKey(editorAPIKey, for: existing.id)
                }

                state = .saved(source: updated)
            }
        } catch {
            errorMessage = error.localizedDescription
            state = .error(error.localizedDescription)
        }

        await loadSources()
    }

    func deleteSource(_ source: ThreatSource) async {
        state = .deleting
        do {
            try await sourceManager.delete(sourceID: source.id)
            await loadSources()
        } catch {
            errorMessage = error.localizedDescription
            state = .error(error.localizedDescription)
        }
    }

    func toggleSource(_ source: ThreatSource) async {
        do {
            try await sourceManager.toggle(sourceID: source.id, enabled: !source.isEnabled)
            await loadSources()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func clearCache() async {
        isClearingCache = true
        do {
            try await repository.deleteAllThreats()
        } catch {
            errorMessage = error.localizedDescription
        }
        isClearingCache = false
    }
}
