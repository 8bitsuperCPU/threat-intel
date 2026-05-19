import SwiftUI

// MARK: - Source Config View (Maverick Polish)

struct SourceConfigView: View {
    @State private var viewModel: SourceConfigViewModel
    @State private var showEditor = false

    init(viewModel: SourceConfigViewModel) {
        self._viewModel = State(initialValue: viewModel)
    }

    var body: some View {
        Group {
            switch viewModel.state {
            case .idle, .loading:
                loadingView

            case .loaded, .saving, .saved, .deleting, .error:
                sourceListContent
            }
        }
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                addButton
            }
        }
        .sheet(isPresented: $showEditor) {
            sourceEditorSheet
        }
    }

    // MARK: - Loading

    private var loadingView: some View {
        VStack(spacing: 16) {
            ProgressView()
                .scaleEffect(1.2)
            Text("Loading sources...")
                .font(.system(size: 13, weight: .medium))
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .task { await viewModel.loadSources() }
    }

    // MARK: - Add Button

    private var addButton: some View {
        Button {
            viewModel.beginAdd()
            showEditor = true
        } label: {
            Image(systemName: "plus")
                .font(.system(size: 14, weight: .medium))
        }
        .help("Add source")
    }

    // MARK: - Source List

    private var sourceListContent: some View {
        VStack(spacing: 0) {
            // Error banner
            if let error = viewModel.errorMessage {
                HStack(spacing: 6) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                        .font(.system(size: 11))
                    Text(error)
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 8)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(.orange.opacity(0.08))
            }

            // Header
            HStack {
                Text("Configured Sources")
                    .font(.system(size: 12, weight: .medium, design: .monospaced))
                    .foregroundStyle(.secondary)
                Spacer()
                Text("\(viewModel.sources.count) total")
                    .font(.system(size: 11))
                    .foregroundStyle(.tertiary)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 8)

            Divider()
                .opacity(0.5)

            if viewModel.sources.isEmpty {
                emptyState
            } else {
                ScrollView {
                    LazyVStack(spacing: 6) {
                        ForEach(viewModel.sources) { source in
                            PolishedSourceRow(
                                source: source,
                                onToggle: { Task { await viewModel.toggleSource(source) } },
                                onEdit: {
                                    viewModel.beginEdit(source)
                                    showEditor = true
                                },
                                onDelete: { Task { await viewModel.deleteSource(source) } }
                            )
                        }
                    }
                    .padding(16)
                }
            }

            Divider().opacity(0.5)

            settingsSection
        }
    }

    // MARK: - Empty State

    private var emptyState: some View {
        VStack(spacing: 12) {
            Image(systemName: "antenna.radiowaves.left.and.right.slash")
                .font(.system(size: 36, weight: .ultraLight))
                .foregroundStyle(.secondary)
            Text("No Sources Configured")
                .font(.system(size: 15, weight: .medium))
                .foregroundStyle(.secondary)
            Text("Add threat intelligence sources to begin\ncollecting and correlating data.")
                .font(.system(size: 12))
                .foregroundStyle(.tertiary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: - Settings Section

    private var settingsSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Settings")
                .font(.system(size: 12, weight: .medium, design: .monospaced))
                .foregroundStyle(.secondary)

            // Backlog depth
            HStack {
                Text("Backlog depth:")
                    .font(.system(size: 12))
                    .foregroundStyle(.primary)
                Spacer()
                HStack(spacing: 6) {
                    Button {
                        viewModel.backlogDepth = max(viewModel.backlogDepth - 1, 3)
                    } label: {
                        Image(systemName: "minus.circle.fill")
                            .font(.system(size: 16))
                            .foregroundStyle(.blue)
                    }
                    .buttonStyle(.plain)
                    .help("Decrease backlog (min 3 days)")

                    Text("\(viewModel.backlogDepth) days")
                        .font(.system(size: 13, weight: .medium, design: .monospaced))
                        .frame(minWidth: 60)
                        .foregroundStyle(.primary)

                    Button {
                        viewModel.backlogDepth = min(viewModel.backlogDepth + 1, 25)
                    } label: {
                        Image(systemName: "plus.circle.fill")
                            .font(.system(size: 16))
                            .foregroundStyle(.blue)
                    }
                    .buttonStyle(.plain)
                    .help("Increase backlog (max 25 days)")
                }
            }

            // Clear cache
            HStack {
                Text("Threat data cache")
                    .font(.system(size: 12))
                    .foregroundStyle(.primary)
                Spacer()
                Button {
                    Task { await viewModel.clearCache() }
                } label: {
                    HStack(spacing: 4) {
                        if viewModel.isClearingCache {
                            ProgressView()
                                .scaleEffect(0.6)
                        } else {
                            Image(systemName: "trash")
                                .font(.system(size: 11))
                        }
                        Text("Clear Cache")
                            .font(.system(size: 11, weight: .medium))
                    }
                    .foregroundStyle(.red)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 4)
                    .background(.red.opacity(0.08))
                    .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
                }
                .buttonStyle(.plain)
                .disabled(viewModel.isClearingCache)
                .help("Delete all cached threat items and indicators")
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
    }

    // MARK: - Editor Sheet

    private var sourceEditorSheet: some View {
        VStack(alignment: .leading, spacing: 18) {
            // Header
            HStack {
                Text(viewModel.editorIsNew ? "Add Source" : "Edit Source")
                    .font(.system(size: 18, weight: .semibold, design: .rounded))
                Spacer()
            }

            Divider()
                .opacity(0.3)

            // Fields
            VStack(alignment: .leading, spacing: 14) {
                editorField(
                    label: "Name",
                    placeholder: "e.g. SANS ISC",
                    text: $viewModel.editorName
                )

                VStack(alignment: .leading, spacing: 4) {
                    Text("Type")
                        .font(.system(size: 10, weight: .medium, design: .monospaced))
                        .foregroundStyle(.secondary)
                    Picker("Type", selection: $viewModel.editorType) {
                        ForEach(SourceType.allCases, id: \.self) { type in
                            HStack {
                                Image(systemName: sourceTypeIcon(type))
                                    .font(.system(size: 11))
                                Text(type.rawValue)
                            }
                            .tag(type)
                        }
                    }
                    .pickerStyle(.menu)
                    .labelsHidden()
                    .frame(maxWidth: .infinity, alignment: .leading)
                }

                editorField(
                    label: viewModel.editorType == .rss ? "Feed URL" : "Base URL",
                    placeholder: "https://...",
                    text: $viewModel.editorURL
                )

                VStack(alignment: .leading, spacing: 4) {
                    Text("API Key")
                        .font(.system(size: 10, weight: .medium, design: .monospaced))
                        .foregroundStyle(.secondary)
                    SecureField("Enter API key", text: $viewModel.editorAPIKey)
                        .textFieldStyle(.roundedBorder)
                        .font(.system(size: 12))
                }

                HStack(spacing: 8) {
                    Text("Rate limit (req/min):")
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                    TextField("30", value: $viewModel.editorRateLimit, format: .number)
                        .textFieldStyle(.roundedBorder)
                        .font(.system(size: 12))
                        .frame(width: 80)
                }
            }

            if let error = viewModel.errorMessage {
                Text(error)
                    .font(.system(size: 11))
                    .foregroundStyle(.red)
            }

            Spacer()

            Divider()
                .opacity(0.3)

            // Actions
            HStack {
                Spacer()
                Button("Cancel") {
                    showEditor = false
                }
                .keyboardShortcut(.cancelAction)
                .buttonStyle(.plain)
                .padding(.horizontal, 12)
                .padding(.vertical, 6)
                .background(.secondary.opacity(0.1))
                .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))

                Button(viewModel.editorIsNew ? "Add Source" : "Save Changes") {
                    Task {
                        await viewModel.saveSource()
                        showEditor = false
                    }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(viewModel.editorName.isEmpty)
                .buttonStyle(.plain)
                .padding(.horizontal, 16)
                .padding(.vertical, 6)
                .background(viewModel.editorName.isEmpty ? .blue.opacity(0.3) : .blue)
                .foregroundStyle(.white)
                .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
            }
        }
        .padding(24)
        .frame(width: 440, height: 440)
    }

    // MARK: - Helpers

    private func editorField(label: String, placeholder: String, text: Binding<String>) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label)
                .font(.system(size: 10, weight: .medium, design: .monospaced))
                .foregroundStyle(.secondary)
            TextField(placeholder, text: text)
                .textFieldStyle(.roundedBorder)
                .font(.system(size: 12))
        }
    }

    private func sourceTypeIcon(_ type: SourceType) -> String {
        switch type {
        case .otx: return "globe.americas"
        case .abuseIPDB: return "network"
        case .sans: return "shield"
        case .rss: return "dot.radiowaves.left.and.right"
        case .custom: return "gearshape"
        }
    }
}

// MARK: - Polished Source Row

struct PolishedSourceRow: View {
    let source: ThreatSource
    let onToggle: () -> Void
    let onEdit: () -> Void
    let onDelete: () -> Void

    @State private var isHovered = false

    var body: some View {
        HStack(spacing: 14) {
            // Enable/disable toggle with spring animation
            Button(action: onToggle) {
                ZStack {
                    Circle()
                        .fill(source.isEnabled ? .green : .secondary.opacity(0.2))
                        .frame(width: 22, height: 22)
                    if source.isEnabled {
                        Image(systemName: "checkmark")
                            .font(.system(size: 10, weight: .bold))
                            .foregroundStyle(.white)
                            .transition(.scale.combined(with: .opacity))
                    }
                }
            }
            .buttonStyle(.plain)
            .animation(.spring(response: 0.35, dampingFraction: 0.7), value: source.isEnabled)

            // Source info
            VStack(alignment: .leading, spacing: 2) {
                Text(source.name)
                    .font(.system(size: 13, weight: .medium))
                    .foregroundStyle(.primary)

                HStack(spacing: 6) {
                    Image(systemName: sourceTypeIcon(source.type))
                        .font(.system(size: 9))
                    Text(source.type.rawValue)
                        .font(.system(size: 10))
                        .foregroundStyle(.secondary)

                    if let lastFetch = source.lastFetchedAt {
                        Text("·")
                            .foregroundStyle(.tertiary)
                        Text("Last: \(lastFetch.formatted(.relative(presentation: .named)))")
                            .font(.system(size: 10))
                            .foregroundStyle(.tertiary)
                    }

                    if source.lastError != nil {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .font(.system(size: 9))
                            .foregroundStyle(.orange)
                    }
                }
            }

            Spacer()

            // Action buttons (reveal on hover)
            HStack(spacing: 2) {
                Button(action: onEdit) {
                    Image(systemName: "pencil")
                        .font(.system(size: 11))
                }
                .buttonStyle(.borderless)
                .help("Edit source")
                .opacity(isHovered ? 1 : 0)

                Button(action: onDelete) {
                    Image(systemName: "trash")
                        .font(.system(size: 11))
                        .foregroundStyle(.red)
                }
                .buttonStyle(.borderless)
                .help("Delete source")
                .opacity(isHovered ? 1 : 0)
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .background(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .fill(isHovered ? .primary.opacity(0.04) : Color.clear)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .stroke(.white.opacity(isHovered ? 0.08 : 0), lineWidth: 0.5)
        )
        .animation(.easeOut(duration: 0.15), value: isHovered)
        .onHover { hovering in
            isHovered = hovering
        }
    }

    private func sourceTypeIcon(_ type: SourceType) -> String {
        switch type {
        case .otx: return "globe.americas"
        case .abuseIPDB: return "network"
        case .sans: return "shield"
        case .rss: return "dot.radiowaves.left.and.right"
        case .custom: return "gearshape"
        }
    }
}
