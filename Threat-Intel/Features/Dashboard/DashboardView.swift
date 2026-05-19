import SwiftUI
import AppKit

// MARK: - Dashboard View (Maverick Polish)

struct DashboardView: View {
    @State private var viewModel: DashboardViewModel
    @State private var selectedTab = "threats"
    @State private var searchText = ""
    @State private var searchTask: Task<Void, Never>?

    @Environment(DependencyContainer.self) private var container
    @State private var sourceVM: SourceConfigViewModel?

    init(viewModel: DashboardViewModel) {
        self._viewModel = State(initialValue: viewModel)
    }

    var body: some View {
        NavigationSplitView {
            sidebar
                .navigationSplitViewColumnWidth(min: 200, ideal: 220)
        } detail: {
            if selectedTab == "sources" {
                if let vm = sourceVM {
                    SourceConfigView(viewModel: vm)
                } else {
                    ProgressView()
                        .task {
                            sourceVM = container.makeSourceConfigViewModel()
                        }
                }
            } else {
                mainContent
            }
        }
        .searchable(text: $searchText, prompt: "Search threats...")
        .onChange(of: searchText) { _, newValue in
            viewModel.searchQuery = newValue
            searchTask?.cancel()
            if newValue.isEmpty {
                Task { await viewModel.loadDashboard() }
            } else {
                searchTask = Task {
                    try? await Task.sleep(nanoseconds: 300_000_000)
                    guard !Task.isCancelled else { return }
                    await viewModel.search()
                }
            }
        }
        .task {
            await viewModel.loadDashboard()
        }
        .background(VisualEffectView(material: .windowBackground).ignoresSafeArea())
    }

    // MARK: - Sidebar

    private var sidebar: some View {
        List(selection: $selectedTab) {
            Label("Dashboard", systemImage: "shield.checkered")
                .tag("threats")

            Label("Settings", systemImage: "antenna.radiowaves.left.and.right")
                .tag("sources")

            Divider()

            Section {
                statsOverview
            } header: {
                Text("Overview")
                    .font(.system(size: 11, weight: .semibold, design: .monospaced))
                    .foregroundStyle(.secondary)
            }

            Section {
                ForEach(ThreatSeverity.allCases, id: \.self) { severity in
                    severityFilterButton(severity)
                }
                allFilterButton
            } header: {
                Text("Severity")
                    .font(.system(size: 11, weight: .semibold, design: .monospaced))
                    .foregroundStyle(.secondary)
            }
        }
        .navigationTitle("Threat Intel")
        .listStyle(.sidebar)
        .scrollContentBackground(.hidden)
        .background(VisualEffectView(material: .sidebar).ignoresSafeArea())
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                refreshButton
            }
        }
    }

    // MARK: - Stats Overview

    private var statsOverview: some View {
        VStack(spacing: 6) {
            HStack {
                Text("\(viewModel.totalThreatCount)")
                    .font(.system(size: 28, weight: .ultraLight, design: .serif))
                    .foregroundStyle(.primary)
                Spacer()
            }

            if !viewModel.recentFailedSources.isEmpty {
                HStack(spacing: 4) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .font(.system(size: 9))
                        .foregroundStyle(.orange)
                    Text("\(viewModel.recentFailedSources.count) source\(viewModel.recentFailedSources.count == 1 ? "" : "s") failing")
                        .font(.system(size: 10))
                        .foregroundStyle(.secondary)
                }
            }
        }
        .padding(.vertical, 4)
    }

    // MARK: - Severity Filter

    private func severityFilterButton(_ severity: ThreatSeverity) -> some View {
        Button {
            viewModel.filter(by: viewModel.selectedSeverity == severity ? nil : severity)
        } label: {
            HStack(spacing: 8) {
                severityDot(severity)
                Text(severity.rawValue)
                    .font(.system(size: 12))
                Spacer()
                if viewModel.selectedSeverity == severity {
                    Image(systemName: "checkmark")
                        .font(.system(size: 10, weight: .bold))
                        .foregroundStyle(.secondary)
                }
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    @ViewBuilder
    private func severityDot(_ severity: ThreatSeverity) -> some View {
        Circle()
            .fill(severityGradient(severity))
            .frame(width: 8, height: 8)
            .overlay(
                Circle()
                    .stroke(.white.opacity(0.3), lineWidth: 0.5)
            )
    }

    // MARK: - All Filter

    private var allFilterButton: some View {
        Button {
            viewModel.filteredSourceName = nil
            viewModel.filter(by: nil)
        } label: {
            HStack(spacing: 8) {
                Circle()
                    .fill(LinearGradient(colors: [.white.opacity(0.6), .gray.opacity(0.4)], startPoint: .top, endPoint: .bottom))
                    .frame(width: 8, height: 8)
                    .overlay(
                        Circle()
                            .stroke(.white.opacity(0.3), lineWidth: 0.5)
                    )
                Text("All")
                    .font(.system(size: 12))
                Spacer()
                if viewModel.selectedSeverity == nil {
                    Image(systemName: "checkmark")
                        .font(.system(size: 10, weight: .bold))
                        .foregroundStyle(.secondary)
                }
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    // MARK: - Refresh Button

    private var refreshButton: some View {
        Button {
            Task { await viewModel.refreshAll() }
        } label: {
            Image(systemName: "arrow.triangle.2.circlepath")
                .font(.system(size: 14, weight: .medium))
                .rotationEffect(.degrees(viewModel.isRefreshing ? 360 : 0))
                .animation(
                    viewModel.isRefreshing
                        ? .linear(duration: 1).repeatForever(autoreverses: false)
                        : .default,
                    value: viewModel.isRefreshing
                )
        }
        .disabled(viewModel.isRefreshing)
        .help("Refresh all sources (⇧⌘R)")
    }

    // MARK: - Main Content

    @ViewBuilder
    private var mainContent: some View {
        switch viewModel.state {
        case .idle, .loading:
            loadingView

        case .empty:
            ContentUnavailableView(
                "No Threats",
                systemImage: "shield.slash",
                description: Text("Add sources and refresh to populate the dashboard.")
            )

        case .loaded(let items, let lastUpdated):
            bentoGrid(items: items, lastUpdated: lastUpdated)

        case .partial(let items, let failedSources):
            VStack(spacing: 0) {
                failedSourcesBanner(failedSources)
                bentoGrid(items: items, lastUpdated: Date())
            }

        case .error(let message):
            ContentUnavailableView(
                "Error",
                systemImage: "exclamationmark.triangle",
                description: Text(message)
            )
        }
    }

    // MARK: - Loading View

    private var loadingView: some View {
        VStack(spacing: 16) {
            ProgressView()
                .scaleEffect(1.2)
            Text("Loading threat data...")
                .font(.system(size: 13, weight: .medium))
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: - Failed Sources Banner

    private func failedSourcesBanner(_ failures: [String]) -> some View {
        HStack(spacing: 6) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
                .font(.system(size: 11))
            Text("Failed: \(failures.joined(separator: ", "))")
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.orange.opacity(0.08))
    }

    // MARK: - Bento Grid

    private func bentoGrid(items: [ThreatItem], lastUpdated: Date) -> some View {
        VStack(spacing: 0) {
            // Status bar
            HStack {
                Text("\(items.count) threat\(items.count == 1 ? "" : "s")")
                    .font(.system(size: 12, weight: .medium, design: .monospaced))
                    .foregroundStyle(.secondary)
                Spacer()
                Text("Updated \(lastUpdated.formatted(.relative(presentation: .named)))")
                    .font(.system(size: 11))
                    .foregroundStyle(.tertiary)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 8)

            Divider()
                .opacity(0.5)

            // Raw ingestion results (collapsible)
            if !viewModel.lastIngestionResults.isEmpty {
                IngestionResultsPanel(results: viewModel.lastIngestionResults, selectedSource: viewModel.filteredSourceName, onSelectSource: { name in
                    viewModel.filterBySource(name: name)
                })
                Divider().opacity(0.5)
            }

            // Source filter indicator
            if let sourceName = viewModel.filteredSourceName {
                HStack {
                    Image(systemName: "line.3.horizontal.decrease.circle.fill")
                        .font(.system(size: 10))
                        .foregroundStyle(.cyan)
                    Text("Filtered by: \(sourceName)")
                        .font(.system(size: 11, weight: .medium))
                        .foregroundStyle(.cyan)
                    Spacer()
                    Button("Clear") {
                        viewModel.filterBySource(name: nil)
                    }
                    .buttonStyle(.plain)
                    .font(.system(size: 10, weight: .medium))
                    .foregroundStyle(.cyan)
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 4)
                Divider().opacity(0.5)
            }

            // Bento card grid
            ScrollView {
                LazyVGrid(
                    columns: [GridItem(.adaptive(minimum: 340, maximum: 500), spacing: 12)],
                    spacing: 12
                ) {
                    ForEach(items) { item in
                        ThreatCard(item: item)
                    }
                }
                .padding(16)
            }
        }
    }

    // MARK: - Helpers

    private func severityGradient(_ severity: ThreatSeverity) -> LinearGradient {
        switch severity {
        case .critical:
            return LinearGradient(colors: [.red, .red.opacity(0.7)], startPoint: .top, endPoint: .bottom)
        case .high:
            return LinearGradient(colors: [.orange, .orange.opacity(0.7)], startPoint: .top, endPoint: .bottom)
        case .medium:
            return LinearGradient(colors: [.yellow, .yellow.opacity(0.7)], startPoint: .top, endPoint: .bottom)
        case .low:
            return LinearGradient(colors: [.blue, .blue.opacity(0.7)], startPoint: .top, endPoint: .bottom)
        case .informational:
            return LinearGradient(colors: [.gray, .gray.opacity(0.7)], startPoint: .top, endPoint: .bottom)
        }
    }
}

// MARK: - Threat Card (Bento Style)

struct ThreatCard: View {
    let item: ThreatItem
    @State private var isHovered = false

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            // Header row
            HStack(spacing: 8) {
                // Severity icon with gradient glow
                Image(systemName: severityIcon)
                    .font(.system(size: 18, weight: .light))
                    .foregroundStyle(
                        isHovered
                            ? AnyShapeStyle(severityGradient)
                            : AnyShapeStyle(Color.secondary)
                    )
                    .scaleEffect(isHovered ? 1.15 : 1.0)
                    .animation(.spring(response: 0.35, dampingFraction: 0.7), value: isHovered)

                // Title as clickable link
                if let urlString = item.url, let url = URL(string: urlString) {
                    Link(destination: url) {
                        Text(item.title)
                            .font(.system(size: 14, weight: .semibold))
                            .lineLimit(2)
                            .foregroundStyle(.primary)
                    }
                    .onHover { hovering in
                        if hovering { NSCursor.pointingHand.push() }
                        else { NSCursor.pop() }
                    }
                } else {
                    Text(item.title)
                        .font(.system(size: 14, weight: .semibold))
                        .lineLimit(2)
                        .foregroundStyle(.primary)
                }

                Spacer()

                // Severity badge
                Text(item.severity.rawValue.uppercased())
                    .font(.system(size: 9, weight: .bold, design: .monospaced))
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(severityColor.opacity(0.12))
                    .foregroundStyle(severityColor)
                    .clipShape(Capsule())
            }

            // Description
            Text(item.description)
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
                .lineLimit(3)

            Spacer(minLength: 4)

            // Footer
            HStack(spacing: 8) {
                // Source chip
                Text(item.sourceName)
                    .font(.system(size: 10, weight: .medium))
                    .foregroundStyle(.blue)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(.blue.opacity(0.08))
                    .clipShape(Capsule())

                if !item.indicators.isEmpty {
                    HStack(spacing: 3) {
                        Image(systemName: "tag")
                            .font(.system(size: 8))
                        Text("\(item.indicators.count)")
                            .font(.system(size: 10, weight: .medium, design: .monospaced))
                    }
                    .foregroundStyle(.secondary)
                }

                Spacer()

                Text(item.publishedAt.formatted(date: .abbreviated, time: .shortened))
                    .font(.system(size: 10))
                    .foregroundStyle(.tertiary)
            }
        }
        .padding(14)
        .frame(minHeight: 140)
        // Bento card with material background
        .background(
            RoundedRectangle(cornerRadius: 16, style: .continuous)
                .fill(.regularMaterial)
        )
        .background(
            RoundedRectangle(cornerRadius: 16, style: .continuous)
                .fill(severityBackgroundColor)
        )
        // Dynamic gradient border on hover
        .overlay(
            RoundedRectangle(cornerRadius: 16, style: .continuous)
                .stroke(
                    LinearGradient(
                        colors: isHovered
                            ? [severityColor.opacity(0.6), severityColor.opacity(0.15), Color.clear]
                            : [Color.white.opacity(0.08), Color.clear],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    ),
                    lineWidth: isHovered ? 1.5 : 0.5
                )
        )
        // Tactile shadow depth
        .shadow(
            color: .black.opacity(isHovered ? 0.18 : 0.08),
            radius: isHovered ? 12 : 3,
            x: 0,
            y: isHovered ? 6 : 1
        )
        .scaleEffect(isHovered ? 1.015 : 1.0)
        .animation(.spring(response: 0.35, dampingFraction: 0.75), value: isHovered)
        .onHover { hovering in
            isHovered = hovering
        }
    }

    // MARK: - Computed Properties

    private var severityIcon: String {
        switch item.severity {
        case .critical: return "exclamationmark.shield.fill"
        case .high: return "exclamationmark.triangle.fill"
        case .medium: return "info.circle.fill"
        case .low: return "info.circle"
        case .informational: return "doc.text"
        }
    }

    private var severityColor: Color {
        switch item.severity {
        case .critical: return .red
        case .high: return .orange
        case .medium: return .yellow
        case .low: return .blue
        case .informational: return .gray
        }
    }

    private var severityBackgroundColor: Color {
        switch item.severity {
        case .informational: return Color.green.opacity(0.18)
        case .low: return Color.blue.opacity(0.18)
        case .critical: return Color.red.opacity(0.18)
        case .high: return Color.orange.opacity(0.18)
        default: return .clear
        }
    }

    private var severityGradient: LinearGradient {
        switch item.severity {
        case .critical:
            return LinearGradient(colors: [.red, .pink.opacity(0.7)], startPoint: .topLeading, endPoint: .bottomTrailing)
        case .high:
            return LinearGradient(colors: [.orange, .yellow.opacity(0.7)], startPoint: .topLeading, endPoint: .bottomTrailing)
        case .medium:
            return LinearGradient(colors: [.yellow, .orange.opacity(0.5)], startPoint: .topLeading, endPoint: .bottomTrailing)
        case .low:
            return LinearGradient(colors: [.blue, .cyan.opacity(0.7)], startPoint: .topLeading, endPoint: .bottomTrailing)
        case .informational:
            return LinearGradient(colors: [.gray, .gray.opacity(0.5)], startPoint: .topLeading, endPoint: .bottomTrailing)
        }
    }
}

// MARK: - Ingestion Results Panel (Raw Feed Data)

struct IngestionResultsPanel: View {
    let results: [FeedIngestionState]
    let selectedSource: String?
    let onSelectSource: (String?) -> Void
    @State private var isExpanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Button {
                withAnimation(.spring(response: 0.3, dampingFraction: 0.8)) {
                    isExpanded.toggle()
                }
            } label: {
                HStack(spacing: 6) {
                    Image(systemName: isExpanded ? "chevron.down" : "chevron.right")
                        .font(.system(size: 10, weight: .bold))
                    Text("Ingestion Results")
                        .font(.system(size: 12, weight: .semibold, design: .monospaced))
                    Spacer()
                    let totalNew = results.reduce(0) { count, state in
                        if case .completed(_, let n) = state { return count + n }
                        return count
                    }
                    Text("\(totalNew) new")
                        .font(.system(size: 10, weight: .medium, design: .monospaced))
                        .foregroundStyle(totalNew > 0 ? .green : .secondary)
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 6)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            if isExpanded {
                Divider().opacity(0.3)

                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 4) {
                        ForEach(results.indices, id: \.self) { idx in
                            resultRow(results[idx])
                        }
                    }
                    .padding(8)
                }
                .frame(maxHeight: 200)
            }
        }
    }

    @ViewBuilder
    private func resultRow(_ result: FeedIngestionState) -> some View {
        switch result {
        case .fetching(let name):
            HStack(spacing: 4) {
                ProgressView().scaleEffect(0.5)
                Text(name).font(.system(size: 11))
            }
            .foregroundStyle(.secondary)
        case .completed(let name, let count):
            HStack(spacing: 4) {
                Image(systemName: count > 0 ? "checkmark.circle.fill" : "circle")
                    .foregroundStyle(count > 0 ? .green : .secondary)
                    .font(.system(size: 10))
                Text(name).font(.system(size: 11)).foregroundStyle(.primary)
                Spacer()
                Text("\(count) items").font(.system(size: 10)).foregroundStyle(.secondary)
                if selectedSource == name {
                    Image(systemName: "line.3.horizontal.decrease.circle.fill")
                        .font(.system(size: 9))
                        .foregroundStyle(.cyan)
                }
            }
            .contentShape(Rectangle())
            .onTapGesture {
                let newName = (selectedSource == name) ? nil : name
                onSelectSource(newName)
            }
        case .failed(let name, let error):
            HStack(spacing: 4) {
                Image(systemName: "xmark.circle.fill")
                    .foregroundStyle(.red)
                    .font(.system(size: 10))
                Text(name).font(.system(size: 11)).foregroundStyle(.primary)
                Spacer()
                Text(error).font(.system(size: 9)).foregroundStyle(.red).lineLimit(1)
            }
        default:
            EmptyView()
        }
    }
}

// MARK: - NSViewRepresentable for VisualEffectView

struct VisualEffectView: NSViewRepresentable {
    let material: NSVisualEffectView.Material

    func makeNSView(context: Context) -> NSVisualEffectView {
        let view = NSVisualEffectView()
        view.material = material
        view.blendingMode = .behindWindow
        view.state = .active
        return view
    }

    func updateNSView(_ nsView: NSVisualEffectView, context: Context) {
        nsView.material = material
    }
}
