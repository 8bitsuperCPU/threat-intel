import SwiftUI

@main
struct Threat_IntelApp: App {
    @State private var container = DependencyContainer()
    @State private var isReady = false

    var body: some Scene {
        WindowGroup {
            if isReady {
                ContentView()
                    .environment(container)
                    .frame(minWidth: 900, minHeight: 560)
            } else {
                VStack(spacing: 16) {
                    ProgressView()
                        .scaleEffect(1.2)
                    Text("Threat Intel")
                        .font(.system(size: 16, weight: .semibold, design: .rounded))
                    Text("Initializing...")
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                }
                .frame(width: 400, height: 300)
                .background(VisualEffectView(material: .windowBackground))
                .task {
                    await container.setupIfNeeded()
                    isReady = true
                }
            }
        }
        .windowResizability(.contentMinSize)
        .commands {
            CommandGroup(after: .newItem) {
                Button("Refresh All Sources") {
                    Task { await container.dashboardVM?.refreshAll() }
                }
                .keyboardShortcut("r", modifiers: [.command, .shift])
            }
        }
        .onChange(of: NSApplication.shared.isActive) { _, active in
            if active {
                Task { await container.backgroundSync.start() }
            }
        }
    }
}
