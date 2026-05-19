import SwiftUI

struct ContentView: View {
    @Environment(DependencyContainer.self) private var container

    var body: some View {
        DashboardView(viewModel: container.makeDashboardViewModel())
            .background(VisualEffectView(material: .windowBackground).ignoresSafeArea())
    }
}

#Preview {
    ContentView()
        .environment(DependencyContainer())
}
