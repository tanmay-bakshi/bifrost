import SwiftUI

@main
struct BifrostApp: App {
    @StateObject private var session = SessionModel()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            ContentView(session: session)
                .preferredColorScheme(.dark)
        }
        .onChange(of: scenePhase) { _, phase in
            if phase == .background { session.enteredBackground() }
        }
    }
}
