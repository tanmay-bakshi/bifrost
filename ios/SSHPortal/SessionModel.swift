import Combine
import Foundation
import UIKit

struct SessionOffer {
    let operatorName: String
    let description: String
    let mode: String
}

@MainActor
final class SessionModel: ObservableObject {
    @Published var serverURL = ""
    @Published var reconnect = false
    @Published var keepAwake = true {
        didSet { updateIdleTimer() }
    }
    @Published private(set) var phase = "Ready"
    @Published private(set) var offer: SessionOffer?
    @Published private(set) var errorMessage: String?
    @Published private(set) var isRunning = false
    @Published private(set) var needsApproval = false

    private var client: OpaquePointer?
    private var polling: Task<Void, Never>?

    private struct Configuration: Encodable {
        let server: String
        let device_name: String
        let reconnect: Bool
    }

    private struct Event: Decodable {
        let kind: String
        let phase: String?
        let `operator`: String?
        let description: String?
        let mode: String?
        let message: String?
    }

    func connect() {
        guard client == nil else { return }
        errorMessage = nil
        offer = nil
        needsApproval = false
        do {
            let configuration = Configuration(
                server: serverURL.trimmingCharacters(in: .whitespacesAndNewlines),
                device_name: UIDevice.current.name,
                reconnect: reconnect
            )
            let data = try JSONEncoder().encode(configuration)
            let json = String(decoding: data, as: UTF8.self)
            client = json.withCString { sshportal_client_create($0) }
            isRunning = true
            phase = "Connecting"
            updateIdleTimer()
            polling = Task { [weak self] in
                while !Task.isCancelled {
                    self?.pollEvents()
                    do { try await Task.sleep(for: .milliseconds(100)) }
                    catch { return }
                }
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func approve(_ allowed: Bool) {
        guard let client, needsApproval else { return }
        needsApproval = false
        phase = allowed ? "Starting session" : "Declining session"
        sshportal_client_approve(client, allowed)
    }

    func disconnect(reason: String = "Disconnected") {
        polling?.cancel()
        polling = nil
        if let client { sshportal_client_free(client) }
        client = nil
        isRunning = false
        needsApproval = false
        phase = reason
        updateIdleTimer()
    }

    func enteredBackground() {
        guard isRunning else { return }
        disconnect(reason: "Disconnected when app left foreground")
    }

    private func updateIdleTimer() {
        UIApplication.shared.isIdleTimerDisabled = isRunning && keepAwake
    }

    private func pollEvents() {
        guard let client else { return }
        // Bound work on the UI thread. The Rust task remains the owner of networking.
        for _ in 0..<16 {
            guard let pointer = sshportal_client_poll(client) else { return }
            let data = Data(bytes: pointer, count: strlen(pointer))
            sshportal_string_free(pointer)
            do {
                let event = try JSONDecoder().decode(Event.self, from: data)
                switch event.kind {
                case "status":
                    switch event.phase {
                    case "connecting": phase = "Connecting"
                    case "connected": phase = "Connected"
                    case "reconnecting": phase = "Reconnecting"
                    default: break
                    }
                case "offer":
                    guard let name = event.operator, let description = event.description, let mode = event.mode else {
                        throw DecodingError.dataCorrupted(.init(codingPath: [], debugDescription: "Incomplete session offer"))
                    }
                    offer = SessionOffer(operatorName: name, description: description, mode: mode)
                    needsApproval = true
                    phase = "Your approval is needed"
                case "failed":
                    errorMessage = event.message ?? "The connection failed."
                    disconnect(reason: "Connection ended")
                    return
                case "closed":
                    disconnect(reason: "Session ended")
                    return
                default:
                    break
                }
            } catch {
                errorMessage = "Unable to read the session state: \(error.localizedDescription)"
                disconnect(reason: "Connection ended")
                return
            }
        }
    }
}
