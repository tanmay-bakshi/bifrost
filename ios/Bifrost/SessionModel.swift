import Combine
import Foundation
import UIKit

struct SessionOffer {
    let consumerName: String
    let description: String
    let mode: String
}

@MainActor
final class SessionModel: ObservableObject {
    enum ConnectionMode: String, CaseIterable, Identifiable {
        case connect = "Connect"
        case listen = "Listen"
        var id: Self { self }
    }

    @Published var connectionMode = ConnectionMode.connect
    @Published var peerURL = ""
    @Published var listenAddress = "0.0.0.0:7071"
    @Published var joinToken = UUID().uuidString

    var canStart: Bool {
        switch connectionMode {
        case .connect: !peerURL.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        case .listen: !listenAddress.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && !joinToken.isEmpty
        }
    }
    @Published var reconnect = false
    @Published var keepAwake = true {
        didSet { updateIdleTimer() }
    }
    @Published private(set) var listenerURL: String?
    @Published private(set) var phase = "Ready"
    @Published private(set) var offer: SessionOffer?
    @Published private(set) var errorMessage: String?
    @Published private(set) var isRunning = false
    @Published private(set) var needsApproval = false

    private var peer: OpaquePointer?
    private var polling: Task<Void, Never>?

    private struct Configuration: Encodable {
        let endpoint: EndpointConfiguration
        let device_name: String
        let reconnect: Bool
    }

    private struct EndpointConfiguration: Encodable {
        let kind: String
        let url: String?
        let address: String?
        let join_token: String?
    }

    private struct Event: Decodable {
        let kind: String
        let phase: String?
        let join_url: String?
        let consumer: String?
        let description: String?
        let mode: String?
        let message: String?
    }

    func connect() {
        guard peer == nil else { return }
        errorMessage = nil
        listenerURL = nil
        offer = nil
        needsApproval = false
        do {
            let configuration = Configuration(
                endpoint: connectionMode == .connect
                    ? EndpointConfiguration(kind: "connect", url: peerURL.trimmingCharacters(in: .whitespacesAndNewlines), address: nil, join_token: nil)
                    : EndpointConfiguration(kind: "listen", url: nil, address: listenAddress.trimmingCharacters(in: .whitespacesAndNewlines), join_token: joinToken),
                device_name: UIDevice.current.name,
                reconnect: reconnect
            )
            let data = try JSONEncoder().encode(configuration)
            let json = String(decoding: data, as: UTF8.self)
            peer = json.withCString { bifrost_peer_create($0) }
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
        guard let peer, needsApproval else { return }
        needsApproval = false
        phase = allowed ? "Starting session" : "Declining session"
        bifrost_peer_approve(peer, allowed)
    }

    func disconnect(reason: String = "Disconnected") {
        polling?.cancel()
        polling = nil
        if let peer { bifrost_peer_free(peer) }
        peer = nil
        isRunning = false
        listenerURL = nil
        offer = nil
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
        guard let peer else { return }
        // Bound work on the UI thread. The Rust task remains the owner of networking.
        for _ in 0..<16 {
            guard let pointer = bifrost_peer_poll(peer) else { return }
            let data = Data(bytes: pointer, count: strlen(pointer))
            bifrost_string_free(pointer)
            do {
                let event = try JSONDecoder().decode(Event.self, from: data)
                if let joinURL = event.join_url { listenerURL = joinURL }
                switch event.kind {
                case "status":
                    switch event.phase {
                    case "connecting": phase = connectionMode == .listen ? "Waiting for a peer" : "Connecting"
                    case "connected": phase = "Connected"
                    case "reconnecting": phase = "Reconnecting"
                    default: break
                    }
                case "offer":
                    guard let name = event.consumer, let description = event.description, let mode = event.mode else {
                        throw DecodingError.dataCorrupted(.init(codingPath: [], debugDescription: "Incomplete session offer"))
                    }
                    offer = SessionOffer(consumerName: name, description: description, mode: mode)
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
