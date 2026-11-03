import SwiftUI

struct ContentView: View {
    @ObservedObject var session: SessionModel
    private let accent = Color(red: 0.33, green: 0.88, blue: 0.77)

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 28) {
                HStack(spacing: 14) {
                    Image(systemName: "point.3.connected.trianglepath.dotted")
                        .font(.system(size: 34, weight: .medium))
                        .foregroundStyle(accent)
                    VStack(alignment: .leading, spacing: 3) {
                        Text("SSHPortal").font(.largeTitle.bold())
                        Text("SHARE YOUR NETWORK").font(.caption.weight(.semibold)).tracking(2).foregroundStyle(.secondary)
                    }
                }
                .padding(.top, 20)

                Text("Give a trusted operator temporary network access through this device. You choose whether to allow each session.")
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                VStack(alignment: .leading, spacing: 18) {
                    Label("\(session.phase)", systemImage: session.phase == "Connected" ? "checkmark.circle.fill" : "circle.dotted")
                        .font(.headline)
                        .foregroundStyle(session.phase == "Connected" ? accent : .primary)
                        .accessibilityIdentifier("sessionStatus")
                    if !session.isRunning {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("Join URL").font(.subheadline.weight(.semibold))
                            TextField("https://portal.example?token=…", text: $session.serverURL)
                                .textContentType(.URL)
                                .keyboardType(.URL)
                                .textInputAutocapitalization(.never)
                                .autocorrectionDisabled()
                                .padding(12)
                                .background(.black.opacity(0.25), in: RoundedRectangle(cornerRadius: 10))
                                .accessibilityIdentifier("serverURL")
                            PasteButton(payloadType: String.self) { strings in
                                if let first = strings.first { session.serverURL = first }
                            }
                            .tint(accent)
                        }
                        Toggle("Reconnect after network interruptions", isOn: $session.reconnect)
                            .font(.subheadline)
                            .tint(accent)
                    }
                    Toggle("Keep screen awake during session", isOn: $session.keepAwake)
                        .font(.subheadline)
                        .tint(accent)
                    if !session.isRunning {
                        Button(action: session.connect) {
                            Text("Connect").fontWeight(.semibold).frame(maxWidth: .infinity).padding(.vertical, 7)
                        }
                        .buttonStyle(.borderedProminent)
                        .tint(accent)
                        .foregroundStyle(.black)
                        .disabled(session.serverURL.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                        .accessibilityIdentifier("connect")
                    }
                }
                .padding(20)
                .background(.white.opacity(0.055), in: RoundedRectangle(cornerRadius: 20))

                if let offer = session.offer {
                    VStack(alignment: .leading, spacing: 14) {
                        Text(offer.mode.uppercased()).font(.caption.weight(.semibold)).tracking(1.5).foregroundStyle(accent)
                        Text(offer.operatorName).font(.title2.bold())
                        Text(offer.description).font(.subheadline).fixedSize(horizontal: false, vertical: true)
                        Text("The operator’s connections use your device’s network access and may consume mobile data.")
                            .font(.footnote).foregroundStyle(.secondary)
                        if session.needsApproval {
                            HStack {
                                Button("Decline") { session.approve(false) }
                                    .buttonStyle(.bordered)
                                    .accessibilityIdentifier("decline")
                                Button("Allow access") { session.approve(true) }
                                    .buttonStyle(.borderedProminent).tint(accent).foregroundStyle(.black)
                                    .accessibilityIdentifier("approve")
                            }
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(20)
                    .background(accent.opacity(0.08), in: RoundedRectangle(cornerRadius: 20))
                }

                if let message = session.errorMessage {
                    Label(message, systemImage: "exclamationmark.triangle")
                        .font(.subheadline).foregroundStyle(.orange)
                        .textSelection(.enabled)
                        .accessibilityIdentifier("connectionError")
                }
                if session.isRunning {
                    Button(role: .destructive) { session.disconnect() } label: {
                        Text("Disconnect").frame(maxWidth: .infinity).padding(.vertical, 7)
                    }
                    .buttonStyle(.bordered)
                    .accessibilityIdentifier("disconnect")
                }
                Label {
                    Text("Keep this app open. Switching apps or locking the device ends the session. Returning here never reconnects automatically.")
                        .fixedSize(horizontal: false, vertical: true)
                } icon: {
                    Image(systemName: "iphone.gen3")
                }
                .font(.footnote).foregroundStyle(.secondary)
            }
            .padding(24)
            .frame(maxWidth: 600)
            .frame(maxWidth: .infinity)
        }
        .background(Color(red: 0.045, green: 0.07, blue: 0.10).ignoresSafeArea())
    }
}
