//
//  Fortress Crypt — 6-layer cascade encryption system
//  Copyright (C) 2025 Steve Watts, The Lion's Kingdom IT Solutions, LLC
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU Affero General Public License as published
//  by the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU Affero General Public License for more details.
//
//  You should have received a copy of the GNU Affero General Public License
//  along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
//  For commercial licensing without the AGPL's copyleft obligations,
//  contact the Maintainer (see README).
//

import SwiftUI
import UniformTypeIdentifiers

// MARK: - App Entry Point

@main
struct FortressCryptApp: App {
    @StateObject private var viewModel = VaultViewModel()

    var body: some Scene {
        WindowGroup {
            Group {
                switch viewModel.state {
                case .locked:
                    LockScreenView(viewModel: viewModel)
                case .unlocking:
                    ProgressView("Unlocking vault...")
                        .tint(.cyan)
                case .unlocked:
                    VaultMainView(viewModel: viewModel)
                case .error(let msg):
                    LockScreenView(viewModel: viewModel)
                        .alert("Error", isPresented: .constant(true)) {
                            Button("OK") { viewModel.state = .locked }
                        } message: {
                            Text(msg)
                        }
                }
            }
            .preferredColorScheme(.dark)
        }
    }
}

// MARK: - Lock Screen

struct LockScreenView: View {
    @ObservedObject var viewModel: VaultViewModel
    @State private var password = ""
    @State private var isAuthenticating = false

    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()

            VStack(spacing: 32) {
                Spacer()

                // Shield icon
                Image(systemName: "lock.shield.fill")
                    .font(.system(size: 64))
                    .foregroundStyle(
                        LinearGradient(
                            colors: [Color.cyan, Color.cyan.opacity(0.6)],
                            startPoint: .top, endPoint: .bottom
                        )
                    )

                VStack(spacing: 4) {
                    Text("FORTRESS")
                        .font(.system(size: 28, weight: .bold, design: .monospaced))
                        .foregroundColor(.white)
                        .tracking(6)

                    Text("CRYPT")
                        .font(.system(size: 12, weight: .light))
                        .foregroundColor(.gray)
                        .tracking(8)
                }

                VStack(spacing: 16) {
                    SecureField("Master Password", text: $password)
                        .textFieldStyle(.plain)
                        .padding()
                        .background(Color.white.opacity(0.08))
                        .cornerRadius(12)
                        .overlay(
                            RoundedRectangle(cornerRadius: 12)
                                .stroke(Color.cyan.opacity(0.3), lineWidth: 1)
                        )
                        .foregroundColor(.white)
                        .onSubmit { unlock() }

                    Button(action: unlock) {
                        HStack {
                            Image(systemName: "lock.open.fill")
                            Text("Unlock Vault")
                                .fontWeight(.semibold)
                        }
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(Color.cyan)
                        .foregroundColor(.black)
                        .cornerRadius(12)
                    }
                    .disabled(password.isEmpty)

                    if viewModel.settings.biometricEnabled {
                        Button(action: { viewModel.authenticateWithBiometrics() }) {
                            Image(systemName: "faceid")
                                .font(.system(size: 32))
                                .foregroundColor(.cyan.opacity(0.7))
                        }
                    }
                }
                .padding(.horizontal, 40)

                Spacer()

                Text("6-Layer Cascade Encryption")
                    .font(.caption2)
                    .foregroundColor(.gray.opacity(0.5))
                    .padding(.bottom, 20)
            }
        }
    }

    private func unlock() {
        guard !password.isEmpty else { return }
        viewModel.unlock(password: password)
        password = ""
    }
}

// MARK: - Main Vault View

struct VaultMainView: View {
    @ObservedObject var viewModel: VaultViewModel
    @State private var showingImporter = false
    @State private var showingEncryptSheet = false
    @State private var showingMessageComposer = false
    @State private var selectedTab = 0

    var body: some View {
        TabView(selection: $selectedTab) {
            // Files Tab
            NavigationStack {
                VaultFilesView(viewModel: viewModel)
                    .navigationTitle("Vault")
                    .toolbar {
                        ToolbarItem(placement: .primaryAction) {
                            Menu {
                                Button(action: { showingImporter = true }) {
                                    Label("Import & Encrypt File", systemImage: "plus.circle")
                                }
                                Button(action: { viewModel.lock() }) {
                                    Label("Lock Vault", systemImage: "lock.fill")
                                }
                            } label: {
                                Image(systemName: "plus")
                            }
                        }
                    }
            }
            .tabItem {
                Label("Vault", systemImage: "lock.shield.fill")
            }
            .tag(0)

            // Messages Tab
            NavigationStack {
                MessagesView(viewModel: viewModel)
                    .navigationTitle("Messages")
                    .toolbar {
                        ToolbarItem(placement: .primaryAction) {
                            Button(action: { showingMessageComposer = true }) {
                                Image(systemName: "square.and.pencil")
                            }
                        }
                    }
            }
            .tabItem {
                Label("Messages", systemImage: "envelope.fill")
            }
            .tag(1)

            // Settings Tab
            NavigationStack {
                SettingsView(viewModel: viewModel)
                    .navigationTitle("Settings")
            }
            .tabItem {
                Label("Settings", systemImage: "gearshape.fill")
            }
            .tag(2)
        }
        .tint(.cyan)
        .fileImporter(
            isPresented: $showingImporter,
            allowedContentTypes: [.item],
            allowsMultipleSelection: false
        ) { result in
            if case .success(let urls) = result, let url = urls.first {
                if url.startAccessingSecurityScopedResource() {
                    defer { url.stopAccessingSecurityScopedResource() }
                    showingEncryptSheet = true
                    // Copy file to temp, then encrypt
                    viewModel.encryptFile(at: url)
                }
            }
        }
        .sheet(isPresented: $showingMessageComposer) {
            MessageComposerView(viewModel: viewModel)
        }
        .overlay {
            if case .encrypting(let progress, let status) = viewModel.operationState {
                OperationOverlay(progress: progress, status: status, icon: "lock.fill")
            } else if case .decrypting(let progress, let status) = viewModel.operationState {
                OperationOverlay(progress: progress, status: status, icon: "lock.open.fill")
            } else if case .derivingKeys = viewModel.operationState {
                OperationOverlay(progress: nil, status: "Deriving keys...", icon: "key.fill")
            }
        }
        .alert("Error", isPresented: $viewModel.showingError) {
            Button("OK") {}
        } message: {
            Text(viewModel.errorMessage)
        }
    }
}

// MARK: - Vault Files List

struct VaultFilesView: View {
    @ObservedObject var viewModel: VaultViewModel

    var body: some View {
        List {
            if viewModel.filteredItems.isEmpty {
                ContentUnavailableView {
                    Label("No Files", systemImage: "lock.shield")
                } description: {
                    Text("Tap + to import and encrypt files")
                }
            } else {
                ForEach(viewModel.filteredItems) { item in
                    VaultItemRow(item: item)
                        .swipeActions(edge: .trailing) {
                            Button(role: .destructive) {
                                viewModel.deleteItem(item)
                            } label: {
                                Label("Delete", systemImage: "trash")
                            }
                        }
                        .swipeActions(edge: .leading) {
                            Button {
                                // Export/decrypt action
                            } label: {
                                Label("Decrypt", systemImage: "lock.open")
                            }
                            .tint(.cyan)
                        }
                }
            }
        }
        .searchable(text: $viewModel.searchText, prompt: "Search vault")
    }
}

struct VaultItemRow: View {
    let item: VaultItem

    var body: some View {
        HStack(spacing: 14) {
            Image(systemName: item.category.icon)
                .font(.title3)
                .foregroundColor(item.category.color)
                .frame(width: 36, height: 36)
                .background(item.category.color.opacity(0.15))
                .cornerRadius(8)

            VStack(alignment: .leading, spacing: 3) {
                Text(item.name)
                    .font(.body.weight(.medium))
                    .lineLimit(1)

                HStack(spacing: 8) {
                    Text(item.fileSize.formattedFileSize)
                    Text("·")
                    Text(item.dateAdded, style: .date)
                }
                .font(.caption)
                .foregroundColor(.secondary)
            }

            Spacer()

            if item.isFavorite {
                Image(systemName: "star.fill")
                    .foregroundColor(.yellow)
                    .font(.caption)
            }

            Image(systemName: "lock.fill")
                .foregroundColor(.cyan.opacity(0.5))
                .font(.caption)
        }
        .padding(.vertical, 4)
    }
}

// MARK: - Messages View

struct MessagesView: View {
    @ObservedObject var viewModel: VaultViewModel

    var body: some View {
        List {
            if viewModel.messages.isEmpty {
                ContentUnavailableView {
                    Label("No Messages", systemImage: "envelope")
                } description: {
                    Text("Compose encrypted messages to share securely")
                }
            } else {
                ForEach(viewModel.messages) { msg in
                    HStack {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(msg.recipientName)
                                .fontWeight(.medium)
                            Text(msg.dateCreated, style: .relative)
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                        Spacer()
                        if msg.hasTraps {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .foregroundColor(.orange)
                                .font(.caption)
                        }
                        Image(systemName: "lock.fill")
                            .foregroundColor(.cyan.opacity(0.5))
                            .font(.caption)
                    }
                }
            }
        }
    }
}

// MARK: - Message Composer

struct MessageComposerView: View {
    @ObservedObject var viewModel: VaultViewModel
    @Environment(\.dismiss) private var dismiss
    @State private var messageText = ""
    @State private var recipientName = ""
    @State private var messagePassword = ""
    @State private var trapCount = 0
    @State private var trapCodes: [String] = []
    @State private var isEncrypting = false

    var body: some View {
        NavigationStack {
            Form {
                Section("Recipient") {
                    TextField("Name", text: $recipientName)
                }
                Section("Message") {
                    TextEditor(text: $messageText)
                        .frame(minHeight: 120)
                }
                Section("Message Password") {
                    SecureField("Encryption password", text: $messagePassword)
                }
                Section("Trap Codes") {
                    Stepper("Trap codes: \(trapCount)", value: $trapCount, in: 0...5)
                    ForEach(0..<trapCount, id: \.self) { i in
                        SecureField("Code #\(i+1)", text: binding(for: i))
                    }
                }
            }
            .navigationTitle("Compose")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Encrypt & Save") {
                        encryptAndSave()
                    }
                    .disabled(messageText.isEmpty || recipientName.isEmpty)
                }
            }
        }
    }

    private func binding(for index: Int) -> Binding<String> {
        while trapCodes.count <= index { trapCodes.append("") }
        return $trapCodes[index]
    }

    private func encryptAndSave() {
        guard !messageText.isEmpty, !messagePassword.isEmpty else { return }
        isEncrypting = true

        Task.detached(priority: .userInitiated) {
            do {
                let codes = trapCodes.prefix(trapCount).filter { !$0.isEmpty }
                let token = try FortressAPI.encryptMessage(
                    message: messageText, password: messagePassword,
                    trapCodes: codes.isEmpty ? nil : Array(codes)
                )

                let msg = EncryptedMessage(
                    id: UUID(),
                    recipientName: recipientName,
                    dateCreated: Date(),
                    token: token,
                    hasTraps: !codes.isEmpty,
                    hasDuress: false
                )

                await MainActor.run {
                    viewModel.messages.append(msg)
                    isEncrypting = false
                    dismiss()
                }
            } catch {
                await MainActor.run {
                    isEncrypting = false
                    // Show error
                }
            }
        }
    }
}

// MARK: - Settings View

struct SettingsView: View {
    @ObservedObject var viewModel: VaultViewModel

    var body: some View {
        Form {
            Section("Security") {
                Picker("Default Level", selection: $viewModel.settings.defaultSecurityLevel) {
                    ForEach(SecurityLevel.allCases) { level in
                        Text(level.displayName).tag(level)
                    }
                }
                Toggle("Biometric Unlock", isOn: $viewModel.settings.biometricEnabled)
                Picker("Auto-Lock", selection: $viewModel.settings.autoLockSeconds) {
                    Text("1 minute").tag(60)
                    Text("5 minutes").tag(300)
                    Text("15 minutes").tag(900)
                    Text("Never").tag(0)
                }
            }

            Section("Defaults") {
                Stepper("Default trap codes: \(viewModel.settings.defaultTrapCount)",
                        value: $viewModel.settings.defaultTrapCount, in: 0...5)
                Toggle("Enable duress mode by default", isOn: $viewModel.settings.enableDuress)
            }

            Section("About") {
                HStack {
                    Text("Version")
                    Spacer()
                    Text("2.0.0").foregroundColor(.secondary)
                }
                HStack {
                    Text("Cipher Layers")
                    Spacer()
                    Text("6 (double cascade)").foregroundColor(.secondary)
                }
                HStack {
                    Text("KDF Chain")
                    Spacer()
                    Text("Argon2id -> scrypt -> HKDF").foregroundColor(.secondary)
                }
            }

            Section {
                Button("Lock Vault", role: .destructive) {
                    viewModel.lock()
                }
            }
        }
    }
}

// MARK: - Operation Overlay

struct OperationOverlay: View {
    let progress: Double?
    let status: String
    let icon: String

    var body: some View {
        ZStack {
            Color.black.opacity(0.7)
                .ignoresSafeArea()

            VStack(spacing: 20) {
                Image(systemName: icon)
                    .font(.system(size: 40))
                    .foregroundColor(.cyan)
                    .symbolEffect(.pulse)

                if let progress {
                    ProgressView(value: progress)
                        .tint(.cyan)
                        .frame(width: 200)

                    Text("\(Int(progress * 100))%")
                        .font(.system(.title2, design: .monospaced))
                        .foregroundColor(.white)
                } else {
                    ProgressView()
                        .tint(.cyan)
                }

                Text(status)
                    .font(.callout)
                    .foregroundColor(.gray)
            }
            .padding(40)
            .background(.ultraThinMaterial)
            .cornerRadius(20)
        }
    }
}
