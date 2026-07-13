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

import Foundation
import SwiftUI
import LocalAuthentication

@MainActor
class VaultViewModel: ObservableObject {
    @Published var state: VaultState = .locked
    @Published var items: [VaultItem] = []
    @Published var messages: [EncryptedMessage] = []
    @Published var operationState: OperationState = .idle
    @Published var settings: VaultSettings = VaultSettings()
    @Published var searchText: String = ""
    @Published var selectedCategory: VaultItem.ItemCategory? = nil
    @Published var showingError: Bool = false
    @Published var errorMessage: String = ""

    private var masterPassword: String?
    private let persistence = VaultPersistence()

    // MARK: - Vault Lock/Unlock

    func unlock(password: String) {
        state = .unlocking
        masterPassword = password

        Task {
            do {
                let metadata = try await persistence.load(password: password)
                items = metadata.items
                messages = metadata.messages
                settings = metadata.settings

                // Store in Keychain for biometric unlock if enabled
                if settings.biometricEnabled {
                    try? KeychainService.storePassword(password)
                }

                state = .unlocked
            } catch {
                state = .error("Wrong password or corrupted vault")
                errorMessage = "Wrong password or corrupted vault"
                showingError = true
            }
        }
    }

    func lock() {
        // Save before locking
        if let pw = masterPassword {
            Task {
                let metadata = VaultMetadata(items: items, messages: messages, settings: settings)
                try? await persistence.save(metadata: metadata, password: pw)
            }
        }
        masterPassword = nil
        items = []
        messages = []
        state = .locked
    }

    func authenticateWithBiometrics() {
        guard KeychainService.biometricsAvailable(),
              KeychainService.hasStoredPassword() else { return }

        Task {
            do {
                let password = try KeychainService.retrievePassword()
                await MainActor.run { unlock(password: password) }
            } catch {
                // Biometric failed — user will type password
            }
        }
    }

    /// Save vault state to disk (call after any mutation)
    private func saveVault() {
        guard let pw = masterPassword else { return }
        Task {
            let metadata = VaultMetadata(items: items, messages: messages, settings: settings)
            try? await persistence.save(metadata: metadata, password: pw)
        }
    }

    // MARK: - File Operations

    func encryptFile(
        at url: URL, trapCodes: [String] = [],
        duressPassword: String? = nil, duressData: Data? = nil
    ) {
        guard let password = masterPassword else { return }

        operationState = .derivingKeys

        Task.detached(priority: .userInitiated) { [settings] in
            do {
                let outputURL = self.vaultDirectory.appendingPathComponent(
                    UUID().uuidString + ".fortress"
                )

                let result = try FortressAPI.encryptFile(
                    inputURL: url, outputURL: outputURL, password: password,
                    level: settings.defaultSecurityLevel,
                    trapCodes: trapCodes.isEmpty ? nil : trapCodes,
                    duressPassword: duressPassword, duressData: duressData,
                    progress: { progress, status in
                        Task { @MainActor in
                            self.operationState = .encrypting(progress: progress, status: status)
                        }
                    }
                )

                let item = VaultItem(
                    id: UUID(),
                    name: url.deletingPathExtension().lastPathComponent,
                    originalFileName: url.lastPathComponent,
                    encryptedFileName: outputURL.lastPathComponent,
                    fileSize: result["inputSize"] as? UInt64 ?? 0,
                    dateAdded: Date(), dateModified: Date(),
                    category: Self.categorize(url),
                    isFavorite: false, tags: []
                )

                await MainActor.run {
                    self.items.append(item)
                    self.operationState = .complete(success: true, message: "Encrypted successfully")
                    self.saveVault()
                }
            } catch {
                await MainActor.run {
                    self.operationState = .complete(success: false, message: error.localizedDescription)
                    self.errorMessage = error.localizedDescription
                    self.showingError = true
                }
            }
        }
    }

    func decryptFile(_ item: VaultItem, to outputURL: URL, trapCodes: [String] = []) {
        guard let password = masterPassword else { return }

        operationState = .derivingKeys

        Task.detached(priority: .userInitiated) {
            do {
                let inputURL = self.vaultDirectory.appendingPathComponent(item.encryptedFileName)

                let _ = try FortressAPI.decryptFile(
                    inputURL: inputURL, outputURL: outputURL, password: password,
                    trapCodes: trapCodes.isEmpty ? nil : trapCodes,
                    progress: { progress, status in
                        Task { @MainActor in
                            self.operationState = .decrypting(progress: progress, status: status)
                        }
                    }
                )

                await MainActor.run {
                    self.operationState = .complete(success: true, message: "Decrypted to \(outputURL.lastPathComponent)")
                }
            } catch let error as FortressError {
                await MainActor.run {
                    self.operationState = .complete(success: false, message: error.localizedDescription)
                    self.errorMessage = error.localizedDescription
                    self.showingError = true
                }
            } catch {
                await MainActor.run {
                    self.operationState = .complete(success: false, message: error.localizedDescription)
                }
            }
        }
    }

    func deleteItem(_ item: VaultItem) {
        let url = vaultDirectory.appendingPathComponent(item.encryptedFileName)
        try? FileManager.default.removeItem(at: url)
        items.removeAll { $0.id == item.id }
        saveVault()
    }

    // MARK: - Filtered Items

    var filteredItems: [VaultItem] {
        var result = items
        if let cat = selectedCategory {
            result = result.filter { $0.category == cat }
        }
        if !searchText.isEmpty {
            result = result.filter {
                $0.name.localizedCaseInsensitiveContains(searchText) ||
                $0.originalFileName.localizedCaseInsensitiveContains(searchText) ||
                $0.tags.contains { $0.localizedCaseInsensitiveContains(searchText) }
            }
        }
        return result.sorted { $0.dateModified > $1.dateModified }
    }

    // MARK: - Helpers

    var vaultDirectory: URL {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        let vault = docs.appendingPathComponent("FortressVault", isDirectory: true)
        try? FileManager.default.createDirectory(at: vault, withIntermediateDirectories: true)
        return vault
    }

    private static func categorize(_ url: URL) -> VaultItem.ItemCategory {
        switch url.pathExtension.lowercased() {
        case "pdf", "doc", "docx", "txt", "rtf", "md", "pages":
            return .document
        case "jpg", "jpeg", "png", "heic", "gif", "bmp", "tiff", "svg":
            return .image
        case "mp4", "mov", "avi", "mkv", "m4v":
            return .video
        case "mp3", "aac", "wav", "flac", "m4a":
            return .audio
        case "zip", "tar", "gz", "7z", "rar":
            return .archive
        default:
            return .other
        }
    }
}
