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
import CryptoKit

/// Manages encrypted vault metadata on disk.
/// The vault index (list of items, settings) is itself encrypted
/// with a key derived from the master password.
actor VaultPersistence {

    private let fileManager = FileManager.default

    var vaultDirectory: URL {
        let docs = fileManager.urls(for: .documentDirectory, in: .userDomainMask).first!
        let vault = docs.appendingPathComponent("FortressVault", isDirectory: true)
        try? fileManager.createDirectory(at: vault, withIntermediateDirectories: true)
        return vault
    }

    private var metadataURL: URL {
        vaultDirectory.appendingPathComponent(".vault_metadata.enc")
    }

    // MARK: - Save / Load Metadata

    /// Encrypt and save vault metadata using the master password
    func save(metadata: VaultMetadata, password: String) throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let plaintext = try encoder.encode(metadata)

        // Derive a quick key for metadata encryption (not full Fortress — just AES-GCM)
        let salt = Data("fortress-metadata-salt-v1".utf8)
        let key = SymmetricKey(data: HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: Data(password.utf8)),
            salt: salt,
            info: Data("fortress-metadata-key".utf8),
            outputByteCount: 32
        ))

        let sealed = try AES.GCM.seal(plaintext, using: key)
        let combined = sealed.combined!
        try combined.write(to: metadataURL)
    }

    /// Decrypt and load vault metadata
    func load(password: String) throws -> VaultMetadata {
        guard fileManager.fileExists(atPath: metadataURL.path) else {
            // First launch — return empty vault
            return VaultMetadata(
                items: [],
                messages: [],
                settings: VaultSettings()
            )
        }

        let encrypted = try Data(contentsOf: metadataURL)

        let salt = Data("fortress-metadata-salt-v1".utf8)
        let key = SymmetricKey(data: HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: Data(password.utf8)),
            salt: salt,
            info: Data("fortress-metadata-key".utf8),
            outputByteCount: 32
        ))

        let sealedBox = try AES.GCM.SealedBox(combined: encrypted)
        let plaintext = try AES.GCM.open(sealedBox, using: key)

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(VaultMetadata.self, from: plaintext)
    }

    /// Check if a vault exists (for first-run detection)
    func vaultExists() -> Bool {
        fileManager.fileExists(atPath: metadataURL.path)
    }
}
