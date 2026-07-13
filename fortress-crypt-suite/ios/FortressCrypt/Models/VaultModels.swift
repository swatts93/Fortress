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

// MARK: - Vault Item

struct VaultItem: Identifiable, Codable {
    let id: UUID
    var name: String
    var originalFileName: String
    var encryptedFileName: String
    var fileSize: UInt64
    var dateAdded: Date
    var dateModified: Date
    var category: ItemCategory
    var isFavorite: Bool
    var tags: [String]

    enum ItemCategory: String, Codable, CaseIterable, Identifiable {
        case document = "document"
        case image = "image"
        case video = "video"
        case audio = "audio"
        case archive = "archive"
        case message = "message"
        case other = "other"

        var id: String { rawValue }

        var icon: String {
            switch self {
            case .document: return "doc.fill"
            case .image:    return "photo.fill"
            case .video:    return "film.fill"
            case .audio:    return "waveform"
            case .archive:  return "archivebox.fill"
            case .message:  return "envelope.fill"
            case .other:    return "doc.questionmark.fill"
            }
        }

        var color: Color {
            switch self {
            case .document: return .blue
            case .image:    return .green
            case .video:    return .purple
            case .audio:    return .orange
            case .archive:  return .gray
            case .message:  return .cyan
            case .other:    return .secondary
            }
        }
    }
}

// MARK: - Encrypted Message

struct EncryptedMessage: Identifiable, Codable {
    let id: UUID
    var recipientName: String
    var dateCreated: Date
    var token: String        // FORTRESS:... base64 token
    var hasTraps: Bool
    var hasDuress: Bool
}

// MARK: - Vault Metadata (encrypted at rest)

struct VaultMetadata: Codable {
    var items: [VaultItem]
    var messages: [EncryptedMessage]
    var settings: VaultSettings
}

struct VaultSettings: Codable {
    var defaultSecurityLevel: SecurityLevel = .paranoid
    var defaultTrapCount: Int = 0
    var enableDuress: Bool = false
    var biometricEnabled: Bool = false
    var autoLockSeconds: Int = 300 // 5 minutes
}

// MARK: - App State

enum VaultState {
    case locked
    case unlocking
    case unlocked
    case error(String)
}

enum OperationState: Equatable {
    case idle
    case encrypting(progress: Double, status: String)
    case decrypting(progress: Double, status: String)
    case derivingKeys
    case complete(success: Bool, message: String)
}

// MARK: - Size Formatting

extension UInt64 {
    var formattedFileSize: String {
        let units = ["B", "KB", "MB", "GB", "TB"]
        var size = Double(self)
        for unit in units {
            if size < 1024 { return String(format: "%.1f %@", size, unit) }
            size /= 1024
        }
        return String(format: "%.1f PB", size)
    }
}
