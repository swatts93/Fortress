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

// MARK: - Fortress Encryption Engine
// 6-layer double cascade: [Camellia → ChaCha → AES] × 2

enum FortressEngine {

    static let defaultChunkSize = 1_048_576 // 1 MB
    static let gcmTagSize = 16
    static let poly1305TagSize = 16
    static let hmac512TagSize = 64

    // MARK: - Full Chunk Encryption (Double Cascade)

    /// Encrypt one chunk through 6 layers with anti-forensic padding
    static func encryptChunk(
        plaintext: Data, keys: FortressKeys, chunkIndex: UInt64
    ) throws -> Data {
        // Add anti-forensic random padding
        let padLen = try FortressKeyDerivation.derivePaddingLength(
            paddingKey: keys.paddingKey, chunkIndex: chunkIndex
        )
        var paddingHeader = Data()
        paddingHeader.append(contentsOf: withUnsafeBytes(of: UInt16(padLen).littleEndian) { Data($0) })

        var randomPadding = Data(count: padLen)
        randomPadding.withUnsafeMutableBytes { ptr in
            _ = SecRandomCopyBytes(kSecRandomDefault, padLen, ptr.baseAddress!)
        }

        var paddedPlaintext = paddingHeader + randomPadding + plaintext

        // Pass 1: Camellia → ChaCha → AES (key set 1)
        let afterPass1 = try cascadeEncrypt(
            data: paddedPlaintext,
            aesKey: keys.p1AESKey, chachaKey: keys.p1ChaChaKey,
            camelliaKey: keys.p1CamelliaKey, hmacKey: keys.p1HMACKey,
            nonceSeed: keys.nonceSeed, chunkIndex: chunkIndex, passNum: 1
        )

        // Pass 2: Camellia → ChaCha → AES (key set 2)
        let afterPass2 = try cascadeEncrypt(
            data: afterPass1,
            aesKey: keys.p2AESKey, chachaKey: keys.p2ChaChaKey,
            camelliaKey: keys.p2CamelliaKey, hmacKey: keys.p2HMACKey,
            nonceSeed: keys.nonceSeed, chunkIndex: chunkIndex, passNum: 2
        )

        return afterPass2
    }

    /// Decrypt one chunk through 6 layers (reverse order)
    static func decryptChunk(
        encrypted: Data, keys: FortressKeys, chunkIndex: UInt64
    ) throws -> Data {
        // Reverse Pass 2
        let afterPass1 = try cascadeDecrypt(
            data: encrypted,
            aesKey: keys.p2AESKey, chachaKey: keys.p2ChaChaKey,
            camelliaKey: keys.p2CamelliaKey, hmacKey: keys.p2HMACKey,
            nonceSeed: keys.nonceSeed, chunkIndex: chunkIndex, passNum: 2
        )

        // Reverse Pass 1
        let paddedPlaintext = try cascadeDecrypt(
            data: afterPass1,
            aesKey: keys.p1AESKey, chachaKey: keys.p1ChaChaKey,
            camelliaKey: keys.p1CamelliaKey, hmacKey: keys.p1HMACKey,
            nonceSeed: keys.nonceSeed, chunkIndex: chunkIndex, passNum: 1
        )

        // Strip anti-forensic padding
        guard paddedPlaintext.count >= 2 else {
            throw FortressError.decryptionFailed("Chunk too short after decryption")
        }

        let padLen = Int(paddedPlaintext.prefix(2).withUnsafeBytes {
            $0.load(as: UInt16.self).littleEndian
        })

        guard paddedPlaintext.count >= 2 + padLen else {
            throw FortressError.decryptionFailed("Invalid padding length")
        }

        return paddedPlaintext.suffix(from: 2 + padLen)
    }

    // MARK: - Single Cascade Pass

    /// One full cascade: Camellia-256-CBC+HMAC → ChaCha20-Poly1305 → AES-256-GCM
    private static func cascadeEncrypt(
        data: Data,
        aesKey: SymmetricKey, chachaKey: SymmetricKey,
        camelliaKey: Data, hmacKey: SymmetricKey,
        nonceSeed: Data, chunkIndex: UInt64, passNum: UInt32
    ) throws -> Data {
        let nonces = try FortressKeyDerivation.deriveChunkNonces(
            nonceSeed: nonceSeed, chunkIndex: chunkIndex, cascadePass: passNum
        )

        // Layer 1: Camellia-256-CBC + HMAC-SHA512 (Encrypt-then-MAC)
        let layer1 = try camelliaEncrypt(
            plaintext: data, key: camelliaKey, iv: nonces.camelliaIV,
            hmacKey: hmacKey, chunkIndex: chunkIndex, passNum: passNum
        )

        // Layer 2: ChaCha20-Poly1305
        let layer2 = try chachaEncrypt(plaintext: layer1, key: chachaKey, nonce: nonces.chachaNonce)

        // Layer 3: AES-256-GCM
        let layer3 = try aesEncrypt(plaintext: layer2, key: aesKey, nonce: nonces.aesNonce)

        return layer3
    }

    private static func cascadeDecrypt(
        data: Data,
        aesKey: SymmetricKey, chachaKey: SymmetricKey,
        camelliaKey: Data, hmacKey: SymmetricKey,
        nonceSeed: Data, chunkIndex: UInt64, passNum: UInt32
    ) throws -> Data {
        let nonces = try FortressKeyDerivation.deriveChunkNonces(
            nonceSeed: nonceSeed, chunkIndex: chunkIndex, cascadePass: passNum
        )

        // Reverse Layer 3: AES-256-GCM
        let layer2 = try aesDecrypt(
            ciphertext: data, key: aesKey, nonce: nonces.aesNonce,
            chunkIndex: chunkIndex, passNum: passNum
        )

        // Reverse Layer 2: ChaCha20-Poly1305
        let layer1 = try chachaDecrypt(
            ciphertext: layer2, key: chachaKey, nonce: nonces.chachaNonce,
            chunkIndex: chunkIndex, passNum: passNum
        )

        // Reverse Layer 1: Camellia-256-CBC + HMAC-SHA512
        let plaintext = try camelliaDecrypt(
            data: layer1, key: camelliaKey, iv: nonces.camelliaIV,
            hmacKey: hmacKey, chunkIndex: chunkIndex, passNum: passNum
        )

        return plaintext
    }

    // MARK: - AES-256-GCM (CryptoKit — native)

    private static func aesEncrypt(plaintext: Data, key: SymmetricKey, nonce: Data) throws -> Data {
        let aesNonce = try AES.GCM.Nonce(data: nonce)
        let sealed = try AES.GCM.seal(plaintext, using: key, nonce: aesNonce)
        // Return ciphertext + tag (16 bytes)
        return sealed.ciphertext + sealed.tag
    }

    private static func aesDecrypt(
        ciphertext: Data, key: SymmetricKey, nonce: Data,
        chunkIndex: UInt64, passNum: UInt32
    ) throws -> Data {
        guard ciphertext.count >= gcmTagSize else {
            throw FortressError.authenticationFailed("AES", chunkIndex, passNum)
        }

        let ct = ciphertext.prefix(ciphertext.count - gcmTagSize)
        let tag = ciphertext.suffix(gcmTagSize)

        let aesNonce = try AES.GCM.Nonce(data: nonce)
        let sealedBox = try AES.GCM.SealedBox(nonce: aesNonce, ciphertext: ct, tag: tag)

        do {
            return try AES.GCM.open(sealedBox, using: key)
        } catch {
            throw FortressError.authenticationFailed("AES-256-GCM", chunkIndex, passNum)
        }
    }

    // MARK: - ChaCha20-Poly1305 (CryptoKit — native)

    private static func chachaEncrypt(plaintext: Data, key: SymmetricKey, nonce: Data) throws -> Data {
        let chachaNonce = try ChaChaPoly.Nonce(data: nonce)
        let sealed = try ChaChaPoly.seal(plaintext, using: key, nonce: chachaNonce)
        return sealed.ciphertext + sealed.tag
    }

    private static func chachaDecrypt(
        ciphertext: Data, key: SymmetricKey, nonce: Data,
        chunkIndex: UInt64, passNum: UInt32
    ) throws -> Data {
        guard ciphertext.count >= poly1305TagSize else {
            throw FortressError.authenticationFailed("ChaCha20", chunkIndex, passNum)
        }

        let ct = ciphertext.prefix(ciphertext.count - poly1305TagSize)
        let tag = ciphertext.suffix(poly1305TagSize)

        let chachaNonce = try ChaChaPoly.Nonce(data: nonce)
        let sealedBox = try ChaChaPoly.SealedBox(nonce: chachaNonce, ciphertext: ct, tag: tag)

        do {
            return try ChaChaPoly.open(sealedBox, using: key)
        } catch {
            throw FortressError.authenticationFailed("ChaCha20-Poly1305", chunkIndex, passNum)
        }
    }

    // MARK: - Camellia-256-CBC + HMAC-SHA512

    /// NOTE: Camellia uses OpenSSL via C bridge. See CBridge/FortressCBridge.c
    private static func camelliaEncrypt(
        plaintext: Data, key: Data, iv: Data,
        hmacKey: SymmetricKey, chunkIndex: UInt64, passNum: UInt32
    ) throws -> Data {
        // PKCS7 padding
        let blockSize = 16
        let padLen = blockSize - (plaintext.count % blockSize)
        var padded = plaintext
        padded.append(contentsOf: Data(repeating: UInt8(padLen), count: padLen))

        // Camellia-256-CBC via OpenSSL C bridge (padding disabled — we do PKCS7 in Swift)
        let ciphertext = try openSSLCamelliaEncrypt(data: padded, key: key, iv: iv)

        // HMAC-SHA512 (Encrypt-then-MAC) — this part uses CryptoKit
        var authData = Data()
        authData.append(contentsOf: withUnsafeBytes(of: chunkIndex.littleEndian) { Data($0) })
        authData.append(contentsOf: withUnsafeBytes(of: passNum.littleEndian) { Data($0) })
        authData.append(iv)
        authData.append(ciphertext)

        let hmacTag = Data(HMAC<SHA512>.authenticationCode(for: authData, using: hmacKey))

        return ciphertext + hmacTag
    }

    private static func camelliaDecrypt(
        data: Data, key: Data, iv: Data,
        hmacKey: SymmetricKey, chunkIndex: UInt64, passNum: UInt32
    ) throws -> Data {
        guard data.count >= hmac512TagSize else {
            throw FortressError.authenticationFailed("Camellia", chunkIndex, passNum)
        }

        let ciphertext = data.prefix(data.count - hmac512TagSize)
        let receivedTag = data.suffix(hmac512TagSize)

        // Verify HMAC first
        var authData = Data()
        authData.append(contentsOf: withUnsafeBytes(of: chunkIndex.littleEndian) { Data($0) })
        authData.append(contentsOf: withUnsafeBytes(of: passNum.littleEndian) { Data($0) })
        authData.append(iv)
        authData.append(ciphertext)

        let expectedTag = Data(HMAC<SHA512>.authenticationCode(for: authData, using: hmacKey))

        guard expectedTag == receivedTag else {
            throw FortressError.authenticationFailed("Camellia HMAC-SHA512", chunkIndex, passNum)
        }

        // Decrypt
        let padded = try openSSLCamelliaDecrypt(data: Data(ciphertext), key: key, iv: iv)

        // Remove PKCS7 padding
        guard let lastByte = padded.last else {
            throw FortressError.decryptionFailed("Empty Camellia output")
        }
        let padLen = Int(lastByte)
        guard padLen >= 1, padLen <= 16, padded.count >= padLen else {
            throw FortressError.decryptionFailed("Invalid PKCS7 padding")
        }
        // Verify all padding bytes
        let paddingBytes = padded.suffix(padLen)
        guard paddingBytes.allSatisfy({ $0 == lastByte }) else {
            throw FortressError.decryptionFailed("Corrupted PKCS7 padding")
        }

        return padded.prefix(padded.count - padLen)
    }

    // MARK: - OpenSSL Camellia Stubs

    /// Replace with actual OpenSSL EVP_CipherInit_ex / EVP_CipherUpdate / EVP_CipherFinal_ex
    private static func openSSLCamelliaEncrypt(data: Data, key: Data, iv: Data) throws -> Data {
        var output = Data(count: data.count + 16)
        var outputLen: Int32 = 0
        let result = output.withUnsafeMutableBytes { outPtr in
            data.withUnsafeBytes { inPtr in
                key.withUnsafeBytes { keyPtr in
                    iv.withUnsafeBytes { ivPtr in
                        fortress_camellia_encrypt(
                            inPtr.baseAddress!.assumingMemoryBound(to: UInt8.self), Int32(data.count),
                            keyPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                            ivPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                            outPtr.baseAddress!.assumingMemoryBound(to: UInt8.self), &outputLen
                        )
                    }
                }
            }
        }
        guard result == 0 else { throw FortressError.decryptionFailed("Camellia encrypt failed") }
        return output.prefix(Int(outputLen))
    }

    private static func openSSLCamelliaDecrypt(data: Data, key: Data, iv: Data) throws -> Data {
        var output = Data(count: data.count)
        var outputLen: Int32 = 0
        let result = output.withUnsafeMutableBytes { outPtr in
            data.withUnsafeBytes { inPtr in
                key.withUnsafeBytes { keyPtr in
                    iv.withUnsafeBytes { ivPtr in
                        fortress_camellia_decrypt(
                            inPtr.baseAddress!.assumingMemoryBound(to: UInt8.self), Int32(data.count),
                            keyPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                            ivPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                            outPtr.baseAddress!.assumingMemoryBound(to: UInt8.self), &outputLen
                        )
                    }
                }
            }
        }
        guard result == 0 else { throw FortressError.decryptionFailed("Camellia decrypt failed") }
        return output.prefix(Int(outputLen))
    }
}

// MARK: - Error Types

enum FortressError: LocalizedError {
    case authenticationFailed(String, UInt64, UInt32) // cipher, chunk, pass
    case decryptionFailed(String)
    case trapTriggered(String)
    case duressActivated
    case invalidFile(String)
    case keyDerivationFailed(String)
    case pqNotAvailable

    var errorDescription: String? {
        switch self {
        case .authenticationFailed(let cipher, let chunk, let pass):
            return "\(cipher) authentication FAILED [chunk=\(chunk), pass=\(pass)]"
        case .decryptionFailed(let msg):
            return "Decryption failed: \(msg)"
        case .trapTriggered(let msg):
            return "TRAP TRIGGERED: \(msg)"
        case .duressActivated:
            return "Duress activated"
        case .invalidFile(let msg):
            return "Invalid file: \(msg)"
        case .keyDerivationFailed(let msg):
            return "Key derivation failed: \(msg)"
        case .pqNotAvailable:
            return "Post-quantum library not available"
        }
    }
}
