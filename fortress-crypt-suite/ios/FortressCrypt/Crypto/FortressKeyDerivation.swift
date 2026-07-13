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
import CommonCrypto

// MARK: - Security Level Presets

/// Argon2id + scrypt parameter presets
enum SecurityLevel: String, CaseIterable, Identifiable, Codable {
    case standard = "standard"
    case high = "high"
    case paranoid = "paranoid"
    case fortress = "fortress"

    var id: String { rawValue }

    var displayName: String {
        switch self {
        case .standard: return "Standard (256 MB)"
        case .high:     return "High (1 GB)"
        case .paranoid: return "Paranoid (2 GB)"
        case .fortress: return "Fortress (4 GB)"
        }
    }

    var argon2: (timeCost: UInt32, memoryCost: UInt32, parallelism: UInt32) {
        switch self {
        case .standard: return (4,   131_072,  4)
        case .high:     return (6,   524_288,  4)
        case .paranoid: return (10, 1_048_576, 8)
        case .fortress: return (14, 2_097_152, 8)
        }
    }

    var scrypt: (n: UInt64, r: UInt32, p: UInt32) {
        switch self {
        case .standard: return (1 << 17, 8, 1)
        case .high:     return (1 << 19, 8, 1)
        case .paranoid: return (1 << 20, 8, 2)
        case .fortress: return (1 << 21, 8, 2)
        }
    }
}

// MARK: - Derived Key Container

/// All keys derived for the double-cascade encryption
struct FortressKeys {
    // Pass 1 keys
    let p1AESKey: SymmetricKey       // 256-bit
    let p1ChaChaKey: SymmetricKey    // 256-bit
    let p1CamelliaKey: Data          // 256-bit (32 bytes)
    let p1HMACKey: SymmetricKey      // 256-bit

    // Pass 2 keys (completely independent)
    let p2AESKey: SymmetricKey
    let p2ChaChaKey: SymmetricKey
    let p2CamelliaKey: Data
    let p2HMACKey: SymmetricKey

    // Authentication keys
    let headerAuthKey: SymmetricKey
    let footerAuthKey: Data          // SHA3-256 based

    // Anti-forensic
    let paddingKey: Data

    // Nonce derivation
    let nonceSeed: Data

    // Key commitment (SHA3-512)
    let commitment: Data
}

// MARK: - Key Derivation

enum FortressKeyDerivation {

    static let saltSize = 32
    static let nonceSeedSize = 32
    static let masterKeySize = 64
    static let derivedKeySize = 32
    static let maxTraps = 5
    static let trapHashSize = 32

    /// Generate cryptographically secure random bytes
    static func generateSalt() -> Data {
        var bytes = Data(count: saltSize)
        bytes.withUnsafeMutableBytes { ptr in
            _ = SecRandomCopyBytes(kSecRandomDefault, saltSize, ptr.baseAddress!)
        }
        return bytes
    }

    static func generateNonceSeed() -> Data {
        var bytes = Data(count: nonceSeedSize)
        bytes.withUnsafeMutableBytes { ptr in
            _ = SecRandomCopyBytes(kSecRandomDefault, nonceSeedSize, ptr.baseAddress!)
        }
        return bytes
    }

    // MARK: - Triple-Chained KDF

    /// Derive all encryption keys via Argon2id → scrypt → HKDF-SHA512
    ///
    /// - Parameters:
    ///   - password: User's password
    ///   - salt: Random salt (stored in file header)
    ///   - nonceSeed: Random seed for per-chunk nonce derivation
    ///   - level: Security level preset
    ///   - kemSharedSecret: Optional ML-KEM shared secret for hybrid PQ mode
    static func deriveKeys(
        password: String,
        salt: Data,
        nonceSeed: Data,
        level: SecurityLevel,
        kemSharedSecret: Data? = nil
    ) throws -> FortressKeys {
        let passwordData = Data(password.utf8)
        let argon2Params = level.argon2
        let scryptParams = level.scrypt

        // ── Phase 1: Argon2id ────────────────────────────────
        let phase1 = try argon2id(
            password: passwordData, salt: salt,
            timeCost: argon2Params.timeCost,
            memoryCost: argon2Params.memoryCost,
            parallelism: argon2Params.parallelism,
            hashLength: masterKeySize
        )

        var phase1Result = phase1

        // ── Hybrid PQ injection ──────────────────────────────
        if let kem = kemSharedSecret {
            phase1Result = try hkdfDerive(
                ikm: phase1 + kem, salt: salt,
                info: Data("fortress-hybrid-pre-scrypt-v2".utf8),
                outputSize: masterKeySize
            )
        }

        // ── Phase 2: scrypt ──────────────────────────────────
        let scryptSalt = sha3_256(Data("fortress-scrypt-salt-v2".utf8) + salt)
        let phase2 = try scryptDerive(
            password: phase1Result, salt: scryptSalt,
            n: scryptParams.n, r: scryptParams.r, p: scryptParams.p,
            keyLength: masterKeySize
        )

        // ── Phase 3: XOR + HKDF-SHA512 ──────────────────────
        // XOR the two independent memory-hard outputs so BOTH must be correct.
        let combined = Data(zip(phase1Result, phase2).map { $0 ^ $1 })

        let master = try hkdfDerive(
            ikm: combined, salt: salt,
            info: Data("fortress-master-key-v2".utf8),
            outputSize: masterKeySize
        )

        // ── Derive all sub-keys ──────────────────────────────
        let p1a = try hkdfDerive(ikm: master, salt: salt, info: d("fortress-p1-aes256gcm-v2"))
        let p1c = try hkdfDerive(ikm: master, salt: salt, info: d("fortress-p1-chacha20poly1305-v2"))
        let p1m = try hkdfDerive(ikm: master, salt: salt, info: d("fortress-p1-camellia256cbc-v2"))
        let p1h = try hkdfDerive(ikm: master, salt: salt, info: d("fortress-p1-hmac-sha512-v2"))

        let p2a = try hkdfDerive(ikm: master, salt: salt, info: d("fortress-p2-aes256gcm-v2"))
        let p2c = try hkdfDerive(ikm: master, salt: salt, info: d("fortress-p2-chacha20poly1305-v2"))
        let p2m = try hkdfDerive(ikm: master, salt: salt, info: d("fortress-p2-camellia256cbc-v2"))
        let p2h = try hkdfDerive(ikm: master, salt: salt, info: d("fortress-p2-hmac-sha512-v2"))

        let hdr = try hkdfDerive(ikm: master, salt: salt, info: d("fortress-header-auth-sha256-v2"))
        let ftr = try hkdfDerive(ikm: master, salt: salt, info: d("fortress-footer-auth-sha3-256-v2"))
        let pad = try hkdfDerive(ikm: master, salt: salt, info: d("fortress-padding-key-v2"))

        // Key commitment (SHA3-512)
        let allKeysConcat = p1a + p1c + p1m + p1h + p2a + p2c + p2m + p2h + hdr + ftr
        let commitment = sha3_512(Data("fortress-key-commitment-v2".utf8) + allKeysConcat)

        return FortressKeys(
            p1AESKey: SymmetricKey(data: p1a),
            p1ChaChaKey: SymmetricKey(data: p1c),
            p1CamelliaKey: p1m,
            p1HMACKey: SymmetricKey(data: p1h),
            p2AESKey: SymmetricKey(data: p2a),
            p2ChaChaKey: SymmetricKey(data: p2c),
            p2CamelliaKey: p2m,
            p2HMACKey: SymmetricKey(data: p2h),
            headerAuthKey: SymmetricKey(data: hdr),
            footerAuthKey: ftr,
            paddingKey: pad,
            nonceSeed: nonceSeed,
            commitment: commitment
        )
    }

    // MARK: - Chunk Nonce Derivation

    /// Derive unique nonces for each cipher, per chunk, per cascade pass
    static func deriveChunkNonces(
        nonceSeed: Data, chunkIndex: UInt64, cascadePass: UInt32
    ) throws -> (aesNonce: Data, chachaNonce: Data, camelliaIV: Data) {
        var ctx = Data()
        ctx.append(contentsOf: withUnsafeBytes(of: chunkIndex.littleEndian) { Data($0) })
        ctx.append(contentsOf: withUnsafeBytes(of: cascadePass.littleEndian) { Data($0) })

        let aesNonce = try hkdfDerive(ikm: nonceSeed, salt: ctx,
                                       info: d("fortress-aes-nonce"), outputSize: 12)
        let chachaNonce = try hkdfDerive(ikm: nonceSeed, salt: ctx,
                                          info: d("fortress-chacha-nonce"), outputSize: 12)
        let camelliaIV = try hkdfDerive(ikm: nonceSeed, salt: ctx,
                                         info: d("fortress-camellia-iv"), outputSize: 16)

        return (aesNonce, chachaNonce, camelliaIV)
    }

    /// Derive deterministic padding length for anti-forensic padding
    static func derivePaddingLength(
        paddingKey: Data, chunkIndex: UInt64,
        minPad: Int = 256, maxPad: Int = 4096
    ) throws -> Int {
        var ctx = Data()
        ctx.append(contentsOf: withUnsafeBytes(of: chunkIndex.littleEndian) { Data($0) })
        let raw = try hkdfDerive(ikm: paddingKey, salt: ctx,
                                  info: d("fortress-pad-len"), outputSize: 4)
        let value = raw.withUnsafeBytes { $0.load(as: UInt32.self).littleEndian }
        return minPad + Int(value % UInt32(maxPad - minPad + 1))
    }

    // MARK: - Trap Sequence

    static func hashTrapCode(trapSalt: Data, index: Int, code: String) -> Data {
        var input = trapSalt
        input.append(contentsOf: withUnsafeBytes(of: UInt32(index).littleEndian) { Data($0) })
        input.append(contentsOf: Data(code.utf8))
        return sha3_256(input)
    }

    static func generateTrapHashes(trapSalt: Data, codes: [String]) -> [Data] {
        return codes.enumerated().map { hashTrapCode(trapSalt: trapSalt, index: $0.offset, code: $0.element) }
    }

    static func verifyTrapCode(trapSalt: Data, index: Int, code: String, expectedHash: Data) -> Bool {
        let computed = hashTrapCode(trapSalt: trapSalt, index: index, code: code)
        return constantTimeEquals(computed, expectedHash)
    }

    /// Constant-time comparison to prevent timing side-channel attacks.
    /// Compares all bytes regardless of where the first difference occurs.
    static func constantTimeEquals(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        for i in 0..<a.count {
            diff |= a[a.startIndex + i] ^ b[b.startIndex + i]
        }
        return diff == 0
    }

    // MARK: - Primitive Wrappers

    /// Argon2id password hashing
    /// NOTE: Requires swift-argon2 or Argon2Swift SPM package.
    /// Replace this stub with actual library call.
    private static func argon2id(
        password: Data, salt: Data,
        timeCost: UInt32, memoryCost: UInt32, parallelism: UInt32,
        hashLength: Int
    ) throws -> Data {
        var output = Data(count: hashLength)
        let result = output.withUnsafeMutableBytes { outPtr in
            password.withUnsafeBytes { pwPtr in
                salt.withUnsafeBytes { saltPtr in
                    fortress_argon2id(
                        pwPtr.baseAddress!.assumingMemoryBound(to: UInt8.self), password.count,
                        saltPtr.baseAddress!.assumingMemoryBound(to: UInt8.self), salt.count,
                        timeCost, memoryCost, parallelism,
                        outPtr.baseAddress!.assumingMemoryBound(to: UInt8.self), hashLength
                    )
                }
            }
        }
        guard result == 0 else { throw NSError(domain: "Fortress", code: -1, userInfo: [NSLocalizedDescriptionKey: "Argon2id failed"]) }
        return output
    }

    /// scrypt key derivation via OpenSSL
    /// NOTE: Requires OpenSSL C library linked.
    private static func scryptDerive(
        password: Data, salt: Data,
        n: UInt64, r: UInt32, p: UInt32,
        keyLength: Int
    ) throws -> Data {
        var output = Data(count: keyLength)
        let result = output.withUnsafeMutableBytes { outPtr in
            password.withUnsafeBytes { pwPtr in
                salt.withUnsafeBytes { saltPtr in
                    fortress_scrypt(
                        pwPtr.baseAddress!.assumingMemoryBound(to: UInt8.self), password.count,
                        saltPtr.baseAddress!.assumingMemoryBound(to: UInt8.self), salt.count,
                        n, UInt32(r), UInt32(p),
                        outPtr.baseAddress!.assumingMemoryBound(to: UInt8.self), keyLength
                    )
                }
            }
        }
        guard result == 0 else { throw NSError(domain: "Fortress", code: -2, userInfo: [NSLocalizedDescriptionKey: "scrypt failed"]) }
        return output
    }

    /// HKDF-SHA512 key derivation (CryptoKit — no dependencies needed)
    static func hkdfDerive(
        ikm: Data, salt: Data, info: Data, outputSize: Int = derivedKeySize
    ) throws -> Data {
        let key = SymmetricKey(data: ikm)
        let derived = HKDF<SHA512>.deriveKey(
            inputKeyMaterial: key,
            salt: salt,
            info: info,
            outputByteCount: outputSize
        )
        return derived.withUnsafeBytes { Data($0) }
    }

    /// SHA3-256 hash
    /// NOTE: CryptoKit added SHA3 in iOS 18 / macOS 15. For iOS 17, use OpenSSL.
    static func sha3_256(_ data: Data) -> Data {
        var output = Data(count: 32)
        output.withUnsafeMutableBytes { outPtr in
            data.withUnsafeBytes { inPtr in
                fortress_sha3_256(
                    inPtr.baseAddress!.assumingMemoryBound(to: UInt8.self), data.count,
                    outPtr.baseAddress!.assumingMemoryBound(to: UInt8.self)
                )
            }
        }
        return output
    }

    /// SHA3-512 hash
    static func sha3_512(_ data: Data) -> Data {
        var output = Data(count: 64)
        output.withUnsafeMutableBytes { outPtr in
            data.withUnsafeBytes { inPtr in
                fortress_sha3_512(
                    inPtr.baseAddress!.assumingMemoryBound(to: UInt8.self), data.count,
                    outPtr.baseAddress!.assumingMemoryBound(to: UInt8.self)
                )
            }
        }
        return output
    }

    /// Helper to convert string to Data
    private static func d(_ s: String) -> Data { Data(s.utf8) }
}
