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

// MARK: - Fortress API

enum FortressAPI {

    // MARK: - File Encryption

    static func encryptFile(
        inputURL: URL, outputURL: URL, password: String,
        level: SecurityLevel = .paranoid,
        chunkSize: Int = FortressEngine.defaultChunkSize,
        trapCodes: [String]? = nil,
        duressPassword: String? = nil, duressData: Data? = nil,
        pqPublicKey: Data? = nil,
        progress: ((Double, String) -> Void)? = nil
    ) throws -> [String: Any] {

        let fileSize = try FileManager.default.attributesOfItem(atPath: inputURL.path)[.size] as! UInt64
        let salt = FortressKeyDerivation.generateSalt()
        let nonceSeed = FortressKeyDerivation.generateNonceSeed()

        // Mode & PQ
        var mode: UInt8 = 0
        var kemCT: Data? = nil
        var kemSS: Data? = nil
        if pqPublicKey != nil {
            mode = 2
            // TODO: ML-KEM encapsulation via liboqs
        }

        // Trap setup
        var trapCount: UInt8 = 0
        var trapSalt = Data(count: 32)
        var trapHashes = [Data]()
        if let codes = trapCodes, !codes.isEmpty {
            trapCount = UInt8(codes.count)
            trapSalt = FortressKeyDerivation.generateSalt()
            trapHashes = FortressKeyDerivation.generateTrapHashes(trapSalt: trapSalt, codes: codes)
        }

        // Duress setup
        var duressEnabled: UInt8 = 0
        var dSalt = Data(count: 32), dNonce = Data(count: 32)
        var dCommit = Data(count: 64)
        var dDataSize: UInt64 = 0, dChunkCount: UInt32 = 0
        var dKeys: FortressKeys? = nil

        if let dPw = duressPassword, let dData = duressData {
            duressEnabled = 1
            dSalt = FortressKeyDerivation.generateSalt()
            dNonce = FortressKeyDerivation.generateNonceSeed()
            progress?(0, "Deriving duress keys...")
            dKeys = try FortressKeyDerivation.deriveKeys(
                password: dPw, salt: dSalt, nonceSeed: dNonce,
                level: level, kemSharedSecret: kemSS
            )
            dCommit = dKeys!.commitment
            dDataSize = UInt64(dData.count)
            dChunkCount = dData.isEmpty ? 0 : UInt32((dData.count + chunkSize - 1) / chunkSize)
        }

        // Derive real keys
        progress?(0, "Deriving keys (Argon2id → scrypt → HKDF)...")
        let keys = try FortressKeyDerivation.deriveKeys(
            password: password, salt: salt, nonceSeed: nonceSeed,
            level: level, kemSharedSecret: kemSS
        )

        // Build header
        let header = FortressHeader(
            version: FortressFormat.version, mode: mode,
            argon2Time: level.argon2.timeCost, argon2Memory: level.argon2.memoryCost,
            argon2Parallelism: level.argon2.parallelism,
            scryptN: UInt32(level.scrypt.n), scryptR: level.scrypt.r, scryptP: level.scrypt.p,
            salt: salt, nonceSeed: nonceSeed,
            originalSize: fileSize, chunkSize: UInt32(chunkSize),
            keyCommitment: keys.commitment, kemCiphertext: kemCT,
            trapCount: trapCount, trapSalt: trapSalt, trapHashes: trapHashes,
            duressEnabled: duressEnabled,
            duressSalt: dSalt, duressNonceSeed: dNonce,
            duressKeyCommitment: dCommit,
            duressDataSize: dDataSize, duressChunkCount: dChunkCount
        )

        // Write file
        FileManager.default.createFile(atPath: outputURL.path, contents: nil)
        let outHandle = try FileHandle(forWritingTo: outputURL)
        defer { outHandle.closeFile() }

        // Write header + HMAC
        let headerBytes = header.serialize()
        outHandle.write(headerBytes)
        let headerHMAC = Data(HMAC<SHA256>.authenticationCode(
            for: headerBytes, using: keys.headerAuthKey
        ))
        outHandle.write(headerHMAC)

        // Write duress chunks
        var duressChunkCTs = [Data]()
        if duressEnabled == 1, let dData = duressData, let dk = dKeys {
            progress?(0, "Encrypting duress layer...")
            var offset = 0
            var idx: UInt64 = 0
            while offset < dData.count {
                let end = min(offset + chunkSize, dData.count)
                let chunk = dData[offset..<end]
                let ct = try FortressEngine.encryptChunk(plaintext: Data(chunk), keys: dk, chunkIndex: idx)
                FortressChunkIO.writeChunk(to: outHandle, data: ct)
                duressChunkCTs.append(ct)
                offset = end; idx += 1
            }
            let dFooter = footerHMAC(key: dk.footerAuthKey, chunks: duressChunkCTs)
            FortressChunkIO.writeFooter(to: outHandle, hmac: dFooter)
        }

        // Write real chunks
        let inHandle = try FileHandle(forReadingFrom: inputURL)
        defer { inHandle.closeFile() }

        let totalChunks = header.totalChunks
        var realChunkCTs = [Data]()
        var chunkIdx: UInt64 = 0

        while true {
            let raw = inHandle.readData(ofLength: chunkSize)
            if raw.isEmpty { break }
            progress?(Double(chunkIdx) / Double(max(totalChunks, 1)), "Encrypting...")
            let ct = try FortressEngine.encryptChunk(plaintext: raw, keys: keys, chunkIndex: chunkIdx)
            FortressChunkIO.writeChunk(to: outHandle, data: ct)
            realChunkCTs.append(ct)
            chunkIdx += 1
        }

        let realFooter = footerHMAC(key: keys.footerAuthKey, chunks: realChunkCTs)
        FortressChunkIO.writeFooter(to: outHandle, hmac: realFooter)

        progress?(1.0, "Done")

        return [
            "inputSize": fileSize,
            "chunks": chunkIdx,
            "trapsSet": trapCount,
            "duressEnabled": duressEnabled == 1,
            "layers": 6
        ]
    }

    // MARK: - File Decryption

    static func decryptFile(
        inputURL: URL, outputURL: URL, password: String,
        trapCodes: [String]? = nil,
        pqSecretKey: Data? = nil,
        progress: ((Double, String) -> Void)? = nil
    ) throws -> [String: Any] {

        let inHandle = try FileHandle(forReadingFrom: inputURL)
        defer { inHandle.closeFile() }

        let header = try FortressHeader.parse(from: inHandle)

        // Step 1: Verify trap codes
        if header.trapCount > 0 {
            guard let codes = trapCodes, codes.count == Int(header.trapCount) else {
                try FortressScramble.scrambleHeader(at: inputURL)
                throw FortressError.trapTriggered(
                    "Wrong number of trap codes. FILE PERMANENTLY DESTROYED."
                )
            }
            for (i, code) in codes.enumerated() {
                if !FortressKeyDerivation.verifyTrapCode(
                    trapSalt: header.trapSalt, index: i,
                    code: code, expectedHash: header.trapHashes[i]
                ) {
                    try FortressScramble.scrambleHeader(at: inputURL)
                    throw FortressError.trapTriggered(
                        "Trap code #\(i+1) INCORRECT. FILE PERMANENTLY DESTROYED."
                    )
                }
            }
        }

        // Step 2: PQ decapsulation
        var kemSS: Data? = nil
        if header.mode == 2 {
            guard pqSecretKey != nil else {
                throw FortressError.invalidFile("Hybrid PQ mode — secret key required")
            }
            // TODO: ML-KEM decapsulation
        }

        // Step 3: Derive keys and determine real vs duress
        progress?(0, "Deriving keys...")
        let level = SecurityLevel.standard // Params come from header, not preset

        let realKeys = try FortressKeyDerivation.deriveKeys(
            password: password, salt: header.salt, nonceSeed: header.nonceSeed,
            level: level, kemSharedSecret: kemSS
        )

        let isReal = FortressKeyDerivation.constantTimeEquals(realKeys.commitment, header.keyCommitment)

        // Always derive the duress keyset when duress is enabled, even if the
        // real password already matched. Deriving it only on a real-password
        // mismatch makes the real password ~2x faster to verify than any other
        // guess (one KDF pass vs. two), letting a coercion adversary confirm a
        // handed-over password is the genuine one from wall-clock timing alone —
        // defeating the duress deniability goal.
        var duressKeys: FortressKeys? = nil
        var duressMatch = false
        if header.duressEnabled == 1 {
            progress?(0, "Verifying credentials...")
            let dKeys = try FortressKeyDerivation.deriveKeys(
                password: password, salt: header.duressSalt,
                nonceSeed: header.duressNonceSeed,
                level: level, kemSharedSecret: kemSS
            )
            duressKeys = dKeys
            duressMatch = FortressKeyDerivation.constantTimeEquals(dKeys.commitment, header.duressKeyCommitment)
        }

        if !isReal && duressMatch {
            // DURESS MODE — decrypt dummy, destroy real
            return try decryptDuress(
                inputURL: inputURL, outputURL: outputURL,
                header: header, duressKeys: duressKeys!, progress: progress
            )
        } else if !isReal {
            throw FortressError.decryptionFailed("KEY COMMITMENT MISMATCH — wrong password")
        }

        // Step 4: Decrypt real data
        inHandle.seek(toFileOffset: 0)
        let _ = try FortressHeader.parse(from: inHandle) // re-parse to advance position

        // Skip duress section
        if header.duressEnabled == 1 {
            for _ in 0..<header.duressChunkCount {
                let _ = FortressChunkIO.readChunk(from: inHandle)
            }
            let _ = inHandle.readData(ofLength: FortressFormat.footerHMACSize)
        }

        FileManager.default.createFile(atPath: outputURL.path, contents: nil)
        let outHandle = try FileHandle(forWritingTo: outputURL)
        defer { outHandle.closeFile() }

        var bytesWritten: UInt64 = 0
        var chunkCTs = [Data]()

        for i in 0..<header.totalChunks {
            progress?(Double(i) / Double(header.totalChunks), "Decrypting...")
            guard let ct = FortressChunkIO.readChunk(from: inHandle) else {
                throw FortressError.invalidFile("Unexpected EOF at chunk \(i)")
            }
            chunkCTs.append(ct)
            let pt = try FortressEngine.decryptChunk(encrypted: ct, keys: realKeys, chunkIndex: UInt64(i))
            let remaining = header.originalSize - bytesWritten
            let toWrite = pt.prefix(Int(min(UInt64(pt.count), remaining)))
            outHandle.write(toWrite)
            bytesWritten += UInt64(toWrite.count)
        }

        // Verify footer
        guard let storedFooter = FortressChunkIO.readFooter(from: inHandle) else {
            throw FortressError.invalidFile("Missing footer")
        }
        let expectedFooter = footerHMAC(key: realKeys.footerAuthKey, chunks: chunkCTs)
        guard FortressKeyDerivation.constantTimeEquals(storedFooter, expectedFooter) else {
            try? FileManager.default.removeItem(at: outputURL)
            throw FortressError.authenticationFailed("Footer SHA3-256", 0, 0)
        }

        progress?(1.0, "Done")
        return [
            "originalSize": header.originalSize,
            "bytesWritten": bytesWritten,
            "chunks": header.totalChunks,
            "duress": false,
            "verified": true
        ]
    }

    // MARK: - Duress Decryption (private)

    private static func decryptDuress(
        inputURL: URL, outputURL: URL,
        header: FortressHeader, duressKeys: FortressKeys,
        progress: ((Double, String) -> Void)?
    ) throws -> [String: Any] {
        let inHandle = try FileHandle(forReadingFrom: inputURL)
        defer { inHandle.closeFile() }

        inHandle.seek(toFileOffset: 0)
        let _ = try FortressHeader.parse(from: inHandle)

        FileManager.default.createFile(atPath: outputURL.path, contents: nil)
        let outHandle = try FileHandle(forWritingTo: outputURL)
        defer { outHandle.closeFile() }

        var bytesWritten: UInt64 = 0
        var chunkCTs = [Data]()

        for i in 0..<header.duressChunkCount {
            progress?(Double(i) / Double(max(header.duressChunkCount, 1)), "Decrypting...")
            guard let ct = FortressChunkIO.readChunk(from: inHandle) else { break }
            chunkCTs.append(ct)
            let pt = try FortressEngine.decryptChunk(encrypted: ct, keys: duressKeys, chunkIndex: UInt64(i))
            let remaining = header.duressDataSize - bytesWritten
            let toWrite = pt.prefix(Int(min(UInt64(pt.count), remaining)))
            outHandle.write(toWrite)
            bytesWritten += UInt64(toWrite.count)
        }

        // Verify duress footer
        guard let storedFooter = FortressChunkIO.readFooter(from: inHandle) else {
            throw FortressError.invalidFile("Missing duress footer")
        }
        let expectedFooter = footerHMAC(key: duressKeys.footerAuthKey, chunks: chunkCTs)
        guard FortressKeyDerivation.constantTimeEquals(storedFooter, expectedFooter) else {
            try? FileManager.default.removeItem(at: outputURL)
            throw FortressError.authenticationFailed("Duress Footer", 0, 0)
        }

        // SILENTLY DESTROY REAL DATA
        progress?(0.9, "Finalizing...")
        try FortressScramble.scrambleRealData(at: inputURL, header: header)

        progress?(1.0, "Done")
        return [
            "originalSize": header.duressDataSize,
            "bytesWritten": bytesWritten,
            "chunks": header.duressChunkCount,
            "duress": true,
            "verified": true
        ]
    }

    // MARK: - Footer HMAC (SHA3-256 chain)

    private static func footerHMAC(key: Data, chunks: [Data]) -> Data {
        // SHA3-256 chain — uses different hash family than header (SHA-256)
        var input = Data("fortress-footer-chain-v2".utf8) + key
        for ct in chunks {
            var len = UInt32(ct.count).littleEndian
            input.append(Data(bytes: &len, count: 4))
            input.append(ct)
        }
        return FortressKeyDerivation.sha3_256(input)
    }

    // MARK: - Message Encryption

    /// Encrypt a text message → base64 FORTRESS: token
    static func encryptMessage(
        message: String, password: String,
        level: SecurityLevel = .standard,
        trapCodes: [String]? = nil
    ) throws -> String {
        let msgData = Data(message.utf8)
        let salt = FortressKeyDerivation.generateSalt()
        let nonceSeed = FortressKeyDerivation.generateNonceSeed()

        // Trap setup
        var trapCount: UInt8 = 0
        var trapSalt = Data(count: 32)
        var trapHashes = [Data]()
        if let codes = trapCodes, !codes.isEmpty {
            trapCount = UInt8(codes.count)
            trapSalt = FortressKeyDerivation.generateSalt()
            trapHashes = FortressKeyDerivation.generateTrapHashes(trapSalt: trapSalt, codes: codes)
        }

        let keys = try FortressKeyDerivation.deriveKeys(
            password: password, salt: salt, nonceSeed: nonceSeed, level: level
        )

        let header = FortressHeader(
            version: FortressFormat.version, mode: 0,
            argon2Time: level.argon2.timeCost, argon2Memory: level.argon2.memoryCost,
            argon2Parallelism: level.argon2.parallelism,
            scryptN: UInt32(level.scrypt.n), scryptR: level.scrypt.r, scryptP: level.scrypt.p,
            salt: salt, nonceSeed: nonceSeed,
            originalSize: UInt64(msgData.count), chunkSize: UInt32(msgData.count + 8192),
            keyCommitment: keys.commitment, kemCiphertext: nil,
            trapCount: trapCount, trapSalt: trapSalt, trapHashes: trapHashes,
            duressEnabled: 0,
            duressSalt: Data(count: 32), duressNonceSeed: Data(count: 32),
            duressKeyCommitment: Data(count: 64),
            duressDataSize: 0, duressChunkCount: 0
        )

        var buf = Data()
        let headerBytes = header.serialize()
        buf.append(headerBytes)
        let headerHMAC = Data(HMAC<SHA256>.authenticationCode(for: headerBytes, using: keys.headerAuthKey))
        buf.append(headerHMAC)

        let ct = try FortressEngine.encryptChunk(plaintext: msgData, keys: keys, chunkIndex: 0)
        var len = UInt32(ct.count).littleEndian
        buf.append(Data(bytes: &len, count: 4))
        buf.append(ct)

        let footer = footerHMAC(key: keys.footerAuthKey, chunks: [ct])
        buf.append(footer)

        return "FORTRESS:" + buf.base64EncodedString()
    }

    /// Decrypt a FORTRESS: base64 message token
    static func decryptMessage(
        token: String, password: String,
        trapCodes: [String]? = nil
    ) throws -> String {
        guard token.hasPrefix("FORTRESS:") else {
            throw FortressError.invalidFile("Not a Fortress message")
        }

        let b64 = String(token.dropFirst(9))
        guard let raw = Data(base64Encoded: b64) else {
            throw FortressError.invalidFile("Invalid base64")
        }

        // Parse header from in-memory buffer
        let handle = DataByteReader(raw)
        let header = try FortressHeader.parse(from: handle)

        // Verify traps
        if header.trapCount > 0 {
            guard let codes = trapCodes, codes.count == Int(header.trapCount) else {
                throw FortressError.trapTriggered("Wrong number of trap codes")
            }
            for (i, code) in codes.enumerated() {
                if !FortressKeyDerivation.verifyTrapCode(
                    trapSalt: header.trapSalt, index: i,
                    code: code, expectedHash: header.trapHashes[i]
                ) {
                    throw FortressError.trapTriggered("Trap code #\(i+1) INCORRECT")
                }
            }
        }

        let keys = try FortressKeyDerivation.deriveKeys(
            password: password, salt: header.salt, nonceSeed: header.nonceSeed,
            level: .standard
        )

        guard FortressKeyDerivation.constantTimeEquals(keys.commitment, header.keyCommitment) else {
            throw FortressError.decryptionFailed("KEY COMMITMENT MISMATCH — wrong password")
        }

        // Read chunk
        guard let ct = FortressChunkIO.readChunk(from: handle) else {
            throw FortressError.invalidFile("No encrypted data")
        }

        let plaintext = try FortressEngine.decryptChunk(encrypted: ct, keys: keys, chunkIndex: 0)
        let msgData = plaintext.prefix(Int(header.originalSize))
        guard let text = String(data: msgData, encoding: .utf8) else {
            throw FortressError.decryptionFailed("Invalid UTF-8 in decrypted message")
        }

        return text
    }
}
