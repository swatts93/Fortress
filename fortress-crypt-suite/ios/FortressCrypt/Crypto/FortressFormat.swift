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

// MARK: - File Format Constants

enum FortressFormat {
    static let magic = Data("FORTRESS".utf8)
    static let version: UInt16 = 2
    static let headerHMACSize = 32
    static let footerHMACSize = 32
    static let keyCommitmentSize = 64
    static let trapHashSize = 32
    static let trapSaltSize = 32
}

// MARK: - Header Model

struct FortressHeader: Codable {
    let version: UInt16
    let mode: UInt8               // 0=password, 1=pq-only, 2=hybrid
    let argon2Time: UInt32
    let argon2Memory: UInt32
    let argon2Parallelism: UInt32
    let scryptN: UInt32
    let scryptR: UInt32
    let scryptP: UInt32
    let salt: Data                // 32 bytes
    let nonceSeed: Data           // 32 bytes
    let originalSize: UInt64
    let chunkSize: UInt32
    let keyCommitment: Data       // 64 bytes (SHA3-512)
    let kemCiphertext: Data?

    // Trap sequence
    let trapCount: UInt8
    let trapSalt: Data            // 32 bytes
    let trapHashes: [Data]        // SHA3-256 hashes

    // Duress
    let duressEnabled: UInt8
    let duressSalt: Data
    let duressNonceSeed: Data
    let duressKeyCommitment: Data
    let duressDataSize: UInt64
    let duressChunkCount: UInt32

    var totalChunks: Int {
        if originalSize == 0 { return 0 }
        var n = Int(originalSize / UInt64(chunkSize))
        if originalSize % UInt64(chunkSize) > 0 { n += 1 }
        return n
    }

    // MARK: - Serialization

    func serialize() -> Data {
        var buf = Data()
        buf.append(FortressFormat.magic)
        buf.appendLE(version)
        buf.append(mode)
        buf.appendLE(argon2Time)
        buf.appendLE(argon2Memory)
        buf.appendLE(argon2Parallelism)
        buf.appendLE(scryptN)
        buf.appendLE(scryptR)
        buf.appendLE(scryptP)
        buf.append(salt)
        buf.append(nonceSeed)
        buf.appendLE(originalSize)
        buf.appendLE(chunkSize)
        buf.append(keyCommitment)

        let kem = kemCiphertext ?? Data()
        buf.appendLE(UInt32(kem.count))
        buf.append(kem)

        // Trap section
        buf.append(trapCount)
        buf.append(trapSalt)
        for th in trapHashes { buf.append(th) }

        // Duress section
        buf.append(duressEnabled)
        buf.append(duressSalt)
        buf.append(duressNonceSeed)
        buf.append(duressKeyCommitment)
        buf.appendLE(duressDataSize)
        buf.appendLE(duressChunkCount)

        return buf
    }

    // MARK: - Deserialization

    static func parse(from handle: ByteReader) throws -> FortressHeader {
        let magicData = handle.readData(ofLength: 8)
        guard magicData == FortressFormat.magic else {
            throw FortressError.invalidFile("Not a Fortress file (bad magic)")
        }

        let version: UInt16 = handle.readLE()
        guard version == FortressFormat.version else {
            throw FortressError.invalidFile("Unsupported version: \(version)")
        }

        let mode: UInt8 = handle.readData(ofLength: 1).first!
        let a_t: UInt32 = handle.readLE()
        let a_m: UInt32 = handle.readLE()
        let a_p: UInt32 = handle.readLE()
        let s_n: UInt32 = handle.readLE()
        let s_r: UInt32 = handle.readLE()
        let s_p: UInt32 = handle.readLE()
        let salt = handle.readData(ofLength: 32)
        let nonce = handle.readData(ofLength: 32)
        let origSize: UInt64 = handle.readLE()
        let chunkSz: UInt32 = handle.readLE()
        let commit = handle.readData(ofLength: 64)
        let kemLen: UInt32 = handle.readLE()
        let kemCT = kemLen > 0 ? handle.readData(ofLength: Int(kemLen)) : nil

        // Trap section
        let trapCount: UInt8 = handle.readData(ofLength: 1).first!
        let trapSalt = handle.readData(ofLength: 32)
        var trapHashes = [Data]()
        for _ in 0..<trapCount {
            trapHashes.append(handle.readData(ofLength: 32))
        }

        // Duress section
        let duressEnabled: UInt8 = handle.readData(ofLength: 1).first!
        let dSalt = handle.readData(ofLength: 32)
        let dNonce = handle.readData(ofLength: 32)
        let dCommit = handle.readData(ofLength: 64)
        let dSize: UInt64 = handle.readLE()
        let dChunks: UInt32 = handle.readLE()

        // Read header HMAC (consume it so file position advances past header)
        let _ = handle.readData(ofLength: FortressFormat.headerHMACSize)

        return FortressHeader(
            version: version, mode: mode,
            argon2Time: a_t, argon2Memory: a_m, argon2Parallelism: a_p,
            scryptN: s_n, scryptR: s_r, scryptP: s_p,
            salt: salt, nonceSeed: nonce,
            originalSize: origSize, chunkSize: chunkSz,
            keyCommitment: commit, kemCiphertext: kemCT,
            trapCount: trapCount, trapSalt: trapSalt, trapHashes: trapHashes,
            duressEnabled: duressEnabled,
            duressSalt: dSalt, duressNonceSeed: dNonce,
            duressKeyCommitment: dCommit,
            duressDataSize: dSize, duressChunkCount: dChunks
        )
    }
}

// MARK: - Chunk I/O

enum FortressChunkIO {

    static func writeChunk(to handle: FileHandle, data: Data) {
        var len = UInt32(data.count).littleEndian
        handle.write(Data(bytes: &len, count: 4))
        handle.write(data)
    }

    static func readChunk(from handle: ByteReader) -> Data? {
        let lenData = handle.readData(ofLength: 4)
        guard lenData.count == 4 else { return nil }
        let len = lenData.withUnsafeBytes { $0.load(as: UInt32.self).littleEndian }
        let data = handle.readData(ofLength: Int(len))
        guard data.count == Int(len) else { return nil }
        return data
    }

    static func writeFooter(to handle: FileHandle, hmac: Data) {
        handle.write(hmac)
    }

    static func readFooter(from handle: ByteReader) -> Data? {
        let data = handle.readData(ofLength: FortressFormat.footerHMACSize)
        return data.count == FortressFormat.footerHMACSize ? data : nil
    }
}

// MARK: - Scramble Operations (Destructive)

enum FortressScramble {

    /// Overwrite critical header fields with random bytes — file permanently destroyed
    static func scrambleHeader(at url: URL) throws {
        let handle = try FileHandle(forUpdating: url)
        defer { handle.closeFile() }

        // Skip magic(8) + version(2) + mode(1) + argon2(12) + scrypt(12) = 35 bytes
        handle.seek(toFileOffset: 35)

        // Overwrite salt (32B) + nonce_seed (32B) = 64 bytes of random
        var random = Data(count: 64)
        random.withUnsafeMutableBytes { ptr in
            _ = SecRandomCopyBytes(kSecRandomDefault, 64, ptr.baseAddress!)
        }
        handle.write(random)

        // Skip original_size(8) + chunk_size(4) = 12 bytes
        handle.seek(toFileOffset: handle.offsetInFile + 12)

        // Overwrite key_commitment (64B)
        var commitRandom = Data(count: 64)
        commitRandom.withUnsafeMutableBytes { ptr in
            _ = SecRandomCopyBytes(kSecRandomDefault, 64, ptr.baseAddress!)
        }
        handle.write(commitRandom)

        handle.synchronizeFile()
    }

    /// Overwrite real data section with random bytes (duress activation)
    static func scrambleRealData(at url: URL, header: FortressHeader) throws {
        let handle = try FileHandle(forUpdating: url)
        defer { handle.closeFile() }

        // Parse past header to get position
        handle.seek(toFileOffset: 0)
        let _ = try FortressHeader.parse(from: handle)

        // Skip duress chunks
        for _ in 0..<header.duressChunkCount {
            guard FortressChunkIO.readChunk(from: handle) != nil else { break }
        }
        // Skip duress footer
        handle.seek(toFileOffset: handle.offsetInFile + UInt64(FortressFormat.footerHMACSize))

        let realStart = handle.offsetInFile

        // Calculate real section size
        var realSize: UInt64 = 0
        for _ in 0..<header.totalChunks {
            let lenData = handle.readData(ofLength: 4)
            guard lenData.count == 4 else { break }
            let len = lenData.withUnsafeBytes { $0.load(as: UInt32.self).littleEndian }
            realSize += 4 + UInt64(len)
            handle.seek(toFileOffset: handle.offsetInFile + UInt64(len))
        }
        realSize += UInt64(FortressFormat.footerHMACSize)

        // Overwrite with random
        handle.seek(toFileOffset: realStart)
        var remaining = realSize
        while remaining > 0 {
            let blockSize = min(remaining, 1_048_576)
            var randomBlock = Data(count: Int(blockSize))
            randomBlock.withUnsafeMutableBytes { ptr in
                _ = SecRandomCopyBytes(kSecRandomDefault, Int(blockSize), ptr.baseAddress!)
            }
            handle.write(randomBlock)
            remaining -= blockSize
        }

        // Also wipe real key commitment in header
        handle.seek(toFileOffset: 35 + 64 + 12) // after salt+nonce+sizes
        var commitRandom = Data(count: 64)
        commitRandom.withUnsafeMutableBytes { ptr in
            _ = SecRandomCopyBytes(kSecRandomDefault, 64, ptr.baseAddress!)
        }
        handle.write(commitRandom)

        handle.synchronizeFile()
    }
}

// MARK: - Data Extensions for Binary I/O

extension Data {
    mutating func appendLE<T: FixedWidthInteger>(_ value: T) {
        var le = value.littleEndian
        append(Data(bytes: &le, count: MemoryLayout<T>.size))
    }
}

// MARK: - ByteReader Abstraction

/// Sequential byte reader — lets format parsing work over either a file
/// (FileHandle) or an in-memory buffer, without ever spilling plaintext
/// to disk. Used for message decryption which stays entirely in RAM.
protocol ByteReader: AnyObject {
    func readData(ofLength length: Int) -> Data
}

extension FileHandle: ByteReader {}

extension ByteReader {
    func readLE<T: FixedWidthInteger>() -> T {
        let data = readData(ofLength: MemoryLayout<T>.size)
        return data.withUnsafeBytes { $0.load(as: T.self).littleEndian }
    }
}

/// In-memory ByteReader backed by a Data buffer. No disk I/O — safe for
/// decrypted message material that should never touch persistent storage.
final class DataByteReader: ByteReader {
    private let data: Data
    private var offset: Int = 0

    init(_ data: Data) { self.data = data }

    func readData(ofLength length: Int) -> Data {
        let end = Swift.min(offset + length, data.count)
        guard offset < data.count else { return Data() }
        let slice = data.subdata(in: offset..<end)
        offset = end
        return slice
    }
}
