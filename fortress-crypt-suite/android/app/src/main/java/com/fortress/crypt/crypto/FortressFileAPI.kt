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

package com.fortress.crypt.crypto

import java.io.*
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom

// ═══════════════════════════════════════════════════════════════
//  FILE FORMAT
// ═══════════════════════════════════════════════════════════════

data class FortressHeader(
    val version: Int, val mode: Int,
    val argon2Time: Int, val argon2Memory: Int, val argon2Parallelism: Int,
    val scryptN: Int, val scryptR: Int, val scryptP: Int,
    val salt: ByteArray, val nonceSeed: ByteArray,
    val originalSize: Long, val chunkSize: Int,
    val keyCommitment: ByteArray, val kemCiphertext: ByteArray?,
    val trapCount: Int, val trapSalt: ByteArray, val trapHashes: List<ByteArray>,
    val duressEnabled: Boolean,
    val duressSalt: ByteArray, val duressNonceSeed: ByteArray,
    val duressKeyCommitment: ByteArray,
    val duressDataSize: Long, val duressChunkCount: Int
) {
    val totalChunks: Int get() {
        if (originalSize == 0L) return 0
        var n = (originalSize / chunkSize).toInt()
        if (originalSize % chunkSize > 0) n++
        return n
    }

    fun serialize(): ByteArray {
        val buf = ByteArrayOutputStream()
        val out = DataOutputStream(buf)

        out.write("FORTRESS".toByteArray())
        out.writeLE16(version); out.write(mode)
        out.writeLE32(argon2Time); out.writeLE32(argon2Memory); out.writeLE32(argon2Parallelism)
        out.writeLE32(scryptN); out.writeLE32(scryptR); out.writeLE32(scryptP)
        out.write(salt); out.write(nonceSeed)
        out.writeLE64(originalSize); out.writeLE32(chunkSize)
        out.write(keyCommitment)
        val kem = kemCiphertext ?: ByteArray(0)
        out.writeLE32(kem.size); out.write(kem)

        out.write(trapCount)
        out.write(trapSalt)
        trapHashes.forEach { out.write(it) }

        out.write(if (duressEnabled) 1 else 0)
        out.write(duressSalt); out.write(duressNonceSeed)
        out.write(duressKeyCommitment)
        out.writeLE64(duressDataSize); out.writeLE32(duressChunkCount)

        return buf.toByteArray()
    }

    companion object {
        fun parse(input: DataInputStream): FortressHeader {
            val magic = ByteArray(8); input.readFully(magic)
            if (!magic.contentEquals("FORTRESS".toByteArray()))
                throw FortressException.InvalidFile("Bad magic")

            val version = input.readLE16()
            if (version != 2) throw FortressException.InvalidFile("Unsupported version: $version")

            val mode = input.read()
            val aT = input.readLE32(); val aM = input.readLE32(); val aP = input.readLE32()
            val sN = input.readLE32(); val sR = input.readLE32(); val sP = input.readLE32()
            val salt = ByteArray(32); input.readFully(salt)
            val nonce = ByteArray(32); input.readFully(nonce)
            val origSize = input.readLE64(); val chunkSize = input.readLE32()
            val commit = ByteArray(64); input.readFully(commit)
            val kemLen = input.readLE32()
            val kemCT = if (kemLen > 0) ByteArray(kemLen).also { input.readFully(it) } else null

            val trapCount = input.read()
            val trapSalt = ByteArray(32); input.readFully(trapSalt)
            val trapHashes = (0 until trapCount).map { ByteArray(32).also { input.readFully(it) } }

            val duressEnabled = input.read() == 1
            val dSalt = ByteArray(32); input.readFully(dSalt)
            val dNonce = ByteArray(32); input.readFully(dNonce)
            val dCommit = ByteArray(64); input.readFully(dCommit)
            val dSize = input.readLE64(); val dChunks = input.readLE32()

            val headerHmac = ByteArray(32); input.readFully(headerHmac) // consume HMAC

            return FortressHeader(
                version, mode, aT, aM, aP, sN, sR, sP,
                salt, nonce, origSize, chunkSize, commit, kemCT,
                trapCount, trapSalt, trapHashes,
                duressEnabled, dSalt, dNonce, dCommit, dSize, dChunks
            )
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  HIGH-LEVEL API
// ═══════════════════════════════════════════════════════════════

object FortressAPI {

    fun encryptFile(
        inputFile: File, outputFile: File, password: String,
        level: SecurityLevel = SecurityLevel.PARANOID,
        chunkSize: Int = FortressEngine.DEFAULT_CHUNK_SIZE,
        trapCodes: List<String>? = null,
        duressPassword: String? = null, duressData: ByteArray? = null,
        progress: ((Double, String) -> Unit)? = null
    ): Map<String, Any> {
        val fileSize = inputFile.length()
        val salt = FortressKeyDerivation.generateSalt()
        val nonceSeed = FortressKeyDerivation.generateNonceSeed()

        // Trap setup
        val trapCount = trapCodes?.size ?: 0
        val trapSalt = if (trapCount > 0) FortressKeyDerivation.generateSalt() else ByteArray(32)
        val trapHashes = if (trapCodes != null) FortressKeyDerivation.generateTrapHashes(trapSalt, trapCodes) else emptyList()

        // Duress setup
        var dKeys: FortressKeys? = null
        val duressEnabled = duressPassword != null && duressData != null
        val dSalt = if (duressEnabled) FortressKeyDerivation.generateSalt() else ByteArray(32)
        val dNonce = if (duressEnabled) FortressKeyDerivation.generateNonceSeed() else ByteArray(32)
        var dCommit = ByteArray(64)
        val dDataSize = duressData?.size?.toLong() ?: 0L
        val dChunkCount = if (duressEnabled && dDataSize > 0) ((dDataSize + chunkSize - 1) / chunkSize).toInt() else 0

        if (duressEnabled) {
            progress?.invoke(0.0, "Deriving duress keys...")
            dKeys = FortressKeyDerivation.deriveKeys(duressPassword!!, dSalt, dNonce, level)
            dCommit = dKeys.commitment
        }

        progress?.invoke(0.0, "Deriving real keys (Argon2id → scrypt → HKDF)...")
        val keys = FortressKeyDerivation.deriveKeys(password, salt, nonceSeed, level)

        try {
            val header = FortressHeader(
                2, 0, level.argon2Time, level.argon2Memory, level.argon2Parallelism,
                level.scryptN, level.scryptR, level.scryptP,
                salt, nonceSeed, fileSize, chunkSize, keys.commitment, null,
                trapCount, trapSalt, trapHashes,
                duressEnabled, dSalt, dNonce, dCommit, dDataSize, dChunkCount
            )

            DataOutputStream(BufferedOutputStream(FileOutputStream(outputFile))).use { out ->
                // Header + HMAC
                val headerBytes = header.serialize()
                out.write(headerBytes)
                out.write(FortressKeyDerivation.hmacSHA256(keys.headerAuthKey, headerBytes))

                // Duress chunks
                val duressChunkCTs = mutableListOf<ByteArray>()
                if (duressEnabled && duressData != null && dKeys != null) {
                    progress?.invoke(0.0, "Encrypting duress layer...")
                    var offset = 0; var idx = 0L
                    while (offset < duressData.size) {
                        val end = minOf(offset + chunkSize, duressData.size)
                        val ct = FortressEngine.encryptChunk(duressData.copyOfRange(offset, end), dKeys, idx)
                        writeChunk(out, ct)
                        duressChunkCTs.add(ct)
                        offset = end; idx++
                    }
                    out.write(footerHMAC(dKeys.footerAuthKey, duressChunkCTs))
                }

                // Real chunks
                val realChunkCTs = mutableListOf<ByteArray>()
                val totalChunks = header.totalChunks
                BufferedInputStream(FileInputStream(inputFile)).use { inp ->
                    var chunkIdx = 0L
                    val buf = ByteArray(chunkSize)
                    while (true) {
                        val read = inp.readNBytes(buf, 0, chunkSize)
                        if (read == 0) break
                        progress?.invoke(chunkIdx.toDouble() / maxOf(totalChunks, 1), "Encrypting...")
                        val ct = FortressEngine.encryptChunk(buf.copyOfRange(0, read), keys, chunkIdx)
                        writeChunk(out, ct)
                        realChunkCTs.add(ct)
                        chunkIdx++
                    }
                }
                out.write(footerHMAC(keys.footerAuthKey, realChunkCTs))
            }

            progress?.invoke(1.0, "Done")
            return mapOf("inputSize" to fileSize, "chunks" to header.totalChunks,
                "trapsSet" to trapCount, "duressEnabled" to duressEnabled, "layers" to 6)
        } finally {
            keys.wipe()
            dKeys?.wipe()
        }
    }

    fun decryptFile(
        inputFile: File, outputFile: File, password: String,
        trapCodes: List<String>? = null,
        progress: ((Double, String) -> Unit)? = null
    ): Map<String, Any> {
        val header = DataInputStream(BufferedInputStream(FileInputStream(inputFile))).use {
            FortressHeader.parse(it)
        }

        // Step 1: Verify traps
        if (header.trapCount > 0) {
            if (trapCodes == null || trapCodes.size != header.trapCount) {
                scrambleHeader(inputFile)
                throw FortressException.TrapTriggered("Wrong number of trap codes. FILE DESTROYED.")
            }
            for ((i, code) in trapCodes.withIndex()) {
                if (!FortressKeyDerivation.verifyTrapCode(header.trapSalt, i, code, header.trapHashes[i])) {
                    scrambleHeader(inputFile)
                    throw FortressException.TrapTriggered("Trap code #${i+1} INCORRECT. FILE DESTROYED.")
                }
            }
        }

        // Step 2: Derive keys
        progress?.invoke(0.0, "Deriving keys...")
        val realKeys = FortressKeyDerivation.deriveKeys(password, header.salt, header.nonceSeed,
            SecurityLevel.STANDARD) // params from header override preset

        val isReal = FortressKeyDerivation.constantTimeEquals(realKeys.commitment, header.keyCommitment)

        // Always derive the duress keyset when duress is enabled, even if the
        // real password already matched. Deriving it only on a real-password
        // mismatch makes the real password ~2x faster to verify than any other
        // guess (one KDF pass vs. two), letting a coercion adversary confirm a
        // handed-over password is the genuine one from wall-clock timing alone —
        // defeating the duress deniability goal.
        var dKeys: FortressKeys? = null
        var duressMatch = false
        if (header.duressEnabled) {
            dKeys = FortressKeyDerivation.deriveKeys(password, header.duressSalt,
                header.duressNonceSeed, SecurityLevel.STANDARD)
            duressMatch = FortressKeyDerivation.constantTimeEquals(dKeys.commitment, header.duressKeyCommitment)
        }

        if (!isReal && duressMatch) {
            realKeys.wipe()
            val confirmedDuressKeys = dKeys!!
            return decryptDuress(inputFile, outputFile, header, confirmedDuressKeys, progress)
                .also { confirmedDuressKeys.wipe() }
        } else if (!isReal) {
            realKeys.wipe()
            dKeys?.wipe()
            throw FortressException.WrongPassword()
        }
        dKeys?.wipe()

        // Step 3: Decrypt real data
        try {
            DataInputStream(BufferedInputStream(FileInputStream(inputFile))).use { inp ->
                FortressHeader.parse(inp) // skip header

                // Skip duress section
                if (header.duressEnabled) {
                    repeat(header.duressChunkCount) { readChunk(inp) }
                    inp.skipFully(32) // duress footer
                }

                val chunkCTs = mutableListOf<ByteArray>()
                var bytesWritten = 0L

                BufferedOutputStream(FileOutputStream(outputFile)).use { out ->
                    for (i in 0 until header.totalChunks) {
                        progress?.invoke(i.toDouble() / header.totalChunks, "Decrypting...")
                        val ct = readChunk(inp) ?: throw FortressException.InvalidFile("EOF at chunk $i")
                        chunkCTs.add(ct)
                        val pt = FortressEngine.decryptChunk(ct, realKeys, i.toLong())
                        val remaining = header.originalSize - bytesWritten
                        val toWrite = minOf(pt.size.toLong(), remaining).toInt()
                        out.write(pt, 0, toWrite)
                        bytesWritten += toWrite
                    }
                }

                // Verify footer
                val storedFooter = ByteArray(32); inp.readFully(storedFooter)
                val expectedFooter = footerHMAC(realKeys.footerAuthKey, chunkCTs)
                if (!FortressKeyDerivation.constantTimeEquals(storedFooter, expectedFooter)) {
                    outputFile.delete()
                    throw FortressException.AuthFailed("Footer SHA3-256", 0, 0)
                }
            }
            progress?.invoke(1.0, "Done")
            return mapOf("originalSize" to header.originalSize, "bytesWritten" to header.originalSize,
                "chunks" to header.totalChunks, "duress" to false, "verified" to true)
        } finally {
            realKeys.wipe()
        }
    }

    private fun decryptDuress(
        inputFile: File, outputFile: File, header: FortressHeader,
        dKeys: FortressKeys, progress: ((Double, String) -> Unit)?
    ): Map<String, Any> {
        DataInputStream(BufferedInputStream(FileInputStream(inputFile))).use { inp ->
            FortressHeader.parse(inp)
            val chunkCTs = mutableListOf<ByteArray>()
            var bytesWritten = 0L

            BufferedOutputStream(FileOutputStream(outputFile)).use { out ->
                for (i in 0 until header.duressChunkCount) {
                    progress?.invoke(i.toDouble() / maxOf(header.duressChunkCount, 1), "Decrypting...")
                    val ct = readChunk(inp) ?: break
                    chunkCTs.add(ct)
                    val pt = FortressEngine.decryptChunk(ct, dKeys, i.toLong())
                    val remaining = header.duressDataSize - bytesWritten
                    val toWrite = minOf(pt.size.toLong(), remaining).toInt()
                    out.write(pt, 0, toWrite)
                    bytesWritten += toWrite
                }
            }

            val storedFooter = ByteArray(32); inp.readFully(storedFooter)
            val expectedFooter = footerHMAC(dKeys.footerAuthKey, chunkCTs)
            if (!FortressKeyDerivation.constantTimeEquals(storedFooter, expectedFooter)) {
                outputFile.delete()
                throw FortressException.AuthFailed("Duress Footer", 0, 0)
            }
        }

        // SILENTLY DESTROY REAL DATA
        progress?.invoke(0.9, "Finalizing...")
        scrambleRealData(inputFile, header)

        progress?.invoke(1.0, "Done")
        return mapOf("originalSize" to header.duressDataSize, "chunks" to header.duressChunkCount,
            "duress" to true, "verified" to true)
    }

    // ── Helpers ──────────────────────────────────────────────────

    private fun writeChunk(out: DataOutputStream, data: ByteArray) {
        val len = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(data.size).array()
        out.write(len); out.write(data)
    }

    private fun readChunk(inp: DataInputStream): ByteArray? {
        val lenBuf = ByteArray(4)
        if (inp.read(lenBuf) < 4) return null
        val len = ByteBuffer.wrap(lenBuf).order(ByteOrder.LITTLE_ENDIAN).int
        val data = ByteArray(len); inp.readFully(data)
        return data
    }

    private fun footerHMAC(key: ByteArray, chunks: List<ByteArray>): ByteArray {
        var input = "fortress-footer-chain-v2".toByteArray() + key
        for (ct in chunks) {
            input += ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(ct.size).array()
            input += ct
        }
        return FortressKeyDerivation.sha3_256(input)
    }

    private fun scrambleHeader(file: File) {
        RandomAccessFile(file, "rw").use { raf ->
            raf.seek(35) // past magic+version+mode+kdf_params
            val random = ByteArray(64); SecureRandom().nextBytes(random)
            raf.write(random) // salt + nonce_seed
            raf.seek(raf.filePointer + 12) // skip sizes
            val commitRandom = ByteArray(64); SecureRandom().nextBytes(commitRandom)
            raf.write(commitRandom)
            raf.fd.sync()
        }
    }

    /**
     * DESTRUCTIVE: overwrite the real data section with random bytes (duress activation).
     *
     * Computes the real-data start offset in a single parse pass, then overwrites
     * everything from that offset to EOF with cryptographic random, plus wipes the
     * real key commitment in the header.
     */
    private fun scrambleRealData(file: File, header: FortressHeader) {
        // Single pass: compute exact byte offset where real data begins.
        val headerSize = header.serialize().size + 32 // header bytes + HMAC-SHA256
        var duressSize = 0L
        DataInputStream(BufferedInputStream(FileInputStream(file))).use { inp ->
            inp.skipFully(headerSize)
            repeat(header.duressChunkCount) {
                val ct = readChunk(inp)
                duressSize += 4 + (ct?.size ?: 0) // 4-byte length prefix + chunk
            }
            if (header.duressEnabled) duressSize += 32 // duress footer HMAC
        }
        val realStart = headerSize + duressSize

        RandomAccessFile(file, "rw").use { raf ->
            val secRandom = SecureRandom()
            val buf = ByteArray(1_048_576)

            // Overwrite real data section [realStart, EOF) with random
            raf.seek(realStart)
            var remaining = raf.length() - realStart
            while (remaining > 0) {
                val block = minOf(remaining, buf.size.toLong()).toInt()
                secRandom.nextBytes(buf)
                raf.write(buf, 0, block)
                remaining -= block
            }

            // Wipe the real key commitment in the header (64 bytes)
            // Offset: magic(8)+version(2)+mode(1)+argon2(12)+scrypt(12)+salt(32)+nonce(32)
            //         +origSize(8)+chunkSize(4) = 111
            val commitmentOffset = 8 + 2 + 1 + 12 + 12 + 32 + 32 + 8 + 4
            val commitRandom = ByteArray(64)
            secRandom.nextBytes(commitRandom)
            raf.seek(commitmentOffset.toLong())
            raf.write(commitRandom)

            raf.fd.sync()
        }
    }
}

// ── DataOutputStream LE extensions ──────────────────────────────

fun DataOutputStream.writeLE16(v: Int) = write(ByteBuffer.allocate(2).order(ByteOrder.LITTLE_ENDIAN).putShort(v.toShort()).array())
fun DataOutputStream.writeLE32(v: Int) = write(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(v).array())
fun DataOutputStream.writeLE64(v: Long) = write(ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(v).array())
fun DataInputStream.readLE16(): Int { val b = ByteArray(2); readFully(b); return ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN).short.toInt() }
fun DataInputStream.readLE32(): Int { val b = ByteArray(4); readFully(b); return ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN).int }
fun DataInputStream.readLE64(): Long { val b = ByteArray(8); readFully(b); return ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN).long }

/**
 * Skip exactly [n] bytes, reading fully. Replaces single-arg readNBytes(n)
 * which requires API 33+ — this works on minSdk 28.
 */
fun DataInputStream.skipFully(n: Int) {
    val buf = ByteArray(n)
    readFully(buf)
}

/**
 * Read exactly [n] bytes or throw. Works on all API levels (unlike readNBytes(int)).
 */
fun DataInputStream.readExactly(n: Int): ByteArray {
    val buf = ByteArray(n)
    readFully(buf)
    return buf
}
