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

import org.bouncycastle.crypto.generators.SCrypt
import org.bouncycastle.jcajce.provider.digest.SHA3
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

// ═══════════════════════════════════════════════════════════════
//  SECURITY LEVELS
// ═══════════════════════════════════════════════════════════════

enum class SecurityLevel(
    val displayName: String,
    val argon2Time: Int, val argon2Memory: Int, val argon2Parallelism: Int,
    val scryptN: Int, val scryptR: Int, val scryptP: Int
) {
    STANDARD("Standard (256 MB)", 4, 131_072, 4, 1 shl 17, 8, 1),
    HIGH("High (1 GB)", 6, 524_288, 4, 1 shl 19, 8, 1),
    PARANOID("Paranoid (2 GB)", 10, 1_048_576, 8, 1 shl 20, 8, 2),
    FORTRESS("Fortress (4 GB)", 14, 2_097_152, 8, 1 shl 21, 8, 2);
}

// ═══════════════════════════════════════════════════════════════
//  DERIVED KEY CONTAINER
// ═══════════════════════════════════════════════════════════════

data class FortressKeys(
    val p1AesKey: ByteArray,       // 32 bytes
    val p1ChaChaKey: ByteArray,    // 32 bytes
    val p1CamelliaKey: ByteArray,  // 32 bytes
    val p1HmacKey: ByteArray,      // 32 bytes
    val p2AesKey: ByteArray,
    val p2ChaChaKey: ByteArray,
    val p2CamelliaKey: ByteArray,
    val p2HmacKey: ByteArray,
    val headerAuthKey: ByteArray,  // 32 bytes
    val footerAuthKey: ByteArray,  // 32 bytes
    val paddingKey: ByteArray,     // 32 bytes
    val nonceSeed: ByteArray,      // 32 bytes
    val commitment: ByteArray      // 64 bytes (SHA3-512)
) {
    fun wipe() {
        listOf(
            p1AesKey, p1ChaChaKey, p1CamelliaKey, p1HmacKey,
            p2AesKey, p2ChaChaKey, p2CamelliaKey, p2HmacKey,
            headerAuthKey, footerAuthKey, paddingKey, nonceSeed
        ).forEach { it.fill(0) }
    }
}

// ═══════════════════════════════════════════════════════════════
//  KEY DERIVATION — Argon2id → scrypt → HKDF-SHA512
// ═══════════════════════════════════════════════════════════════

object FortressKeyDerivation {

    const val SALT_SIZE = 32
    const val NONCE_SEED_SIZE = 32
    const val MASTER_KEY_SIZE = 64
    const val DERIVED_KEY_SIZE = 32
    const val MAX_TRAPS = 5
    const val TRAP_HASH_SIZE = 32

    private val secureRandom = SecureRandom()

    fun generateSalt(): ByteArray = ByteArray(SALT_SIZE).also { secureRandom.nextBytes(it) }
    fun generateNonceSeed(): ByteArray = ByteArray(NONCE_SEED_SIZE).also { secureRandom.nextBytes(it) }
    fun generateRandom(size: Int): ByteArray = ByteArray(size).also { secureRandom.nextBytes(it) }

    /**
     * Derive all encryption keys via triple-chained KDF.
     * Chain: Argon2id → scrypt (Bouncy Castle) → HKDF-SHA512
     */
    fun deriveKeys(
        password: String,
        salt: ByteArray,
        nonceSeed: ByteArray,
        level: SecurityLevel,
        kemSharedSecret: ByteArray? = null
    ): FortressKeys {
        val passwordBytes = password.toByteArray(Charsets.UTF_8)

        // ── Phase 1: Argon2id ────────────────────────────────────
        var phase1 = argon2id(
            password = passwordBytes, salt = salt,
            timeCost = level.argon2Time, memoryCost = level.argon2Memory,
            parallelism = level.argon2Parallelism, hashLength = MASTER_KEY_SIZE
        )

        // ── Hybrid PQ injection ──────────────────────────────────
        if (kemSharedSecret != null) {
            phase1 = hkdfDerive(
                ikm = phase1 + kemSharedSecret, salt = salt,
                info = "fortress-hybrid-pre-scrypt-v2".toByteArray(),
                length = MASTER_KEY_SIZE
            )
        }

        // ── Phase 2: scrypt (Bouncy Castle) ──────────────────────
        val scryptSalt = sha3_256("fortress-scrypt-salt-v2".toByteArray() + salt)
        val phase2 = SCrypt.generate(
            phase1, scryptSalt,
            level.scryptN, level.scryptR, level.scryptP, MASTER_KEY_SIZE
        )

        // ── Phase 3: XOR + HKDF-SHA512 ──────────────────────────
        val combined = ByteArray(MASTER_KEY_SIZE) { (phase1[it].toInt() xor phase2[it].toInt()).toByte() }
        val master = hkdfDerive(combined, salt, "fortress-master-key-v2".toByteArray(), MASTER_KEY_SIZE)

        // ── Derive all sub-keys ──────────────────────────────────
        val p1a = hkdfDerive(master, salt, "fortress-p1-aes256gcm-v2".toByteArray())
        val p1c = hkdfDerive(master, salt, "fortress-p1-chacha20poly1305-v2".toByteArray())
        val p1m = hkdfDerive(master, salt, "fortress-p1-camellia256cbc-v2".toByteArray())
        val p1h = hkdfDerive(master, salt, "fortress-p1-hmac-sha512-v2".toByteArray())
        val p2a = hkdfDerive(master, salt, "fortress-p2-aes256gcm-v2".toByteArray())
        val p2c = hkdfDerive(master, salt, "fortress-p2-chacha20poly1305-v2".toByteArray())
        val p2m = hkdfDerive(master, salt, "fortress-p2-camellia256cbc-v2".toByteArray())
        val p2h = hkdfDerive(master, salt, "fortress-p2-hmac-sha512-v2".toByteArray())
        val hdr = hkdfDerive(master, salt, "fortress-header-auth-sha256-v2".toByteArray())
        val ftr = hkdfDerive(master, salt, "fortress-footer-auth-sha3-256-v2".toByteArray())
        val pad = hkdfDerive(master, salt, "fortress-padding-key-v2".toByteArray())

        val allKeys = p1a + p1c + p1m + p1h + p2a + p2c + p2m + p2h + hdr + ftr
        val commitment = sha3_512("fortress-key-commitment-v2".toByteArray() + allKeys)

        return FortressKeys(
            p1AesKey = p1a, p1ChaChaKey = p1c, p1CamelliaKey = p1m, p1HmacKey = p1h,
            p2AesKey = p2a, p2ChaChaKey = p2c, p2CamelliaKey = p2m, p2HmacKey = p2h,
            headerAuthKey = hdr, footerAuthKey = ftr, paddingKey = pad,
            nonceSeed = nonceSeed, commitment = commitment
        )
    }

    // ── Chunk nonce derivation ───────────────────────────────────

    data class ChunkNonces(val aesNonce: ByteArray, val chachaNonce: ByteArray, val camelliaIV: ByteArray)

    fun deriveChunkNonces(nonceSeed: ByteArray, chunkIndex: Long, cascadePass: Int): ChunkNonces {
        val ctx = ByteBuffer.allocate(12).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(chunkIndex).putInt(cascadePass).array()

        return ChunkNonces(
            aesNonce = hkdfDerive(nonceSeed, ctx, "fortress-aes-nonce".toByteArray(), 12),
            chachaNonce = hkdfDerive(nonceSeed, ctx, "fortress-chacha-nonce".toByteArray(), 12),
            camelliaIV = hkdfDerive(nonceSeed, ctx, "fortress-camellia-iv".toByteArray(), 16)
        )
    }

    fun derivePaddingLength(paddingKey: ByteArray, chunkIndex: Long, minPad: Int = 256, maxPad: Int = 4096): Int {
        val ctx = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(chunkIndex).array()
        val raw = hkdfDerive(paddingKey, ctx, "fortress-pad-len".toByteArray(), 4)
        val value = ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
        return minPad + (value % (maxPad - minPad + 1)).toInt()
    }

    // ── Trap sequence ────────────────────────────────────────────

    fun hashTrapCode(trapSalt: ByteArray, index: Int, code: String): ByteArray {
        val input = trapSalt +
            ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(index).array() +
            code.toByteArray(Charsets.UTF_8)
        return sha3_256(input)
    }

    fun generateTrapHashes(trapSalt: ByteArray, codes: List<String>): List<ByteArray> =
        codes.mapIndexed { i, code -> hashTrapCode(trapSalt, i, code) }

    fun verifyTrapCode(trapSalt: ByteArray, index: Int, code: String, expectedHash: ByteArray): Boolean =
        constantTimeEquals(hashTrapCode(trapSalt, index, code), expectedHash)

    /**
     * Constant-time byte array comparison to prevent timing side-channel attacks.
     * Uses java.security.MessageDigest.isEqual which is constant-time on modern JVMs.
     */
    fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean =
        java.security.MessageDigest.isEqual(a, b)

    // ═══════════════════════════════════════════════════════════
    //  CRYPTO PRIMITIVES
    // ═══════════════════════════════════════════════════════════

    /**
     * Argon2id via argon2kt library.
     * Integration: com.lambdapioneer.argon2kt:argon2kt
     */
    private fun argon2id(
        password: ByteArray, salt: ByteArray,
        timeCost: Int, memoryCost: Int, parallelism: Int, hashLength: Int
    ): ByteArray {
        val argon2 = com.lambdapioneer.argon2kt.Argon2Kt()
        val result = argon2.hash(
            mode = com.lambdapioneer.argon2kt.Argon2Mode.ARGON2_ID,
            password = password,
            salt = salt,
            tCostInIterations = timeCost,
            mCostInKibibytes = memoryCost,
            parallelism = parallelism,
            hashLengthInBytes = hashLength
        )
        return result.rawHashAsByteArray()
    }

    /**
     * HKDF-SHA512 (RFC 5869) — implemented with javax.crypto.Mac
     * No external dependencies needed.
     */
    fun hkdfDerive(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int = DERIVED_KEY_SIZE): ByteArray {
        // Extract
        val prk = hmacSHA512(if (salt.isEmpty()) ByteArray(64) else salt, ikm)

        // Expand
        val hashLen = 64 // SHA-512 output size
        val n = (length + hashLen - 1) / hashLen
        var okm = ByteArray(0)
        var t = ByteArray(0)

        for (i in 1..n) {
            val input = t + info + byteArrayOf(i.toByte())
            t = hmacSHA512(prk, input)
            okm += t
        }

        return okm.copyOfRange(0, length)
    }

    fun hmacSHA512(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA512")
        mac.init(SecretKeySpec(key, "HmacSHA512"))
        return mac.doFinal(data)
    }

    fun hmacSHA256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    /** SHA3-256 via Bouncy Castle */
    fun sha3_256(data: ByteArray): ByteArray {
        val digest = SHA3.Digest256()
        return digest.digest(data)
    }

    /** SHA3-512 via Bouncy Castle */
    fun sha3_512(data: ByteArray): ByteArray {
        val digest = SHA3.Digest512()
        return digest.digest(data)
    }
}
