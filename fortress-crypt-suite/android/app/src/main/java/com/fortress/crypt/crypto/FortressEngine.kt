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

import org.bouncycastle.crypto.engines.CamelliaEngine
import org.bouncycastle.crypto.modes.CBCBlockCipher
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher
import org.bouncycastle.crypto.paddings.PKCS7Padding
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Fortress Double-Cascade Encryption Engine — 6 LAYERS
 *
 * Pass 1: Camellia-256-CBC+HMAC → ChaCha20-Poly1305 → AES-256-GCM (key set 1)
 * Pass 2: Camellia-256-CBC+HMAC → ChaCha20-Poly1305 → AES-256-GCM (key set 2)
 */
object FortressEngine {

    const val DEFAULT_CHUNK_SIZE = 1_048_576 // 1 MB
    private const val GCM_TAG_BITS = 128
    private const val GCM_TAG_SIZE = 16
    private const val POLY1305_TAG_SIZE = 16
    private const val HMAC512_TAG_SIZE = 64

    private val secureRandom = SecureRandom()

    // ═══════════════════════════════════════════════════════════
    //  FULL CHUNK ENCRYPTION (DOUBLE CASCADE)
    // ═══════════════════════════════════════════════════════════

    fun encryptChunk(plaintext: ByteArray, keys: FortressKeys, chunkIndex: Long): ByteArray {
        // Anti-forensic random padding
        val padLen = FortressKeyDerivation.derivePaddingLength(keys.paddingKey, chunkIndex)
        val padding = ByteArray(padLen).also { secureRandom.nextBytes(it) }
        val padHeader = ByteBuffer.allocate(2).order(ByteOrder.LITTLE_ENDIAN).putShort(padLen.toShort()).array()
        val paddedPt = padHeader + padding + plaintext

        // Pass 1
        val afterPass1 = cascadeEncrypt(
            paddedPt, keys.p1AesKey, keys.p1ChaChaKey, keys.p1CamelliaKey, keys.p1HmacKey,
            keys.nonceSeed, chunkIndex, passNum = 1
        )

        // Pass 2
        return cascadeEncrypt(
            afterPass1, keys.p2AesKey, keys.p2ChaChaKey, keys.p2CamelliaKey, keys.p2HmacKey,
            keys.nonceSeed, chunkIndex, passNum = 2
        )
    }

    fun decryptChunk(encrypted: ByteArray, keys: FortressKeys, chunkIndex: Long): ByteArray {
        // Reverse Pass 2
        val afterPass1 = cascadeDecrypt(
            encrypted, keys.p2AesKey, keys.p2ChaChaKey, keys.p2CamelliaKey, keys.p2HmacKey,
            keys.nonceSeed, chunkIndex, passNum = 2
        )

        // Reverse Pass 1
        val paddedPt = cascadeDecrypt(
            afterPass1, keys.p1AesKey, keys.p1ChaChaKey, keys.p1CamelliaKey, keys.p1HmacKey,
            keys.nonceSeed, chunkIndex, passNum = 1
        )

        // Strip padding
        val padLen = ByteBuffer.wrap(paddedPt, 0, 2).order(ByteOrder.LITTLE_ENDIAN).short.toInt() and 0xFFFF
        return paddedPt.copyOfRange(2 + padLen, paddedPt.size)
    }

    // ═══════════════════════════════════════════════════════════
    //  SINGLE CASCADE
    // ═══════════════════════════════════════════════════════════

    private fun cascadeEncrypt(
        data: ByteArray, aesKey: ByteArray, chachaKey: ByteArray,
        camelliaKey: ByteArray, hmacKey: ByteArray,
        nonceSeed: ByteArray, chunkIndex: Long, passNum: Int
    ): ByteArray {
        val nonces = FortressKeyDerivation.deriveChunkNonces(nonceSeed, chunkIndex, passNum)

        val layer1 = camelliaEncrypt(data, camelliaKey, nonces.camelliaIV, hmacKey, chunkIndex, passNum)
        val layer2 = chaChaEncrypt(layer1, chachaKey, nonces.chachaNonce)
        return aesGcmEncrypt(layer2, aesKey, nonces.aesNonce)
    }

    private fun cascadeDecrypt(
        data: ByteArray, aesKey: ByteArray, chachaKey: ByteArray,
        camelliaKey: ByteArray, hmacKey: ByteArray,
        nonceSeed: ByteArray, chunkIndex: Long, passNum: Int
    ): ByteArray {
        val nonces = FortressKeyDerivation.deriveChunkNonces(nonceSeed, chunkIndex, passNum)

        val layer2 = aesGcmDecrypt(data, aesKey, nonces.aesNonce, chunkIndex, passNum)
        val layer1 = chaChaDecrypt(layer2, chachaKey, nonces.chachaNonce, chunkIndex, passNum)
        return camelliaDecrypt(layer1, camelliaKey, nonces.camelliaIV, hmacKey, chunkIndex, passNum)
    }

    // ═══════════════════════════════════════════════════════════
    //  AES-256-GCM (javax.crypto — native Android)
    // ═══════════════════════════════════════════════════════════

    private fun aesGcmEncrypt(plaintext: ByteArray, key: ByteArray, nonce: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, nonce))
        return cipher.doFinal(plaintext) // Returns ciphertext + 16-byte tag appended
    }

    private fun aesGcmDecrypt(data: ByteArray, key: ByteArray, nonce: ByteArray, chunk: Long, pass: Int): ByteArray {
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, nonce))
            return cipher.doFinal(data)
        } catch (e: Exception) {
            throw FortressException.AuthFailed("AES-256-GCM", chunk, pass)
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  ChaCha20-Poly1305 (javax.crypto — Android API 28+)
    // ═══════════════════════════════════════════════════════════

    private fun chaChaEncrypt(plaintext: ByteArray, key: ByteArray, nonce: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("ChaCha20-Poly1305")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
        return cipher.doFinal(plaintext) // Returns ciphertext + 16-byte tag
    }

    private fun chaChaDecrypt(data: ByteArray, key: ByteArray, nonce: ByteArray, chunk: Long, pass: Int): ByteArray {
        try {
            val cipher = Cipher.getInstance("ChaCha20-Poly1305")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
            return cipher.doFinal(data)
        } catch (e: Exception) {
            throw FortressException.AuthFailed("ChaCha20-Poly1305", chunk, pass)
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  Camellia-256-CBC + HMAC-SHA512 (Bouncy Castle)
    // ═══════════════════════════════════════════════════════════

    private fun camelliaEncrypt(
        plaintext: ByteArray, key: ByteArray, iv: ByteArray,
        hmacKey: ByteArray, chunkIndex: Long, passNum: Int
    ): ByteArray {
        // Bouncy Castle Camellia-256-CBC with PKCS7 padding
        val engine = CBCBlockCipher.newInstance(CamelliaEngine())
        val cipher = PaddedBufferedBlockCipher(engine, PKCS7Padding())
        cipher.init(true, ParametersWithIV(KeyParameter(key), iv))

        val output = ByteArray(cipher.getOutputSize(plaintext.size))
        var len = cipher.processBytes(plaintext, 0, plaintext.size, output, 0)
        len += cipher.doFinal(output, len)
        val ciphertext = output.copyOfRange(0, len)

        // HMAC-SHA512 (Encrypt-then-MAC)
        val authData = ByteBuffer.allocate(12).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(chunkIndex).putInt(passNum).array() + iv + ciphertext
        val tag = FortressKeyDerivation.hmacSHA512(hmacKey, authData)

        return ciphertext + tag
    }

    private fun camelliaDecrypt(
        data: ByteArray, key: ByteArray, iv: ByteArray,
        hmacKey: ByteArray, chunkIndex: Long, passNum: Int
    ): ByteArray {
        if (data.size < HMAC512_TAG_SIZE)
            throw FortressException.AuthFailed("Camellia", chunkIndex.toLong(), passNum)

        val ciphertext = data.copyOfRange(0, data.size - HMAC512_TAG_SIZE)
        val receivedTag = data.copyOfRange(data.size - HMAC512_TAG_SIZE, data.size)

        // Verify HMAC
        val authData = ByteBuffer.allocate(12).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(chunkIndex).putInt(passNum).array() + iv + ciphertext
        val expectedTag = FortressKeyDerivation.hmacSHA512(hmacKey, authData)

        if (!FortressKeyDerivation.constantTimeEquals(receivedTag, expectedTag))
            throw FortressException.AuthFailed("Camellia HMAC-SHA512", chunkIndex, passNum)

        // Decrypt
        val engine = CBCBlockCipher.newInstance(CamelliaEngine())
        val cipher = PaddedBufferedBlockCipher(engine, PKCS7Padding())
        cipher.init(false, ParametersWithIV(KeyParameter(key), iv))

        val output = ByteArray(cipher.getOutputSize(ciphertext.size))
        var len = cipher.processBytes(ciphertext, 0, ciphertext.size, output, 0)
        len += cipher.doFinal(output, len)
        return output.copyOfRange(0, len)
    }
}

// ═══════════════════════════════════════════════════════════════
//  EXCEPTIONS
// ═══════════════════════════════════════════════════════════════

sealed class FortressException(message: String) : Exception(message) {
    class AuthFailed(cipher: String, chunk: Long, pass: Int) :
        FortressException("$cipher authentication FAILED [chunk=$chunk, pass=$pass]")
    class TrapTriggered(msg: String) :
        FortressException("TRAP TRIGGERED: $msg")
    class InvalidFile(msg: String) :
        FortressException("Invalid file: $msg")
    class WrongPassword :
        FortressException("KEY COMMITMENT MISMATCH — wrong password")
}
