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

//
//  FortressCBridge.c — OpenSSL + Argon2 implementations
//
//  Link against: libssl, libcrypto, libargon2
//  For iOS, use the OpenSSL-Universal CocoaPod or compile OpenSSL for iOS.
//  For Argon2, use the reference C implementation: https://github.com/P-H-C/phc-winner-argon2
//

#include "FortressCBridge.h"
#include <string.h>

// ── OpenSSL headers ──────────────────────────────────────────
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/err.h>

// ── Argon2 header ────────────────────────────────────────────
// From: https://github.com/P-H-C/phc-winner-argon2
#include <argon2.h>

// ═══════════════════════════════════════════════════════════════
//  Camellia-256-CBC
// ═══════════════════════════════════════════════════════════════

int fortress_camellia_encrypt(
    const uint8_t *input, int inputLen,
    const uint8_t *key, const uint8_t *iv,
    uint8_t *output, int *outputLen
) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int len = 0, totalLen = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_camellia_256_cbc(), NULL, key, iv) != 1) goto err;
    // We handle PKCS7 padding in Swift — disable OpenSSL padding
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    if (EVP_EncryptUpdate(ctx, output, &len, input, inputLen) != 1) goto err;
    totalLen = len;

    if (EVP_EncryptFinal_ex(ctx, output + len, &len) != 1) goto err;
    totalLen += len;

    *outputLen = totalLen;
    EVP_CIPHER_CTX_free(ctx);
    return 0;

err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

int fortress_camellia_decrypt(
    const uint8_t *input, int inputLen,
    const uint8_t *key, const uint8_t *iv,
    uint8_t *output, int *outputLen
) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int len = 0, totalLen = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_camellia_256_cbc(), NULL, key, iv) != 1) goto err;
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    if (EVP_DecryptUpdate(ctx, output, &len, input, inputLen) != 1) goto err;
    totalLen = len;

    if (EVP_DecryptFinal_ex(ctx, output + len, &len) != 1) goto err;
    totalLen += len;

    *outputLen = totalLen;
    EVP_CIPHER_CTX_free(ctx);
    return 0;

err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

// ═══════════════════════════════════════════════════════════════
//  scrypt
// ═══════════════════════════════════════════════════════════════

int fortress_scrypt(
    const uint8_t *password, size_t passwordLen,
    const uint8_t *salt, size_t saltLen,
    uint64_t N, uint32_t r, uint32_t p,
    uint8_t *output, size_t outputLen
) {
    int result = EVP_PBE_scrypt(
        (const char *)password, passwordLen,
        salt, saltLen,
        N, r, p,
        0, // maxmem (0 = no limit)
        output, outputLen
    );
    return (result == 1) ? 0 : -1;
}

// ═══════════════════════════════════════════════════════════════
//  SHA3
// ═══════════════════════════════════════════════════════════════

void fortress_sha3_256(const uint8_t *input, size_t inputLen, uint8_t *output) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int len = 32;
    EVP_DigestInit_ex(ctx, EVP_sha3_256(), NULL);
    EVP_DigestUpdate(ctx, input, inputLen);
    EVP_DigestFinal_ex(ctx, output, &len);
    EVP_MD_CTX_free(ctx);
}

void fortress_sha3_512(const uint8_t *input, size_t inputLen, uint8_t *output) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int len = 64;
    EVP_DigestInit_ex(ctx, EVP_sha3_512(), NULL);
    EVP_DigestUpdate(ctx, input, inputLen);
    EVP_DigestFinal_ex(ctx, output, &len);
    EVP_MD_CTX_free(ctx);
}

// ═══════════════════════════════════════════════════════════════
//  Argon2id
// ═══════════════════════════════════════════════════════════════

int fortress_argon2id(
    const uint8_t *password, size_t passwordLen,
    const uint8_t *salt, size_t saltLen,
    uint32_t timeCost, uint32_t memoryCost, uint32_t parallelism,
    uint8_t *output, size_t outputLen
) {
    return argon2id_hash_raw(
        timeCost, memoryCost, parallelism,
        password, passwordLen,
        salt, saltLen,
        output, outputLen
    );
}
