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
//  FortressCBridge.h — C wrappers for OpenSSL + Argon2
//
//  These functions bridge Swift to OpenSSL's Camellia, scrypt, and SHA3,
//  plus libargon2 for Argon2id.
//

#ifndef FortressCBridge_h
#define FortressCBridge_h

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ── Camellia-256-CBC ─────────────────────────────────────────

/// Encrypt with Camellia-256-CBC. Caller provides pre-padded input.
/// Returns bytes written to output, or -1 on error.
/// Output buffer must be at least inputLen + 16 bytes.
int fortress_camellia_encrypt(
    const uint8_t *input, int inputLen,
    const uint8_t *key,    // 32 bytes
    const uint8_t *iv,     // 16 bytes
    uint8_t *output, int *outputLen
);

/// Decrypt Camellia-256-CBC. Returns plaintext length, or -1 on error.
int fortress_camellia_decrypt(
    const uint8_t *input, int inputLen,
    const uint8_t *key,
    const uint8_t *iv,
    uint8_t *output, int *outputLen
);

// ── scrypt ───────────────────────────────────────────────────

/// scrypt key derivation via OpenSSL EVP_PBE_scrypt.
/// Returns 0 on success, -1 on error.
int fortress_scrypt(
    const uint8_t *password, size_t passwordLen,
    const uint8_t *salt, size_t saltLen,
    uint64_t N, uint32_t r, uint32_t p,
    uint8_t *output, size_t outputLen
);

// ── SHA3 ─────────────────────────────────────────────────────

/// SHA3-256 hash. Output must be 32 bytes.
void fortress_sha3_256(const uint8_t *input, size_t inputLen, uint8_t *output);

/// SHA3-512 hash. Output must be 64 bytes.
void fortress_sha3_512(const uint8_t *input, size_t inputLen, uint8_t *output);

// ── Argon2id ─────────────────────────────────────────────────

/// Argon2id hash. Returns 0 on success, non-zero on error.
int fortress_argon2id(
    const uint8_t *password, size_t passwordLen,
    const uint8_t *salt, size_t saltLen,
    uint32_t timeCost, uint32_t memoryCost, uint32_t parallelism,
    uint8_t *output, size_t outputLen
);

#ifdef __cplusplus
}
#endif

#endif
