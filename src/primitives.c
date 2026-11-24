/*
 * primitives.c --- the whole porting surface, implemented with libsodium.
 *
 * To port to a real firmware, replace this file with implementations on
 * mbedTLS / WolfSSL / the SoC's PSA Crypto: X25519, SHA-256, HKDF, HMAC,
 * ChaCha20-Poly1305 and Ed25519 verify. Nothing else in OCM touches crypto.
 */

#include <string.h>

#include <sodium.h>

#include "ocm.h"

int ocm_init(void)
{
    return sodium_init() < 0 ? -1 : 0;
}

int ocm_random(uint8_t *out, size_t len)
{
    if (!out && len) return -1;
    randombytes_buf(out, len);
    return 0;
}

void ocm_sha256(uint8_t out[32], const uint8_t *data, size_t len)
{
    crypto_hash_sha256(out, data, (unsigned long long)len);
}

int ocm_hkdf_sha256(uint8_t *out, size_t out_len,
                    const uint8_t *ikm, size_t ikm_len,
                    const uint8_t *salt, size_t salt_len,
                    const uint8_t *info, size_t info_len)
{
    uint8_t prk[crypto_kdf_hkdf_sha256_KEYBYTES];
    int rc;

    if (!out || out_len == 0 || out_len > crypto_kdf_hkdf_sha256_BYTES_MAX)
        return -1;
    if (crypto_kdf_hkdf_sha256_extract(prk, salt, salt_len, ikm, ikm_len) != 0)
        return -1;
    rc = crypto_kdf_hkdf_sha256_expand(out, out_len,
                                       (const char *)info, info_len, prk);
    ocm_secure_zero(prk, sizeof prk);
    return rc == 0 ? 0 : -1;
}

void ocm_hmac_sha256(uint8_t out[32],
                     const uint8_t *key, size_t key_len,
                     const uint8_t *data, size_t data_len)
{
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, key, key_len);
    crypto_auth_hmacsha256_update(&st, data, (unsigned long long)data_len);
    crypto_auth_hmacsha256_final(&st, out);
}

int ocm_x25519(uint8_t out[OCM_KEY_LEN],
               const uint8_t scalar[OCM_KEY_LEN],
               const uint8_t point[OCM_KEY_LEN])
{
    return crypto_scalarmult(out, scalar, point) == 0 ? 0 : -1;
}

int ocm_x25519_base(uint8_t out[OCM_KEY_LEN],
                    const uint8_t scalar[OCM_KEY_LEN])
{
    return crypto_scalarmult_base(out, scalar) == 0 ? 0 : -1;
}

int ocm_aead_seal(uint8_t *ct, uint8_t tag[OCM_TAG_LEN],
                  const uint8_t nonce[OCM_NONCE_LEN],
                  const uint8_t *aad, size_t aad_len,
                  const uint8_t *pt, size_t pt_len,
                  const uint8_t key[OCM_KEY_LEN])
{
    unsigned long long tag_len = 0;
    int rc = crypto_aead_chacha20poly1305_ietf_encrypt_detached(
        ct, tag, &tag_len, pt, (unsigned long long)pt_len,
        aad, (unsigned long long)aad_len, NULL, nonce, key);
    if (rc != 0 || tag_len != OCM_TAG_LEN)
        return -1;
    return 0;
}

int ocm_aead_open(uint8_t *pt,
                  const uint8_t tag[OCM_TAG_LEN],
                  const uint8_t nonce[OCM_NONCE_LEN],
                  const uint8_t *aad, size_t aad_len,
                  const uint8_t *ct, size_t ct_len,
                  const uint8_t key[OCM_KEY_LEN])
{
    return crypto_aead_chacha20poly1305_ietf_decrypt_detached(
               pt, NULL, ct, (unsigned long long)ct_len, tag,
               aad, (unsigned long long)aad_len, nonce, key) == 0 ? 0 : -1;
}

int ocm_ed25519_verify(const uint8_t sig[OCM_SIG_LEN],
                       const uint8_t *msg, size_t msg_len,
                       const uint8_t pk[OCM_KEY_LEN])
{
    return crypto_sign_verify_detached(sig, msg,
                                       (unsigned long long)msg_len, pk) == 0;
}

int ocm_ed25519_keypair(const uint8_t seed[OCM_KEY_LEN],
                        uint8_t pk[OCM_KEY_LEN],
                        uint8_t sk[OCM_SIG_LEN])
{
    return crypto_sign_seed_keypair(pk, sk, seed) == 0 ? 0 : -1;
}

int ocm_ed25519_sign(uint8_t sig[OCM_SIG_LEN],
                     const uint8_t *msg, size_t msg_len,
                     const uint8_t sk[OCM_SIG_LEN])
{
    unsigned long long sig_len = 0;
    return crypto_sign_detached(sig, &sig_len, msg,
                                (unsigned long long)msg_len, sk) == 0 ? 0 : -1;
}

int ocm_ct_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
    return sodium_memcmp(a, b, len) == 0;
}

void ocm_secure_zero(void *p, size_t len)
{
    sodium_memzero(p, len);
}
