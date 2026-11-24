# Porting the crypto layer

The reference build uses libsodium. On a real camera SoC you will almost
certainly use the platform's crypto library (mbedTLS, WolfSSL, or PSA Crypto
on top of a secure element). **You port exactly one file: `src/primitives.c`.**
Nothing else in OCM calls a crypto routine directly; `src/derive.c`,
`src/store.c`, `src/core.c`, and `src/buyer.c` only call the `ocm_*` functions
declared in `include/ocm.h`.

## The surface

Implement these, each in a handful of lines:

```c
int  ocm_init(void);
int  ocm_random(uint8_t *out, size_t len);
void ocm_sha256(uint8_t out[32], const uint8_t *data, size_t len);
int  ocm_hkdf_sha256(uint8_t *out, size_t out_len, const uint8_t *ikm, size_t ikm_len,
                     const uint8_t *salt, size_t salt_len,
                     const uint8_t *info, size_t info_len);
void ocm_hmac_sha256(uint8_t out[32], const uint8_t *key, size_t key_len,
                     const uint8_t *data, size_t data_len);
int  ocm_x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]);
int  ocm_x25519_base(uint8_t out[32], const uint8_t scalar[32]);
int  ocm_aead_seal(uint8_t *ct, uint8_t tag[16], const uint8_t nonce[12],
                   const uint8_t *aad, size_t aad_len,
                   const uint8_t *pt, size_t pt_len, const uint8_t key[32]);
int  ocm_aead_open(uint8_t *pt, const uint8_t tag[16], const uint8_t nonce[12],
                   const uint8_t *aad, size_t aad_len,
                   const uint8_t *ct, size_t ct_len, const uint8_t key[32]);
int  ocm_ed25519_verify(const uint8_t sig[64], const uint8_t *msg, size_t len,
                        const uint8_t pk[32]);
int  ocm_ct_equal(const uint8_t *a, const uint8_t *b, size_t len);
void ocm_secure_zero(void *p, size_t len);
```

`ocm_ed25519_keypair`, `ocm_ed25519_sign`, `ocm_service_keygen`, and
`ocm_service_sign_grant` are **cloud-side only**. A device build may define them
as stubs returning an error, or simply not link them; a device never signs.

## mbedTLS sketch

```c
int ocm_x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32])
{
    mbedtls_ecdh_context ctx;
    mbedtls_ecdh_init(&ctx);
    int rc = mbedtls_ecdh_setup(&ctx, MBEDTLS_ECP_DP_CURVE25519);
    if (rc == 0)
        rc = mbedtls_ecdh_compute_shared(&ctx, out, /*peer*/ &point_mp, /*own*/ &scalar_mp, ...);
    mbedtls_ecdh_free(&ctx);
    return rc == 0 ? 0 : -1;
}
```

(`MBEDTLS_ECP_DP_CURVE25519` gives Montgomery multiplication; use
`mbedtls_ecdh` throughout for X25519. For AEAD use
`mbedtls_chachapoly_encrypt_and_tag` / `..._auth_decrypt` with
`MBEDTLS_CHACHAPOLY_AEAD` mode, and for Ed25519 use `mbedtls_ecdsa` is *not*
Ed25519 — either enable mbedTLS 3.x EdDSA support or use a small vendored
Ed25519. PSA Crypto has `psa_verify_message` with
`PSA_ALG_PURE_EDDSA`.)

## PSA Crypto sketch

If the SoC has a secure element exposing PSA, this is the cleanest route: keys
never enter normal RAM, and `psa_export_public_key` gives you `P` without the
scalar ever leaving the element.

```c
psa_status_t st = psa_crypto_init();
psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
psa_set_key_type(&a, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
psa_set_key_usage_flags(&a, PSA_KEY_USAGE_DERIVE);
/* psa_generate_key -> S lives in the element */
/* psa_key_derivation with PSA_ALG_HKDF(PSA_ALG_SHA_256) for HKDF */
/* psa_aead_encrypt with PSA_ALG_CHACHA20_POLY1305 for blob/record */
/* psa_verify_message with PSA_ALG_PURE_EDDSA for grants */
```

## RNG

`ocm_random` **must** be the hardware RNG (or a DRBG seeded from it). Never fall
back to a software PRNG. If the RNG is unavailable, return non-zero; the core
propagates that to `OCM_E_IO` and refuses to provision (`provision_fails_closed`).
This is a deliberate, audit-friendly refusal to ever create a guessable secret.

## The storage HAL

You also implement `ocm_storage_t` (see `include/ocm.h` and `sim/storage_mock.c`
for a model). On real silicon:

- `load` / `store` / `wipe` → the platform NVS, encrypted with a key from the
  keystore. `store` must be power-fail atomic (journal or double-buffer).
- `device_id` → eFuse / OTP serial, 16 bytes. Public.
- `root_key` → a 32-byte key only this chip can obtain (HUK, eFuse-derived
  KEK, or secure-element key). **Must not** be derivable from `device_id`.
- `now_s` → RTC or, failing that, the time from the phone during pairing. A
  wrong clock only weakens back-off/expiry; it cannot leak a secret.

## Verify the port

Run the suite against your primitives:

```
make test         # links your primitives.c instead of libsodium's
```

The tests are written against the public API and the mock HAL, so they run
unchanged against a port. In particular the fuzz-style and tamper tests catch
the mistakes ports commonly make (wrong AEAD mode, mutable tag, non-constant-time
compare).
