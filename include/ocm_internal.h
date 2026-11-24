/*
 * ocm_internal.h --- private layout, encoders and helpers. Not public API.
 */

#ifndef OCM_INTERNAL_H
#define OCM_INTERNAL_H

#include "ocm.h"

#define OCM_VERSION 1u

/* Persistent record plaintext, sealed into OCM_RECORD_LEN bytes. */
#define OCM_REC_PT_LEN      45u  /* 1+2+4+32+1+1+4                         */
#define OCM_ST_FACTORY      0u
#define OCM_ST_COMMISSIONED 1u

typedef struct {
    uint8_t  ver;
    uint16_t epoch;
    uint32_t counter;
    uint8_t  secret[OCM_SECRET_LEN]; /* S while factory, K_dev once claimed */
    uint8_t  state;
    uint8_t  failures;
    uint32_t last_fail;
} ocm_record_t;

/* Domain-separation labels (NUL-terminated ASCII, used as HKDF info). */
#define OCM_DOM_X25519   "ocm/v1/x25519"
#define OCM_DOM_CODE     "ocm/v1/code"
#define OCM_DOM_REC      "ocm/v1/rec"
#define OCM_DOM_KDEV     "ocm/v1/kdev"
#define OCM_DOM_BLOB     "ocm/v1/blob"
#define OCM_DOM_RECEIPT  "ocm/v1/receipt"

static inline uint16_t ocm_rd16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}
static inline uint32_t ocm_rd32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}
static inline void ocm_wr16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v;
}
static inline void ocm_wr32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}

/* Exact bytes the service signs for a grant (OCM_GRANT_SIGNED_LEN). */
void ocm_grant_signed_bytes(const ocm_grant_t *g,
                            uint8_t out[OCM_GRANT_SIGNED_LEN]);

/* SHA-256 over the signed grant bytes; the binding hash both sides use. */
void ocm_grant_hash(const ocm_grant_t *g, uint8_t out[32]);

/* Derive the per-boot pairing code raw bytes. */
void ocm_derive_code(const uint8_t secret[OCM_SECRET_LEN], uint16_t epoch,
                     const uint8_t nonce[OCM_SESS_NONCE_LEN],
                     uint8_t raw[OCM_CODE_BYTES]);

/* Derive the X25519 pairing private key from S. */
void ocm_derive_x(const uint8_t secret[OCM_SECRET_LEN],
                  uint8_t x[OCM_KEY_LEN]);

/* Derive K_dev from S and the grant hash. */
void ocm_derive_kdev(const uint8_t secret[OCM_SECRET_LEN],
                     const uint8_t gh[32], uint8_t out[OCM_KEY_LEN]);

/* Derive the blob AEAD key from the X25519 shared secret, grant hash, code. */
void ocm_derive_blobkey(const uint8_t shared[OCM_KEY_LEN],
                        const uint8_t gh[32],
                        const uint8_t code_raw[OCM_CODE_BYTES],
                        uint8_t out[OCM_KEY_LEN]);

/* Expected receipt from K_dev and the grant hash. */
void ocm_derive_receipt(const uint8_t kdev[OCM_SECRET_LEN],
                        const uint8_t gh[32], uint8_t out[32]);

/* AEAD associated data for a blob: its 67-byte cleartext header. */
#define OCM_BLOB_AAD_LEN 67u
void ocm_blob_aad(const ocm_blob_t *b, uint8_t out[OCM_BLOB_AAD_LEN]);

/* Sealed persistent record. Return: 1 found, 0 absent, <0 error. */
int ocm_record_load(ocm_storage_t *st, ocm_record_t *r);
int ocm_record_store(ocm_storage_t *st, const ocm_record_t *r);
int ocm_record_wipe(ocm_storage_t *st);
int ocm_record_exists(ocm_storage_t *st);

#endif /* OCM_INTERNAL_H */
