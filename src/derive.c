/*
 * derive.c --- all key derivations in one place, so the exact transcript each
 * one binds is auditable in a handful of lines.
 *
 * Threat-relevant properties:
 *   - The pairing code binds (S, epoch, nonce): it rotates every boot, so a
 *     code harvested in a warehouse cannot be used against a later boot.
 *   - K_dev binds S and the grant hash, so it is unique per device *and* per
 *     claim, and differs between a device and any clone that lacks S.
 *   - The blob key needs the X25519 shared secret (buyer_priv + device
 *     ephemeral) AND the grant hash AND the live code. An attacker who has the
 *     grant but not buyer_priv, or not the code, cannot open the blob.
 *   - The receipt proves knowledge of K_dev and binds the exact grant bytes,
 *     so the device only burns S after the purchaser really has K_dev.
 */

#include <string.h>

#include "ocm_internal.h"

void ocm_derive_x(const uint8_t secret[OCM_SECRET_LEN],
                  uint8_t x[OCM_KEY_LEN])
{
    /* Zero salt; domain-separated info. */
    static const uint8_t zero[32] = {0};
    ocm_hkdf_sha256(x, OCM_KEY_LEN,
                    secret, OCM_SECRET_LEN,
                    zero, sizeof zero,
                    (const uint8_t *)OCM_DOM_X25519, sizeof OCM_DOM_X25519 - 1);
}

void ocm_derive_code(const uint8_t secret[OCM_SECRET_LEN], uint16_t epoch,
                     const uint8_t nonce[OCM_SESS_NONCE_LEN],
                     uint8_t raw[OCM_CODE_BYTES])
{
    uint8_t msg[sizeof OCM_DOM_CODE - 1 + 2 + OCM_SESS_NONCE_LEN];
    uint8_t mac[32];
    size_t off = 0;

    memcpy(msg + off, OCM_DOM_CODE, sizeof OCM_DOM_CODE - 1);
    off += sizeof OCM_DOM_CODE - 1;
    ocm_wr16(msg + off, epoch); off += 2;
    memcpy(msg + off, nonce, OCM_SESS_NONCE_LEN); off += OCM_SESS_NONCE_LEN;

    ocm_hmac_sha256(mac, secret, OCM_SECRET_LEN, msg, off);
    memcpy(raw, mac, OCM_CODE_BYTES);
    ocm_secure_zero(mac, sizeof mac);
}

void ocm_derive_kdev(const uint8_t secret[OCM_SECRET_LEN],
                     const uint8_t gh[32], uint8_t out[OCM_KEY_LEN])
{
    /* S is the IKM, the grant hash is the salt: K_dev is unique per device
     * AND per claim, and cannot be computed from the grant alone. */
    ocm_hkdf_sha256(out, OCM_KEY_LEN,
                    secret, OCM_SECRET_LEN,
                    gh, 32,
                    (const uint8_t *)OCM_DOM_KDEV, sizeof OCM_DOM_KDEV - 1);
}

void ocm_derive_blobkey(const uint8_t shared[OCM_KEY_LEN],
                        const uint8_t gh[32],
                        const uint8_t code_raw[OCM_CODE_BYTES],
                        uint8_t out[OCM_KEY_LEN])
{
    /* IKM = shared || code ; salt = grant hash ; info = domain. */
    uint8_t ikm[OCM_KEY_LEN + OCM_CODE_BYTES];
    memcpy(ikm, shared, OCM_KEY_LEN);
    memcpy(ikm + OCM_KEY_LEN, code_raw, OCM_CODE_BYTES);
    ocm_hkdf_sha256(out, OCM_KEY_LEN,
                    ikm, sizeof ikm,
                    gh, 32,
                    (const uint8_t *)OCM_DOM_BLOB, sizeof OCM_DOM_BLOB - 1);
    ocm_secure_zero(ikm, sizeof ikm);
}

void ocm_derive_receipt(const uint8_t kdev[OCM_SECRET_LEN],
                        const uint8_t gh[32], uint8_t out[32])
{
    uint8_t msg[sizeof OCM_DOM_RECEIPT - 1 + 32];
    memcpy(msg, OCM_DOM_RECEIPT, sizeof OCM_DOM_RECEIPT - 1);
    memcpy(msg + sizeof OCM_DOM_RECEIPT - 1, gh, 32);
    ocm_hmac_sha256(out, kdev, OCM_SECRET_LEN, msg, sizeof msg);
}

void ocm_grant_hash(const ocm_grant_t *g, uint8_t out[32])
{
    uint8_t sb[OCM_GRANT_SIGNED_LEN];
    ocm_grant_signed_bytes(g, sb);
    ocm_sha256(out, sb, sizeof sb);
}

void ocm_blob_aad(const ocm_blob_t *b, uint8_t out[OCM_BLOB_AAD_LEN])
{
    out[0] = OCM_VERSION;
    memcpy(out + 1, b->boot_epoch, 2);
    memcpy(out + 3, b->counter, 4);
    memcpy(out + 7, b->device_id, 16);
    memcpy(out + 23, b->eph_pub, OCM_KEY_LEN);
    memcpy(out + 55, b->nonce, OCM_NONCE_LEN);
}
