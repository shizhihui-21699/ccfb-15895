/*
 * store.c --- the 73-byte persistent record.
 *
 * On-flash layout:  nonce(12) || ciphertext(45) || tag(16)
 *   sealed with ChaCha20-Poly1305 under
 *       K_rec = HKDF(root_key, salt = device_id, info = "ocm/v1/rec")
 *
 * root_key comes from the chip's protected keystore, so an attacker with a
 * dump of the flash (but not the chip's root key) sees only ciphertext. The
 * store is authenticated, so tampering is detected (load returns < 0) rather
 * than silently used.
 */

#include <string.h>

#include "ocm_internal.h"

static int rec_key(ocm_storage_t *st, uint8_t out[OCM_KEY_LEN])
{
    uint8_t root[OCM_KEY_LEN], id[16];

    if (!st->root_key || !st->device_id)
        return -1;
    if (st->root_key(st->ctx, root) != 0)
        return -1;
    if (st->device_id(st->ctx, id) != 0) {
        ocm_secure_zero(root, sizeof root);
        return -1;
    }
    int rc = ocm_hkdf_sha256(out, OCM_KEY_LEN,
                             root, sizeof root,
                             id, sizeof id,
                             (const uint8_t *)OCM_DOM_REC,
                             sizeof OCM_DOM_REC - 1);
    ocm_secure_zero(root, sizeof root);
    return rc;
}

static void rec_serialize(const ocm_record_t *r, uint8_t pt[OCM_REC_PT_LEN])
{
    pt[0] = r->ver;
    ocm_wr16(pt + 1, r->epoch);
    ocm_wr32(pt + 3, r->counter);
    memcpy(pt + 7, r->secret, OCM_SECRET_LEN);
    pt[39] = r->state;
    pt[40] = r->failures;
    ocm_wr32(pt + 41, r->last_fail);
}

static void rec_parse(ocm_record_t *r, const uint8_t pt[OCM_REC_PT_LEN])
{
    r->ver = pt[0];
    r->epoch = ocm_rd16(pt + 1);
    r->counter = ocm_rd32(pt + 3);
    memcpy(r->secret, pt + 7, OCM_SECRET_LEN);
    r->state = pt[39];
    r->failures = pt[40];
    r->last_fail = ocm_rd32(pt + 41);
}

int ocm_record_exists(ocm_storage_t *st)
{
    uint8_t buf[OCM_RECORD_LEN];
    if (!st || !st->load)
        return 0;
    return st->load(st->ctx, buf) == 1 ? 1 : 0;
}

int ocm_record_load(ocm_storage_t *st, ocm_record_t *r)
{
    uint8_t buf[OCM_RECORD_LEN], key[OCM_KEY_LEN], pt[OCM_REC_PT_LEN];
    int got, rc = -1;

    if (!st || !st->load || !r)
        return -1;
    got = st->load(st->ctx, buf);
    if (got == 0)
        return 0;
    if (got != 1)
        return -1;
    if (rec_key(st, key) != 0)
        return -1;
    if (ocm_aead_open(pt, buf + 12 + OCM_REC_PT_LEN, buf, NULL, 0,
                      buf + 12, OCM_REC_PT_LEN, key) != 0)
        goto out;                     /* wrong key or tampered */
    rec_parse(r, pt);
    if (r->ver != OCM_VERSION)
        goto out;
    if (r->state != OCM_ST_FACTORY && r->state != OCM_ST_COMMISSIONED)
        goto out;
    rc = 1;
out:
    ocm_secure_zero(key, sizeof key);
    ocm_secure_zero(pt, sizeof pt);
    /* Do not leave decrypted material in the caller's stack if we failed. */
    if (rc != 1)
        ocm_secure_zero(r, sizeof *r);
    return rc;
}

int ocm_record_store(ocm_storage_t *st, const ocm_record_t *r)
{
    uint8_t buf[OCM_RECORD_LEN], key[OCM_KEY_LEN], pt[OCM_REC_PT_LEN];
    int rc = -1;

    if (!st || !st->store || !r)
        return -1;
    if (rec_key(st, key) != 0)
        return -1;
    if (ocm_random(buf, 12) != 0)           /* fresh nonce every write */
        goto out;
    rec_serialize(r, pt);
    if (ocm_aead_seal(buf + 12, buf + 12 + OCM_REC_PT_LEN, buf, NULL, 0,
                      pt, OCM_REC_PT_LEN, key) != 0)
        goto out;
    if (st->store(st->ctx, buf) != 0)
        goto out;
    rc = 0;
out:
    ocm_secure_zero(key, sizeof key);
    ocm_secure_zero(pt, sizeof pt);
    ocm_secure_zero(buf, sizeof buf);
    return rc;
}

int ocm_record_wipe(ocm_storage_t *st)
{
    if (!st || !st->wipe)
        return -1;
    return st->wipe(st->ctx) == 0 ? 0 : -1;
}
