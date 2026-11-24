/*
 * core.c --- device lifecycle: provision, boot, claim, finalize, reset.
 *
 * The functions here contain every security decision; the crypto is in
 * derive.c/primitives.c and the on-flash format is in store.c. Read the flow
 * comments below against docs/DESIGN.md, which walks the same steps with the
 * threat each one answers.
 */

#include <string.h>

#include "ocm_internal.h"

/* A wall clock below 2020-01-01 means "not yet set" (fresh battery-backed RTC,
 * or a chip without one). Grant expiry and back-off are only enforced when the
 * clock is plausible; neither can leak the secret if it is not. */
#define OCM_CLOCK_MIN 1577836800u

static uint32_t now_or_zero(ocm_storage_t *st)
{
    return (st && st->now_s) ? st->now_s(st->ctx) : 0u;
}

static int clock_ok(uint32_t t)
{
    return t >= OCM_CLOCK_MIN;
}

static int get_device_id(ocm_storage_t *st, uint8_t out[16])
{
    if (!st || !st->device_id)
        return -1;
    return st->device_id(st->ctx, out) == 0 ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* Inventory                                                          */
/* ------------------------------------------------------------------ */

int ocm_is_provisioned(ocm_storage_t *st)
{
    return ocm_record_exists(st);
}

int ocm_is_commissioned(ocm_storage_t *st)
{
    ocm_record_t r;
    int rc = ocm_record_load(st, &r);
    if (rc != 1)
        return 0;
    int c = (r.state == OCM_ST_COMMISSIONED);
    ocm_secure_zero(&r, sizeof r);
    return c;
}

/* ------------------------------------------------------------------ */
/* Provisioning                                                       */
/* ------------------------------------------------------------------ */

static ocm_err_t provision_with_secret(ocm_storage_t *st, uint16_t epoch,
                                       const uint8_t secret[OCM_SECRET_LEN],
                                       uint32_t counter, uint8_t state)
{
    ocm_record_t r;

    memset(&r, 0, sizeof r);
    r.ver = OCM_VERSION;
    r.epoch = epoch;
    r.counter = counter;
    memcpy(r.secret, secret, OCM_SECRET_LEN);
    r.state = state;
    r.failures = 0;
    r.last_fail = 0;

    ocm_err_t e = (ocm_record_store(st, &r) == 0) ? OCM_OK : OCM_E_IO;
    ocm_secure_zero(&r, sizeof r);
    return e;
}

ocm_err_t ocm_provision(ocm_storage_t *st)
{
    uint8_t s[OCM_SECRET_LEN];

    if (!st || !st->load || !st->store)
        return OCM_E_INVALID;
    if (ocm_record_exists(st))
        return OCM_E_LIFECYCLE;             /* never overwrite a live secret */

    if (ocm_random(s, sizeof s) != 0)
        return OCM_E_IO;                    /* fail closed: no default secret */
    ocm_err_t e = provision_with_secret(st, 0, s, 0, OCM_ST_FACTORY);
    ocm_secure_zero(s, sizeof s);
    return e;
}

/* ------------------------------------------------------------------ */
/* Boot                                                               */
/* ------------------------------------------------------------------ */

ocm_err_t ocm_boot(ocm_storage_t *st, ocm_session_t *session,
                   ocm_hello_t *hello_out, char code_out[OCM_CODE_STR_LEN])
{
    ocm_record_t r;
    uint8_t x[OCM_KEY_LEN];
    int rc;

    if (!st || !session || !hello_out || !code_out)
        return OCM_E_INVALID;
    memset(session, 0, sizeof *session);
    memset(hello_out, 0, sizeof *hello_out);

    rc = ocm_record_load(st, &r);
    if (rc == 0)
        return OCM_E_STATE;                 /* not provisioned yet */
    if (rc != 1)
        return OCM_E_IO;                    /* corrupt / unreadable */

    if (get_device_id(st, session->device_id) != 0) {
        ocm_secure_zero(&r, sizeof r);
        return OCM_E_IO;
    }
    session->epoch = r.epoch;
    session->valid = 1;

    if (ocm_random(session->nonce, OCM_SESS_NONCE_LEN) != 0) {
        session->valid = 0;
        ocm_secure_zero(&r, sizeof r);
        return OCM_E_IO;
    }

    memcpy(hello_out->boot_epoch, (uint8_t[2]){ (uint8_t)(r.epoch >> 8),
                                                (uint8_t)r.epoch }, 2);
    memcpy(hello_out->device_id, session->device_id, 16);
    memcpy(hello_out->nonce, session->nonce, OCM_SESS_NONCE_LEN);

    if (r.state == OCM_ST_FACTORY) {
        ocm_derive_x(r.secret, x);
        if (ocm_x25519_base(session->pairing_pub, x) != 0) {
            ocm_secure_zero(x, sizeof x);
            ocm_secure_zero(&r, sizeof r);
            session->valid = 0;
            return OCM_E_IO;
        }
        ocm_secure_zero(x, sizeof x);
        ocm_derive_code(r.secret, r.epoch, session->nonce,
                        session->code_raw);
        ocm_code_encode(session->code_raw, code_out);
        memcpy(hello_out->pairing_pub, session->pairing_pub, OCM_KEY_LEN);
    } else {
        /* Commissioned: there is nothing to claim, so expose no pairing
         * material and no code. */
        memset(session->pairing_pub, 0, OCM_KEY_LEN);
        memset(session->code_raw, 0, OCM_CODE_BYTES);
        memset(hello_out->pairing_pub, 0, OCM_KEY_LEN);
        /* "--------" with NUL is 9 bytes; OCM_CODE_STR_LEN is 10, so fill
         * explicitly instead of memcpy from a shorter literal. */
        memset(code_out, '-', OCM_CODE_CHARS);
        code_out[OCM_CODE_CHARS] = '\0';
    }

    ocm_secure_zero(&r, sizeof r);
    return OCM_OK;
}

ocm_err_t ocm_startup(ocm_storage_t *st, ocm_session_t *session,
                      ocm_hello_t *hello_out, char code_out[OCM_CODE_STR_LEN])
{
    if (!st)
        return OCM_E_INVALID;
    if (!ocm_record_exists(st)) {
        ocm_err_t e = ocm_provision(st);
        if (e != OCM_OK && e != OCM_E_LIFECYCLE)
            return e;
    }
    return ocm_boot(st, session, hello_out, code_out);
}

/* ------------------------------------------------------------------ */
/* Shared grant validation                                            */
/* ------------------------------------------------------------------ */

/* Verify signature, type, device binding and expiry. Returns OCM_OK or an
 * error, and on success fills gh/g. */
static ocm_err_t check_grant(const ocm_vendor_t *vendor, const ocm_grant_t *g,
                             const uint8_t sig[OCM_SIG_LEN], uint8_t want_type,
                             const uint8_t device_id[16], uint8_t gh[32],
                             uint32_t now)
{
    uint8_t sb[OCM_GRANT_SIGNED_LEN];

    if (!vendor || !g)
        return OCM_E_INVALID;
    if (g->type != want_type)
        return OCM_E_AUTH;

    ocm_grant_signed_bytes(g, sb);
    if (!ocm_ed25519_verify(sig, sb, sizeof sb, vendor->svc_pub))
        return OCM_E_AUTH;

    if (memcmp(g->device_id, device_id, 16) != 0)
        return OCM_E_AUTH;

    if (ocm_rd32(g->expiry) != 0 && clock_ok(now) &&
        now > ocm_rd32(g->expiry))
        return OCM_E_EXPIRED;

    ocm_sha256(gh, sb, sizeof sb);
    return OCM_OK;
}

/* Enforce the failure back-off. Returns OCM_OK if an attempt is allowed now.
 *
 * A handful of mistakes is tolerated (typos happen), so back-off only begins
 * after OCM_FREE_ATTEMPTS failures; from there each further failure doubles the
 * wait up to OCM_BACKOFF_MAX_S. This is what makes online guessing of a 40-bit
 * code hopeless without punishing the honest purchaser for a fat finger. */
static ocm_err_t backoff_gate(ocm_record_t *r, uint32_t now)
{
    if (r->failures <= OCM_FREE_ATTEMPTS || !clock_ok(now))
        return OCM_OK;
    {
        uint32_t delay = OCM_BACKOFF_BASE_S;
        unsigned sh = (unsigned)(r->failures - OCM_FREE_ATTEMPTS - 1u);
        if (sh > 16u) sh = 16u;
        delay <<= sh;
        if (delay > OCM_BACKOFF_MAX_S) delay = OCM_BACKOFF_MAX_S;
        if (now < r->last_fail + delay)
            return OCM_E_BACKOFF;
    }
    return OCM_OK;
}

static void note_failure(ocm_storage_t *st, ocm_record_t *r, uint32_t now)
{
    if (r->failures < 255u)
        r->failures++;
    r->last_fail = now;
    (void)ocm_record_store(st, r);          /* best effort; never fatal */
}

static void clear_failures(ocm_storage_t *st, ocm_record_t *r)
{
    if (r->failures || r->last_fail) {
        r->failures = 0;
        r->last_fail = 0;
        (void)ocm_record_store(st, r);
    }
}

/* ------------------------------------------------------------------ */
/* Claim, step 1                                                      */
/* ------------------------------------------------------------------ */

ocm_err_t ocm_claim(ocm_storage_t *st, const ocm_vendor_t *vendor,
                    const ocm_session_t *session,
                    const char *code_str,
                    const uint8_t app_pub[OCM_KEY_LEN],
                    const uint8_t *grant_wire, size_t grant_len,
                    uint8_t blob_out[OCM_BLOB_WIRE_LEN])
{
    ocm_record_t r;
    ocm_grant_t g;
    uint8_t sig[OCM_SIG_LEN], gh[32];
    uint8_t code_raw[OCM_CODE_BYTES] = {0};
    uint8_t xe[OCM_KEY_LEN] = {0}, shared[OCM_KEY_LEN] = {0};
    uint8_t bkey[OCM_KEY_LEN] = {0}, kdev[OCM_SECRET_LEN] = {0};
    ocm_blob_t blob;
    uint32_t now;
    ocm_err_t e;
    int rc;

    if (!st || !vendor || !session || !code_str || !app_pub ||
        !grant_wire || !blob_out)
        return OCM_E_INVALID;
    if (!session->valid || grant_len != OCM_GRANT_WIRE_LEN)
        return OCM_E_INVALID;

    rc = ocm_record_load(st, &r);
    if (rc == 0) { return OCM_E_STATE; }
    if (rc != 1) { return OCM_E_IO; }
    if (r.state != OCM_ST_FACTORY) { ocm_secure_zero(&r, sizeof r);
                                     return OCM_E_LIFECYCLE; }
    if (session->epoch != r.epoch) { ocm_secure_zero(&r, sizeof r);
                                     return OCM_E_LIFECYCLE; }

    now = now_or_zero(st);
    e = backoff_gate(&r, now);
    if (e != OCM_OK) { ocm_secure_zero(&r, sizeof r); return e; }

    if (!ocm_grant_decode(&g, sig, grant_wire)) {
        note_failure(st, &r, now); ocm_secure_zero(&r, sizeof r);
        return OCM_E_INVALID;
    }

    e = check_grant(vendor, &g, sig, OCM_GRANT_CLAIM, session->device_id,
                    gh, now);
    if (e != OCM_OK) { note_failure(st, &r, now); ocm_secure_zero(&r, sizeof r);
                       return e; }

    /* The grant must be for exactly this boot and this pairing key. */
    if (memcmp(g.boot_epoch, (uint8_t[2]){ (uint8_t)(r.epoch >> 8),
                                           (uint8_t)r.epoch }, 2) != 0 ||
        memcmp(g.nonce, session->nonce, OCM_SESS_NONCE_LEN) != 0 ||
        memcmp(g.pairing_pub, session->pairing_pub, OCM_KEY_LEN) != 0) {
        note_failure(st, &r, now); ocm_secure_zero(&r, sizeof r);
        return OCM_E_AUTH;
    }

    /* The app on the local link must be the buyer the grant names. */
    if (memcmp(g.buyer_pub, app_pub, OCM_KEY_LEN) != 0) {
        note_failure(st, &r, now); ocm_secure_zero(&r, sizeof r);
        return OCM_E_AUTH;
    }

    /* Live per-boot pairing code, constant-time. */
    if (!ocm_code_decode(code_raw, code_str)) {
        note_failure(st, &r, now); ocm_secure_zero(&r, sizeof r);
        return OCM_E_AUTH;
    }
    if (!ocm_ct_equal(code_raw, session->code_raw, OCM_CODE_BYTES)) {
        note_failure(st, &r, now);
        e = OCM_E_AUTH;
        goto out;
    }

    /* Derive K_dev and seal it to the buyer, keyed also by the code. */
    memset(&blob, 0, sizeof blob);
    ocm_derive_kdev(r.secret, gh, kdev);

    if (ocm_random(xe, sizeof xe) != 0 ||
        ocm_x25519_base(blob.eph_pub, xe) != 0 ||
        ocm_x25519(shared, xe, g.buyer_pub) != 0) {
        e = OCM_E_IO;
        goto out;
    }
    ocm_derive_blobkey(shared, gh, code_raw, bkey);

    ocm_wr16(blob.boot_epoch, r.epoch);
    ocm_wr32(blob.counter, ocm_rd32(g.counter));
    memcpy(blob.device_id, session->device_id, 16);
    if (ocm_random(blob.nonce, OCM_NONCE_LEN) != 0) {
        e = OCM_E_IO;
        goto out;
    }
    {
        uint8_t aad[OCM_BLOB_AAD_LEN];
        ocm_blob_aad(&blob, aad);
        if (ocm_aead_seal(blob.ct, blob.tag, blob.nonce, aad, sizeof aad,
                          kdev, OCM_SECRET_LEN, bkey) != 0) {
            e = OCM_E_IO;
            goto out;
        }
    }
    ocm_blob_encode(&blob, blob_out);
    clear_failures(st, &r);
    e = OCM_OK;

out:
    /* All secrets on every path, success or failure. */
    ocm_secure_zero(kdev, sizeof kdev);
    ocm_secure_zero(bkey, sizeof bkey);
    ocm_secure_zero(shared, sizeof shared);
    ocm_secure_zero(xe, sizeof xe);
    ocm_secure_zero(code_raw, sizeof code_raw);
    ocm_secure_zero(&blob, sizeof blob);
    ocm_secure_zero(&r, sizeof r);
    return e;
}

/* ------------------------------------------------------------------ */
/* Claim, step 2: finalize                                             */
/* ------------------------------------------------------------------ */

ocm_err_t ocm_finalize(ocm_storage_t *st, const ocm_vendor_t *vendor,
                       const ocm_session_t *session,
                       const uint8_t *grant_wire, size_t grant_len,
                       const uint8_t receipt[32])
{
    ocm_record_t r;
    ocm_grant_t g;
    uint8_t sig[OCM_SIG_LEN], gh[32], kdev[OCM_SECRET_LEN], want[32];
    uint32_t now;
    ocm_err_t e;
    int rc;

    if (!st || !vendor || !session || !grant_wire || !receipt)
        return OCM_E_INVALID;
    if (!session->valid || grant_len != OCM_GRANT_WIRE_LEN)
        return OCM_E_INVALID;

    rc = ocm_record_load(st, &r);
    if (rc == 0) { return OCM_E_STATE; }
    if (rc != 1) { return OCM_E_IO; }
    if (r.state != OCM_ST_FACTORY) { ocm_secure_zero(&r, sizeof r);
                                     return OCM_E_LIFECYCLE; }
    if (session->epoch != r.epoch) { ocm_secure_zero(&r, sizeof r);
                                     return OCM_E_LIFECYCLE; }

    now = now_or_zero(st);
    e = backoff_gate(&r, now);
    if (e != OCM_OK) { ocm_secure_zero(&r, sizeof r); return e; }

    if (!ocm_grant_decode(&g, sig, grant_wire)) {
        note_failure(st, &r, now); ocm_secure_zero(&r, sizeof r);
        return OCM_E_INVALID;
    }
    e = check_grant(vendor, &g, sig, OCM_GRANT_CLAIM, session->device_id,
                    gh, now);
    if (e != OCM_OK) { note_failure(st, &r, now); ocm_secure_zero(&r, sizeof r);
                       return e; }

    if (memcmp(g.boot_epoch, (uint8_t[2]){ (uint8_t)(r.epoch >> 8),
                                           (uint8_t)r.epoch }, 2) != 0 ||
        memcmp(g.nonce, session->nonce, OCM_SESS_NONCE_LEN) != 0 ||
        memcmp(g.pairing_pub, session->pairing_pub, OCM_KEY_LEN) != 0) {
        note_failure(st, &r, now); ocm_secure_zero(&r, sizeof r);
        return OCM_E_AUTH;
    }

    ocm_derive_kdev(r.secret, gh, kdev);
    ocm_derive_receipt(kdev, gh, want);
    if (!ocm_ct_equal(want, receipt, 32)) {
        ocm_secure_zero(kdev, sizeof kdev);
        note_failure(st, &r, now);
        ocm_secure_zero(&r, sizeof r);
        return OCM_E_AUTH;
    }

    /* Commit: K_dev replaces S (the bootstrap secret is now gone), state
     * becomes commissioned. If the store fails we keep S intact and return
     * IO so the caller retries; nothing is half-committed. */
    memcpy(r.secret, kdev, OCM_SECRET_LEN);
    r.state = OCM_ST_COMMISSIONED;
    r.counter = ocm_rd32(g.counter);
    r.failures = 0;
    r.last_fail = 0;
    e = (ocm_record_store(st, &r) == 0) ? OCM_OK : OCM_E_IO;

    ocm_secure_zero(kdev, sizeof kdev);
    ocm_secure_zero(want, sizeof want);
    ocm_secure_zero(&r, sizeof r);
    return e;
}

/* ------------------------------------------------------------------ */
/* Factory reset                                                      */
/* ------------------------------------------------------------------ */

static ocm_err_t reset_to_fresh_secret(ocm_storage_t *st, uint16_t new_epoch)
{
    uint8_t s[OCM_SECRET_LEN];
    ocm_err_t e;

    if (ocm_random(s, sizeof s) != 0)
        return OCM_E_IO;
    e = provision_with_secret(st, new_epoch, s, 0, OCM_ST_FACTORY);
    ocm_secure_zero(s, sizeof s);
    return e;
}

ocm_err_t ocm_factory_reset(ocm_storage_t *st, const ocm_vendor_t *vendor,
                            const uint8_t *reset_grant_wire, size_t len)
{
    ocm_record_t r;
    ocm_grant_t g;
    uint8_t sig[OCM_SIG_LEN], gh[32], id[16];
    uint32_t now;
    ocm_err_t e;
    uint16_t new_epoch;
    int rc;

    if (!st || !vendor || !reset_grant_wire)
        return OCM_E_INVALID;
    if (len != OCM_GRANT_WIRE_LEN)
        return OCM_E_INVALID;
    if (!ocm_grant_decode(&g, sig, reset_grant_wire))
        return OCM_E_INVALID;

    /* Authorisation is checked first and does not depend on the record: an
     * operator holding a valid RESET grant can recover a device whose record
     * is corrupt, because the grant is signed by the vendor key. */
    if (get_device_id(st, id) != 0)
        return OCM_E_IO;
    now = now_or_zero(st);
    e = check_grant(vendor, &g, sig, OCM_GRANT_RESET, id, gh, now);
    if (e != OCM_OK)
        return e;

    rc = ocm_record_load(st, &r);
    /* Corrupt or absent record: start a new epoch at 1. The old secret is
     * destroyed by the wipe below regardless. */
    new_epoch = (rc == 1) ? (uint16_t)(r.epoch + 1u) : (uint16_t)1u;
    ocm_secure_zero(&r, sizeof r);

    /* Wipe first so a half-done reset can never leave the old secret behind,
     * then write a brand-new one. */
    if (ocm_record_wipe(st) != 0)
        return OCM_E_IO;
    return reset_to_fresh_secret(st, new_epoch);
}

ocm_err_t ocm_factory_reset_local(ocm_storage_t *st)
{
    ocm_record_t r;
    uint16_t new_epoch;
    int rc;

    if (!st || !st->store || !st->wipe)
        return OCM_E_INVALID;
    rc = ocm_record_load(st, &r);
    /* Physical reset must be able to recover a device whose record is corrupt
     * (bit rot, power glitch during a write). A corrupt record cannot provide
     * a trustworthy epoch, so start the new epoch at 1 -- still guaranteed to
     * differ from any grant issued for the old (now destroyed) secret. */
    if (rc < 0) {
        new_epoch = 1u;
    } else {
        new_epoch = (rc == 1) ? (uint16_t)(r.epoch + 1u) : (uint16_t)1u;
        ocm_secure_zero(&r, sizeof r);
    }

    if (ocm_record_wipe(st) != 0)
        return OCM_E_IO;
    return reset_to_fresh_secret(st, new_epoch);
}

/* ------------------------------------------------------------------ */
/* Credential hand-off                                                */
/* ------------------------------------------------------------------ */

ocm_err_t ocm_take_credential(ocm_storage_t *st, uint8_t out[OCM_SECRET_LEN])
{
    ocm_record_t r;
    int rc;

    if (!st || !out)
        return OCM_E_INVALID;
    rc = ocm_record_load(st, &r);
    if (rc == 0) return OCM_E_STATE;
    if (rc != 1) return OCM_E_IO;
    if (r.state != OCM_ST_COMMISSIONED) {
        ocm_secure_zero(&r, sizeof r);
        return OCM_E_STATE;
    }
    memcpy(out, r.secret, OCM_SECRET_LEN);
    ocm_secure_zero(&r, sizeof r);
    return OCM_OK;
}
