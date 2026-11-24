/*
 * test_ocm.c --- test suite.
 *
 * The happy path is the least interesting part. Most of these tests try to
 * break the protocol: replay a grant after a reboot, harvest a code and use it
 * later, relay a blob, tamper with flash, reset to fall back to a known state,
 * claim someone else's device, brute-force the code, and so on. Each test names
 * the property it defends.
 */

#include <stdio.h>
#include <string.h>

#include "ocm.h"
#include "storage_mock.h"

static int g_pass, g_fail;
static const char *g_test;

#define CHECK(cond) do { \
    if (cond) { g_pass++; } \
    else { g_fail++; \
        fprintf(stderr, "FAIL [%s] %s:%d: %s\n", \
                g_test, __FILE__, __LINE__, #cond); } \
} while (0)

#define TEST(name) do { g_test = name; } while (0)

/* ---------- shared fixtures ---------------------------------------- */

typedef struct {
    ocm_vendor_t  vendor;
    uint8_t       svc_pk[OCM_KEY_LEN], svc_sk[OCM_SIG_LEN];
    uint8_t       seed[OCM_KEY_LEN];
} pki_t;

static void pki_setup(pki_t *p)
{
    memset(p->seed, 0x5a, sizeof p->seed);
    ocm_service_keygen(p->seed, p->svc_pk, p->svc_sk);
    memcpy(p->vendor.svc_pub, p->svc_pk, OCM_KEY_LEN);
}

/* Build a claim grant exactly as the cloud would. */
static void make_grant(const pki_t *p, const ocm_hello_t *h,
                       const uint8_t buyer_pub[OCM_KEY_LEN],
                       uint32_t expiry, uint32_t counter,
                       ocm_grant_t *g, uint8_t wire[OCM_GRANT_WIRE_LEN])
{
    uint8_t sig[OCM_SIG_LEN];
    memset(g, 0, sizeof *g);
    g->type = OCM_GRANT_CLAIM;
    memcpy(g->boot_epoch, h->boot_epoch, 2);
    g->counter[0] = (uint8_t)(counter >> 24);
    g->counter[1] = (uint8_t)(counter >> 16);
    g->counter[2] = (uint8_t)(counter >> 8);
    g->counter[3] = (uint8_t)counter;
    g->expiry[0] = (uint8_t)(expiry >> 24);
    g->expiry[1] = (uint8_t)(expiry >> 16);
    g->expiry[2] = (uint8_t)(expiry >> 8);
    g->expiry[3] = (uint8_t)expiry;
    memcpy(g->device_id, h->device_id, 16);
    memcpy(g->nonce, h->nonce, OCM_SESS_NONCE_LEN);
    memcpy(g->pairing_pub, h->pairing_pub, OCM_KEY_LEN);
    memcpy(g->buyer_pub, buyer_pub, OCM_KEY_LEN);
    ocm_service_sign_grant(p->svc_sk, g, sig);
    ocm_grant_encode(g, sig, wire);
}

static void make_reset_grant(const pki_t *p, const uint8_t device_id[16],
                             ocm_grant_t *g, uint8_t wire[OCM_GRANT_WIRE_LEN])
{
    uint8_t sig[OCM_SIG_LEN];
    memset(g, 0, sizeof *g);
    g->type = OCM_GRANT_RESET;
    memcpy(g->device_id, device_id, 16);
    ocm_service_sign_grant(p->svc_sk, g, sig);
    ocm_grant_encode(g, sig, wire);
}

/* Run a full successful claim; returns the credential. */
static ocm_err_t full_claim(pki_t *p, mock_device_t *dev,
                            uint8_t cred[OCM_SECRET_LEN])
{
    ocm_session_t s; ocm_hello_t h; char code[OCM_CODE_STR_LEN];
    ocm_grant_t g; uint8_t gw[OCM_GRANT_WIRE_LEN], blob[OCM_BLOB_WIRE_LEN];
    uint8_t bp[OCM_KEY_LEN], bv[OCM_KEY_LEN], rcpt[32];
    ocm_err_t e;

    e = ocm_startup(mock_storage(dev), &s, &h, code);
    if (e != OCM_OK) return e;
    ocm_buyer_keygen(bv, bp);
    make_grant(p, &h, bp, dev->now + 600, 1, &g, gw);
    e = ocm_claim(mock_storage(dev), &p->vendor, &s, code, bp, gw,
                  OCM_GRANT_WIRE_LEN, blob);
    if (e != OCM_OK) return e;
    e = ocm_buyer_accept(p->svc_pk, bv, code, gw, OCM_GRANT_WIRE_LEN,
                         blob, OCM_BLOB_WIRE_LEN, cred, rcpt);
    if (e != OCM_OK) return e;
    return ocm_finalize(mock_storage(dev), &p->vendor, &s, gw,
                        OCM_GRANT_WIRE_LEN, rcpt);
}

/* ---------- codec --------------------------------------------------- */

static void test_code_roundtrip(void)
{
    TEST("code_roundtrip");
    uint8_t raw[OCM_CODE_BYTES] = {0x00, 0x00, 0x00, 0x00, 0x00};
    char s[OCM_CODE_STR_LEN];
    uint8_t back[OCM_CODE_BYTES];

    ocm_code_encode(raw, s);
    CHECK(strcmp(s, "0000-0000") == 0);

    memset(raw, 0xff, sizeof raw);
    ocm_code_encode(raw, s);
    CHECK(strlen(s) == 9 && s[4] == '-');
    CHECK(ocm_code_decode(back, s));
    CHECK(memcmp(back, raw, OCM_CODE_BYTES) == 0);

    /* Ambiguous characters and case are tolerated on input. */
    CHECK(ocm_code_decode(back, "oooo-oooo"));   /* O -> 0 */
    CHECK(memcmp(back, (uint8_t[5]){0,0,0,0,0}, 5) == 0);
    CHECK(ocm_code_decode(back, "ilii-1111"));   /* I,L -> 1 */
    CHECK(ocm_code_decode(back, "0000 0000"));   /* space ignored */

    /* Wrong length / bogus chars rejected. */
    CHECK(!ocm_code_decode(back, "0000-000"));
    CHECK(!ocm_code_decode(back, "0000-00000"));
    CHECK(!ocm_code_decode(back, "0000-UUUU"));  /* U excluded from alphabet */
}

static void test_wire_roundtrip(void)
{
    TEST("wire_roundtrip");
    ocm_hello_t h, h2; uint8_t hw[OCM_HELLO_WIRE_LEN];
    ocm_grant_t g, g2; uint8_t gw[OCM_GRANT_WIRE_LEN], sig[OCM_SIG_LEN], sig2[OCM_SIG_LEN];
    ocm_blob_t b, b2; uint8_t bw[OCM_BLOB_WIRE_LEN];

    memset(&h, 0xa1, sizeof h);
    ocm_hello_encode(&h, hw);
    memset(&h2, 0, sizeof h2);
    CHECK(ocm_hello_decode(&h2, hw));
    CHECK(memcmp(&h, &h2, sizeof h) == 0);

    memset(&g, 0xb2, sizeof g); g.type = OCM_GRANT_CLAIM;
    memset(sig, 0xc3, sizeof sig);
    ocm_grant_encode(&g, sig, gw);
    CHECK(ocm_grant_decode(&g2, sig2, gw));
    CHECK(memcmp(&g, &g2, sizeof g) == 0);
    CHECK(memcmp(sig, sig2, sizeof sig) == 0);

    memset(&b, 0xd4, sizeof b);
    ocm_blob_encode(&b, bw);
    CHECK(ocm_blob_decode(&b2, bw));
    CHECK(memcmp(&b, &b2, sizeof b) == 0);

    /* Version byte is checked. */
    hw[0] = 99; CHECK(!ocm_hello_decode(&h2, hw));
    gw[0] = 99; CHECK(!ocm_grant_decode(&g2, sig2, gw));
}

/* ---------- provisioning / boot ------------------------------------ */

static void test_provision_idempotent(void)
{
    TEST("provision_idempotent");
    mock_device_t d; mock_init(&d, 1, 2);
    CHECK(ocm_provision(mock_storage(&d)) == OCM_OK);
    CHECK(ocm_is_provisioned(mock_storage(&d)));
    /* A second provision must NOT overwrite the live secret. */
    CHECK(ocm_provision(mock_storage(&d)) == OCM_E_LIFECYCLE);
    CHECK(ocm_startup(mock_storage(&d), &(ocm_session_t){0}, &(ocm_hello_t){0},
                      (char[OCM_CODE_STR_LEN]){0}) == OCM_OK);
}

static void test_provision_fails_closed(void)
{
    TEST("provision_fails_closed");
    mock_device_t d;
    /* No keystore -> cannot seal -> must fail with IO, never a default secret. */
    mock_init(&d, 1, 2);
    d.has_keystore = 0;
    CHECK(ocm_provision(mock_storage(&d)) == OCM_E_IO);
    CHECK(!ocm_is_provisioned(mock_storage(&d)));

    /* Storage write failure -> IO, still unprovisioned. */
    mock_init(&d, 1, 2);
    d.io_error = 1;
    CHECK(ocm_provision(mock_storage(&d)) == OCM_E_IO);
}

static void test_boot_before_provision(void)
{
    TEST("boot_before_provision");
    mock_device_t d; mock_init(&d, 1, 2);
    ocm_session_t s; ocm_hello_t h; char code[OCM_CODE_STR_LEN];
    CHECK(ocm_boot(mock_storage(&d), &s, &h, code) == OCM_E_STATE);
    /* But startup provisions first. */
    CHECK(ocm_startup(mock_storage(&d), &s, &h, code) == OCM_OK);
}

static void test_code_rotates_each_boot(void)
{
    TEST("code_rotates_each_boot");
    mock_device_t d; mock_init(&d, 1, 2);
    ocm_session_t s1, s2; ocm_hello_t h1, h2;
    char c1[OCM_CODE_STR_LEN], c2[OCM_CODE_STR_LEN];

    CHECK(ocm_startup(mock_storage(&d), &s1, &h1, c1) == OCM_OK);
    CHECK(ocm_boot(mock_storage(&d), &s2, &h2, c2) == OCM_OK);
    /* Same secret, different nonce => different code. This is what makes a
     * warehouse-harvested code useless later. */
    CHECK(strcmp(c1, c2) != 0);
    CHECK(memcmp(s1.nonce, s2.nonce, OCM_SESS_NONCE_LEN) != 0);
    CHECK(memcmp(s1.pairing_pub, s2.pairing_pub, OCM_KEY_LEN) == 0);
}

static void test_unique_secret_per_device(void)
{
    TEST("unique_secret_per_device");
    /* Two devices with the SAME firmware and the SAME (zeroed) flash history
     * must still end up with different secrets and pairing keys. */
    mock_device_t a, b;
    mock_init(&a, 1, 2);
    mock_init(&b, 1, 2);
    ocm_session_t sa, sb; ocm_hello_t ha, hb;
    char ca[OCM_CODE_STR_LEN], cb[OCM_CODE_STR_LEN];

    CHECK(ocm_startup(mock_storage(&a), &sa, &ha, ca) == OCM_OK);
    CHECK(ocm_startup(mock_storage(&b), &sb, &hb, cb) == OCM_OK);
    CHECK(memcmp(sa.pairing_pub, sb.pairing_pub, OCM_KEY_LEN) != 0);
    CHECK(strcmp(ca, cb) != 0);
    CHECK(memcmp(a.flash, b.flash, OCM_RECORD_LEN) != 0);
}

/* ---------- the claim path ----------------------------------------- */

static void test_full_claim(void)
{
    TEST("full_claim");
    pki_t p; pki_setup(&p);
    mock_device_t d; mock_init(&d, 3, 9);
    uint8_t cred[OCM_SECRET_LEN], got[OCM_SECRET_LEN];

    CHECK(full_claim(&p, &d, cred) == OCM_OK);
    CHECK(ocm_is_commissioned(mock_storage(&d)));
    CHECK(ocm_take_credential(mock_storage(&d), got) == OCM_OK);
    CHECK(memcmp(cred, got, OCM_SECRET_LEN) == 0);
}

static void test_credential_unique_per_device(void)
{
    TEST("credential_unique_per_device");
    /* The whole point: two devices yield different credentials even if the
     * buyer reuses the same app key and the cloud issues the same counter. */
    pki_t p; pki_setup(&p);
    mock_device_t a, b;
    mock_init(&a, 5, 1);
    mock_init(&b, 5, 2);
    uint8_t ca[OCM_SECRET_LEN], cb[OCM_SECRET_LEN];
    CHECK(full_claim(&p, &a, ca) == OCM_OK);
    CHECK(full_claim(&p, &b, cb) == OCM_OK);
    CHECK(memcmp(ca, cb, OCM_SECRET_LEN) != 0);
}

static void test_wrong_code_rejected(void)
{
    TEST("wrong_code_rejected");
    pki_t p; pki_setup(&p);
    mock_device_t d; mock_init(&d, 7, 7);
    ocm_session_t s; ocm_hello_t h; char code[OCM_CODE_STR_LEN];
    ocm_grant_t g; uint8_t gw[OCM_GRANT_WIRE_LEN], blob[OCM_BLOB_WIRE_LEN];
    uint8_t bp[OCM_KEY_LEN], bv[OCM_KEY_LEN];

    CHECK(ocm_startup(mock_storage(&d), &s, &h, code) == OCM_OK);
    ocm_buyer_keygen(bv, bp);
    make_grant(&p, &h, bp, d.now + 600, 1, &g, gw);

    CHECK(ocm_claim(mock_storage(&d), &p.vendor, &s, "0000-0000", bp,
                    gw, OCM_GRANT_WIRE_LEN, blob) == OCM_E_AUTH);
    /* And the correct code still works afterwards. */
    CHECK(ocm_claim(mock_storage(&d), &p.vendor, &s, code, bp,
                    gw, OCM_GRANT_WIRE_LEN, blob) == OCM_OK);
}

static void test_wrong_buyer_key_rejected(void)
{
    TEST("wrong_buyer_key_rejected");
    pki_t p; pki_setup(&p);
    mock_device_t d; mock_init(&d, 7, 7);
    ocm_session_t s; ocm_hello_t h; char code[OCM_CODE_STR_LEN];
    ocm_grant_t g; uint8_t gw[OCM_GRANT_WIRE_LEN], blob[OCM_BLOB_WIRE_LEN];
    uint8_t bp[OCM_KEY_LEN], bv[OCM_KEY_LEN], other[OCM_KEY_LEN];

    CHECK(ocm_startup(mock_storage(&d), &s, &h, code) == OCM_OK);
    ocm_buyer_keygen(bv, bp);
    ocm_buyer_keygen(bv, other);              /* a different app key */
    make_grant(&p, &h, bp, d.now + 600, 1, &g, gw);

    /* The device checks app_pub == grant.buyer_pub, so pointing the claim at
     * a different key fails: a malicious cloud cannot redirect the credential. */
    CHECK(ocm_claim(mock_storage(&d), &p.vendor, &s, code, other,
                    gw, OCM_GRANT_WIRE_LEN, blob) == OCM_E_AUTH);
}

static void test_forged_grant_rejected(void)
{
    TEST("forged_grant_rejected");
    pki_t p; pki_setup(&p);
    mock_device_t d; mock_init(&d, 8, 8);
    ocm_session_t s; ocm_hello_t h; char code[OCM_CODE_STR_LEN];
    ocm_grant_t g; uint8_t gw[OCM_GRANT_WIRE_LEN], blob[OCM_BLOB_WIRE_LEN];
    uint8_t bp[OCM_KEY_LEN], bv[OCM_KEY_LEN];

    CHECK(ocm_startup(mock_storage(&d), &s, &h, code) == OCM_OK);
    ocm_buyer_keygen(bv, bp);
    make_grant(&p, &h, bp, d.now + 600, 1, &g, gw);
    gw[150] ^= 0x80;   /* flip a bit inside the signed bytes */

    CHECK(ocm_claim(mock_storage(&d), &p.vendor, &s, code, bp,
                    gw, OCM_GRANT_WIRE_LEN, blob) == OCM_E_AUTH);
}

static void test_grant_replay_after_reboot_rejected(void)
{
    TEST("grant_replay_after_reboot_rejected");
    /* Core anti-replay property: a grant binds the boot nonce, so restoring a
     * device from an old flash image (or replaying an old grant) after a
     * reboot does not work. */
    pki_t p; pki_setup(&p);
    mock_device_t d; mock_init(&d, 9, 9);
    ocm_session_t s1, s2; ocm_hello_t h1, h2;
    char c1[OCM_CODE_STR_LEN], c2[OCM_CODE_STR_LEN];
    ocm_grant_t g; uint8_t gw[OCM_GRANT_WIRE_LEN], blob[OCM_BLOB_WIRE_LEN];
    uint8_t bp[OCM_KEY_LEN], bv[OCM_KEY_LEN];

    CHECK(ocm_startup(mock_storage(&d), &s1, &h1, c1) == OCM_OK);
    ocm_buyer_keygen(bv, bp);
    make_grant(&p, &h1, bp, d.now + 600, 1, &g, gw);

    /* Reboot: new nonce. */
    CHECK(ocm_boot(mock_storage(&d), &s2, &h2, c2) == OCM_OK);

    /* Old grant + old code against the new session must fail. */
    CHECK(ocm_claim(mock_storage(&d), &p.vendor, &s2, c1, bp,
                    gw, OCM_GRANT_WIRE_LEN, blob) == OCM_E_AUTH);
    /* Even with the new code, the old grant's nonce no longer matches. */
    CHECK(ocm_claim(mock_storage(&d), &p.vendor, &s2, c2, bp,
                    gw, OCM_GRANT_WIRE_LEN, blob) == OCM_E_AUTH);
}

static void test_blob_relay_without_buyer_priv(void)
{
    TEST("blob_relay_without_buyer_priv");
    /* An eavesdropper who captures the grant and blob but has neither the
     * buyer private key nor the code gets nothing. */
    pki_t p; pki_setup(&p);
    mock_device_t d; mock_init(&d, 10, 10);
    ocm_session_t s; ocm_hello_t h; char code[OCM_CODE_STR_LEN];
    ocm_grant_t g; uint8_t gw[OCM_GRANT_WIRE_LEN], blob[OCM_BLOB_WIRE_LEN];
    uint8_t bp[OCM_KEY_LEN], bv[OCM_KEY_LEN];
    uint8_t evil_priv[OCM_KEY_LEN], evil_pub[OCM_KEY_LEN];
    uint8_t cred[OCM_SECRET_LEN], rcpt[32];

    CHECK(ocm_startup(mock_storage(&d), &s, &h, code) == OCM_OK);
    ocm_buyer_keygen(bv, bp);
    make_grant(&p, &h, bp, d.now + 600, 1, &g, gw);
    CHECK(ocm_claim(mock_storage(&d), &p.vendor, &s, code, bp,
                    gw, OCM_GRANT_WIRE_LEN, blob) == OCM_OK);

    ocm_buyer_keygen(evil_priv, evil_pub);
    /* Wrong key, right code. */
    CHECK(ocm_buyer_accept(p.svc_pk, evil_priv, code, gw,
                           OCM_GRANT_WIRE_LEN, blob, OCM_BLOB_WIRE_LEN,
                           cred, rcpt) == OCM_E_AUTH);
    /* Right key, wrong code. */
    CHECK(ocm_buyer_accept(p.svc_pk, bv, "0000-0000", gw,
                           OCM_GRANT_WIRE_LEN, blob, OCM_BLOB_WIRE_LEN,
                           cred, rcpt) == OCM_E_AUTH);
}

static void test_expired_grant_rejected(void)
{
    TEST("expired_grant_rejected");
    pki_t p; pki_setup(&p);
    mock_device_t d; mock_init(&d, 11, 11);
    ocm_session_t s; ocm_hello_t h; char code[OCM_CODE_STR_LEN];
    ocm_grant_t g; uint8_t gw[OCM_GRANT_WIRE_LEN], blob[OCM_BLOB_WIRE_LEN];
    uint8_t bp[OCM_KEY_LEN], bv[OCM_KEY_LEN];

    CHECK(ocm_startup(mock_storage(&d), &s, &h, code) == OCM_OK);
    ocm_buyer_keygen(bv, bp);
    make_grant(&p, &h, bp, d.now + 60, 1, &g, gw);   /* valid 60s */
    mock_advance(&d, 120);                            /* now stale */
    CHECK(ocm_claim(mock_storage(&d), &p.vendor, &s, code, bp,
                    gw, OCM_GRANT_WIRE_LEN, blob) == OCM_E_EXPIRED);
}

static void test_backoff_and_lockout(void)
{
    TEST("backoff_and_lockout");
    pki_t p; pki_setup(&p);
    mock_device_t d; mock_init(&d, 12, 12);
    ocm_session_t s; ocm_hello_t h; char code[OCM_CODE_STR_LEN];
    ocm_grant_t g; uint8_t gw[OCM_GRANT_WIRE_LEN], blob[OCM_BLOB_WIRE_LEN];
    uint8_t bp[OCM_KEY_LEN], bv[OCM_KEY_LEN];

    CHECK(ocm_startup(mock_storage(&d), &s, &h, code) == OCM_OK);
    ocm_buyer_keygen(bv, bp);
    make_grant(&p, &h, bp, d.now + 3600, 1, &g, gw);

    /* The first OCM_FREE_ATTEMPTS mistakes are tolerated (typos), each AUTH. */
    for (unsigned i = 0; i < OCM_FREE_ATTEMPTS; i++)
        CHECK(ocm_claim(mock_storage(&d), &p.vendor, &s, "0000-0000", bp,
                        gw, OCM_GRANT_WIRE_LEN, blob) == OCM_E_AUTH);

    /* One more failure crosses into back-off. Immediately after, even the
     * CORRECT code is refused with BACKOFF -- this is what makes online code
     * guessing impractical (an attacker gets ~4 tries, then waits). */
    CHECK(ocm_claim(mock_storage(&d), &p.vendor, &s, "0000-0000", bp,
                    gw, OCM_GRANT_WIRE_LEN, blob) == OCM_E_AUTH);
    CHECK(ocm_claim(mock_storage(&d), &p.vendor, &s, code, bp,
                    gw, OCM_GRANT_WIRE_LEN, blob) == OCM_E_BACKOFF);

    /* Wait out the back-off: the correct code then succeeds, and a success
     * clears the failure counter. */
    mock_advance(&d, OCM_BACKOFF_MAX_S);
    CHECK(ocm_claim(mock_storage(&d), &p.vendor, &s, code, bp,
                    gw, OCM_GRANT_WIRE_LEN, blob) == OCM_OK);
}

static void test_no_double_claim(void)
{
    TEST("no_double_claim");
    pki_t p; pki_setup(&p);
    mock_device_t d; mock_init(&d, 13, 13);
    uint8_t cred[OCM_SECRET_LEN];
    CHECK(full_claim(&p, &d, cred) == OCM_OK);

    /* A second boot exposes no pairing material and cannot be claimed. */
    ocm_session_t s; ocm_hello_t h; char code[OCM_CODE_STR_LEN];
    CHECK(ocm_boot(mock_storage(&d), &s, &h, code) == OCM_OK);
    CHECK(memcmp(s.code_raw, (uint8_t[OCM_CODE_BYTES]){0}, OCM_CODE_BYTES) == 0);
    CHECK(strcmp(code, "--------") == 0);
    CHECK(memcmp(s.pairing_pub, (uint8_t[OCM_KEY_LEN]){0}, OCM_KEY_LEN) == 0);
}

static void test_finalize_bad_receipt(void)
{
    TEST("finalize_bad_receipt");
    pki_t p; pki_setup(&p);
    mock_device_t d; mock_init(&d, 14, 14);
    ocm_session_t s; ocm_hello_t h; char code[OCM_CODE_STR_LEN];
    ocm_grant_t g; uint8_t gw[OCM_GRANT_WIRE_LEN], blob[OCM_BLOB_WIRE_LEN];
    uint8_t bp[OCM_KEY_LEN], bv[OCM_KEY_LEN], cred[OCM_SECRET_LEN], rcpt[32];

    CHECK(ocm_startup(mock_storage(&d), &s, &h, code) == OCM_OK);
    ocm_buyer_keygen(bv, bp);
    make_grant(&p, &h, bp, d.now + 600, 1, &g, gw);
    CHECK(ocm_claim(mock_storage(&d), &p.vendor, &s, code, bp,
                    gw, OCM_GRANT_WIRE_LEN, blob) == OCM_OK);
    CHECK(ocm_buyer_accept(p.svc_pk, bv, code, gw, OCM_GRANT_WIRE_LEN,
                           blob, OCM_BLOB_WIRE_LEN, cred, rcpt) == OCM_OK);

    /* A forged receipt must not commission the device. */
    rcpt[0] ^= 0xff;
    CHECK(ocm_finalize(mock_storage(&d), &p.vendor, &s, gw,
                       OCM_GRANT_WIRE_LEN, rcpt) == OCM_E_AUTH);
    CHECK(!ocm_is_commissioned(mock_storage(&d)));
}

/* ---------- factory reset ------------------------------------------ */

static void test_reset_yields_new_secret(void)
{
    TEST("reset_yields_new_secret");
    mock_device_t d; mock_init(&d, 20, 20);
    ocm_session_t s1, s2; ocm_hello_t h1, h2;
    char c1[OCM_CODE_STR_LEN], c2[OCM_CODE_STR_LEN];

    CHECK(ocm_startup(mock_storage(&d), &s1, &h1, c1) == OCM_OK);
    CHECK(ocm_factory_reset_local(mock_storage(&d)) == OCM_OK);
    CHECK(ocm_boot(mock_storage(&d), &s2, &h2, c2) == OCM_OK);

    /* A reset never returns to a known/previous state: new pairing key, new
     * code, and a bumped epoch. */
    CHECK(memcmp(s1.pairing_pub, s2.pairing_pub, OCM_KEY_LEN) != 0);
    CHECK(strcmp(c1, c2) != 0);
    CHECK(s2.epoch == s1.epoch + 1);
}

static void test_reset_requires_valid_grant(void)
{
    TEST("reset_requires_valid_grant");
    pki_t p; pki_setup(&p);
    mock_device_t d; mock_init(&d, 21, 21);
    ocm_session_t s; ocm_hello_t h; char code[OCM_CODE_STR_LEN];
    ocm_grant_t g; uint8_t gw[OCM_GRANT_WIRE_LEN];
    uint8_t snap[OCM_RECORD_LEN];
    uint8_t bogus_id[16] = {0};

    CHECK(ocm_startup(mock_storage(&d), &s, &h, code) == OCM_OK);
    memcpy(snap, d.flash, OCM_RECORD_LEN);

    /* A reset grant for a DIFFERENT device must not reset this one. */
    make_reset_grant(&p, bogus_id, &g, gw);
    CHECK(ocm_factory_reset(mock_storage(&d), &p.vendor, gw,
                            OCM_GRANT_WIRE_LEN) == OCM_E_AUTH);
    CHECK(memcmp(snap, d.flash, OCM_RECORD_LEN) == 0);   /* untouched */

    /* The right one does. */
    make_reset_grant(&p, h.device_id, &g, gw);
    CHECK(ocm_factory_reset(mock_storage(&d), &p.vendor, gw,
                            OCM_GRANT_WIRE_LEN) == OCM_OK);
}

static void test_reset_burns_old_credential(void)
{
    TEST("reset_burns_old_credential");
    pki_t p; pki_setup(&p);
    mock_device_t d; mock_init(&d, 22, 22);
    uint8_t cred[OCM_SECRET_LEN];

    CHECK(full_claim(&p, &d, cred) == OCM_OK);
    CHECK(ocm_factory_reset_local(mock_storage(&d)) == OCM_OK);
    CHECK(!ocm_is_commissioned(mock_storage(&d)));
    /* Old credential is gone from storage. */
    CHECK(ocm_take_credential(mock_storage(&d), cred) == OCM_E_STATE);
}

/* ---------- storage tampering / confidentiality --------------------- */

static void test_tamper_detected(void)
{
    TEST("tamper_detected");
    mock_device_t d; mock_init(&d, 30, 30);
    CHECK(ocm_provision(mock_storage(&d)) == OCM_OK);

    mock_tamper_flash(&d, 20);
    /* Corruption is an error, never a silent fallback. */
    CHECK(!ocm_is_commissioned(mock_storage(&d))); /* load fails -> not comm. */
    ocm_session_t s; ocm_hello_t h; char c[OCM_CODE_STR_LEN];
    CHECK(ocm_boot(mock_storage(&d), &s, &h, c) == OCM_E_IO);
}

static void test_flash_holds_no_plaintext_secret(void)
{
    TEST("flash_holds_no_plaintext_secret");
    /* A key-recovery attack on flash alone must find nothing. Capture the
     * secret by running the real flow, then confirm its bytes are absent from
     * the flash image (which is AEAD-sealed under the chip root key). */
    pki_t p; pki_setup(&p);
    mock_device_t d; mock_init(&d, 31, 31);
    uint8_t cred[OCM_SECRET_LEN];

    CHECK(full_claim(&p, &d, cred) == OCM_OK);
    CHECK(memmem(d.flash, OCM_RECORD_LEN, cred, OCM_SECRET_LEN) == NULL);

    /* Even the bootstrap secret S (before claim) must not appear. */
    mock_device_t e; mock_init(&e, 32, 32);
    ocm_session_t s; ocm_hello_t h; char c[OCM_CODE_STR_LEN];
    CHECK(ocm_startup(mock_storage(&e), &s, &h, c) == OCM_OK);
    /* Recover S by decrypting with the mock root key is possible only WITH the
     * key; the flash bytes themselves contain no 32-byte S in cleartext. Here
     * we just assert the record is not all-zero and not equal to any obvious
     * constant. */
    uint8_t zero[OCM_RECORD_LEN] = {0};
    CHECK(memcmp(e.flash, zero, OCM_RECORD_LEN) != 0);
}

static void test_store_failure_is_safe(void)
{
    TEST("store_failure_is_safe");
    /* A failing NVS mid-claim must not leave a half-commissioned device that
     * still holds the old secret. Either we commit fully or we do not. */
    pki_t p; pki_setup(&p);
    mock_device_t d; mock_init(&d, 33, 33);
    ocm_session_t s; ocm_hello_t h; char code[OCM_CODE_STR_LEN];
    ocm_grant_t g; uint8_t gw[OCM_GRANT_WIRE_LEN], blob[OCM_BLOB_WIRE_LEN];
    uint8_t bp[OCM_KEY_LEN], bv[OCM_KEY_LEN], cred[OCM_SECRET_LEN], rcpt[32];

    CHECK(ocm_startup(mock_storage(&d), &s, &h, code) == OCM_OK);
    ocm_buyer_keygen(bv, bp);
    make_grant(&p, &h, bp, d.now + 600, 1, &g, gw);
    CHECK(ocm_claim(mock_storage(&d), &p.vendor, &s, code, bp,
                    gw, OCM_GRANT_WIRE_LEN, blob) == OCM_OK);
    CHECK(ocm_buyer_accept(p.svc_pk, bv, code, gw, OCM_GRANT_WIRE_LEN,
                           blob, OCM_BLOB_WIRE_LEN, cred, rcpt) == OCM_OK);

    d.fail_after = 0;   /* next store fails */
    CHECK(ocm_finalize(mock_storage(&d), &p.vendor, &s, gw,
                       OCM_GRANT_WIRE_LEN, rcpt) == OCM_E_IO);
    CHECK(!ocm_is_commissioned(mock_storage(&d)));

    /* Retry once storage works: the SAME receipt must still finalize, because
     * the device kept S. */
    d.fail_after = -1;
    CHECK(ocm_finalize(mock_storage(&d), &p.vendor, &s, gw,
                       OCM_GRANT_WIRE_LEN, rcpt) == OCM_OK);
    CHECK(ocm_is_commissioned(mock_storage(&d)));
}

/* ---------- code space sanity -------------------------------------- */

static void test_expiry_zero_means_no_expiry(void)
{
    TEST("expiry_zero_means_no_expiry");
    pki_t p; pki_setup(&p);
    mock_device_t d; mock_init(&d, 40, 40);
    ocm_session_t s; ocm_hello_t h; char code[OCM_CODE_STR_LEN];
    ocm_grant_t g; uint8_t gw[OCM_GRANT_WIRE_LEN], blob[OCM_BLOB_WIRE_LEN];
    uint8_t bp[OCM_KEY_LEN], bv[OCM_KEY_LEN];

    CHECK(ocm_startup(mock_storage(&d), &s, &h, code) == OCM_OK);
    ocm_buyer_keygen(bv, bp);
    make_grant(&p, &h, bp, 0, 1, &g, gw);        /* expiry 0 = no wall clock */
    mock_advance(&d, 10 * 365 * 24 * 3600u);      /* ten years later */
    CHECK(ocm_claim(mock_storage(&d), &p.vendor, &s, code, bp,
                    gw, OCM_GRANT_WIRE_LEN, blob) == OCM_OK);
}

static void test_reset_then_full_reclaim(void)
{
    TEST("reset_then_full_reclaim");
    /* After a reset the device must be claimable again as a NEW device, and the
     * old code must not work. This exercises the whole lifecycle twice. */
    pki_t p; pki_setup(&p);
    mock_device_t d; mock_init(&d, 41, 41);
    uint8_t c1[OCM_SECRET_LEN], c2[OCM_SECRET_LEN];

    CHECK(full_claim(&p, &d, c1) == OCM_OK);
    CHECK(ocm_factory_reset_local(mock_storage(&d)) == OCM_OK);
    CHECK(!ocm_is_commissioned(mock_storage(&d)));
    CHECK(full_claim(&p, &d, c2) == OCM_OK);       /* reclaimable */
    CHECK(memcmp(c1, c2, OCM_SECRET_LEN) != 0);    /* brand-new credential */
}

static void test_hello_hides_pairing_when_commissioned(void)
{
    TEST("hello_hides_pairing_when_commissioned");
    pki_t p; pki_setup(&p);
    mock_device_t d; mock_init(&d, 42, 42);
    uint8_t cred[OCM_SECRET_LEN];
    ocm_session_t s; ocm_hello_t h; char code[OCM_CODE_STR_LEN];
    uint8_t hw[OCM_HELLO_WIRE_LEN];

    CHECK(full_claim(&p, &d, cred) == OCM_OK);
    CHECK(ocm_boot(mock_storage(&d), &s, &h, code) == OCM_OK);
    ocm_hello_encode(&h, hw);
    /* The wire hello for a commissioned device reveals no pairing key at all. */
    CHECK(memcmp(hw + 51, (uint8_t[OCM_KEY_LEN]){0}, OCM_KEY_LEN) == 0);
}

static void test_device_id_mismatch_rejected(void)
{
    TEST("device_id_mismatch_rejected");
    /* A grant for device A must not be usable on device B, even with the same
     * firmware, buyer key, and (impossibly) matching nonce. */
    pki_t p; pki_setup(&p);
    mock_device_t a, b; mock_init(&a, 50, 50); mock_init(&b, 51, 51);
    ocm_session_t sa, sb; ocm_hello_t ha, hb;
    char ca[OCM_CODE_STR_LEN], cb[OCM_CODE_STR_LEN];
    ocm_grant_t g; uint8_t gw[OCM_GRANT_WIRE_LEN], blob[OCM_BLOB_WIRE_LEN];
    uint8_t bp[OCM_KEY_LEN], bv[OCM_KEY_LEN];

    CHECK(ocm_startup(mock_storage(&a), &sa, &ha, ca) == OCM_OK);
    CHECK(ocm_startup(mock_storage(&b), &sb, &hb, cb) == OCM_OK);
    ocm_buyer_keygen(bv, bp);
    make_grant(&p, &ha, bp, a.now + 600, 1, &g, gw);   /* grant for A */
    CHECK(ocm_claim(mock_storage(&b), &p.vendor, &sb, cb, bp,
                    gw, OCM_GRANT_WIRE_LEN, blob) == OCM_E_AUTH);
}

static void test_local_reset_recovers_corrupt_record(void)
{
    TEST("local_reset_recovers_corrupt_record");
    /* A single bit flip or a power glitch must not brick the device in the
     * field: the physical reset button has to be able to recover it. */
    mock_device_t d; mock_init(&d, 60, 60);
    CHECK(ocm_provision(mock_storage(&d)) == OCM_OK);
    mock_tamper_flash(&d, 30);

    ocm_session_t s; ocm_hello_t h; char c[OCM_CODE_STR_LEN];
    CHECK(ocm_boot(mock_storage(&d), &s, &h, c) == OCM_E_IO);   /* corrupt */

    /* Physical reset recovers it to a fresh, usable factory state. */
    CHECK(ocm_factory_reset_local(mock_storage(&d)) == OCM_OK);
    CHECK(ocm_boot(mock_storage(&d), &s, &h, c) == OCM_OK);
    CHECK(strcmp(c, "--------") != 0);
}

static void test_code_space_size(void)
{
    TEST("code_space_size");
    /* Document the brute-force cost assumption the design relies on. */
    CHECK(OCM_CODE_BYTES == 5);
    /* 2^40 alternatives; the back-off makes online guessing infeasible and an
     * offline attacker on one device's flash faces ~2^39 MACs at 50%. */
}

int main(void)
{
    if (ocm_init() != 0) { fprintf(stderr, "ocm_init failed\n"); return 2; }

    test_code_roundtrip();
    test_wire_roundtrip();
    test_provision_idempotent();
    test_provision_fails_closed();
    test_boot_before_provision();
    test_code_rotates_each_boot();
    test_unique_secret_per_device();
    test_full_claim();
    test_credential_unique_per_device();
    test_wrong_code_rejected();
    test_wrong_buyer_key_rejected();
    test_forged_grant_rejected();
    test_grant_replay_after_reboot_rejected();
    test_blob_relay_without_buyer_priv();
    test_expired_grant_rejected();
    test_backoff_and_lockout();
    test_no_double_claim();
    test_finalize_bad_receipt();
    test_reset_yields_new_secret();
    test_reset_requires_valid_grant();
    test_reset_burns_old_credential();
    test_tamper_detected();
    test_flash_holds_no_plaintext_secret();
    test_store_failure_is_safe();
    test_expiry_zero_means_no_expiry();
    test_reset_then_full_reclaim();
    test_hello_hides_pairing_when_commissioned();
    test_device_id_mismatch_rejected();
    test_local_reset_recovers_corrupt_record();
    test_code_space_size();

    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
