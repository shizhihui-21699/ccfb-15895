/*
 * flow_demo.c --- a narrated end-to-end run of the protocol.
 *
 * It plays every role: the factory line, the device, the purchaser's app, and
 * the cloud service. Each step prints what crosses each boundary, so you can
 * watch exactly what a reseller, a network eavesdropper, and the cloud each get
 * to see -- and what none of them ever see.
 *
 * Build: make demo     Run: ./build/flow_demo
 */

#include <stdio.h>
#include <string.h>

#include "ocm.h"
#include "storage_mock.h"

static void hex(const char *label, const uint8_t *p, size_t n)
{
    printf("    %-14s ", label);
    for (size_t i = 0; i < n; i++)
        printf("%02x", p[i]);
    printf("\n");
}

int main(void)
{
    mock_device_t dev;
    ocm_vendor_t  vendor;
    ocm_session_t sess;
    ocm_hello_t   hello;
    char          code[OCM_CODE_STR_LEN];
    ocm_grant_t   grant;
    uint8_t       sig[OCM_SIG_LEN], grant_wire[OCM_GRANT_WIRE_LEN];
    uint8_t       blob[OCM_BLOB_WIRE_LEN];
    uint8_t       receipt[32], cred[OCM_SECRET_LEN], got[OCM_SECRET_LEN];
    uint8_t       buyer_priv[OCM_KEY_LEN], buyer_pub[OCM_KEY_LEN];
    uint8_t       svc_pk[OCM_KEY_LEN], svc_sk[OCM_SIG_LEN];
    uint8_t       seed[OCM_KEY_LEN];
    uint8_t       hello_wire[OCM_HELLO_WIRE_LEN];
    ocm_err_t     e;

    if (ocm_init() != 0) { fprintf(stderr, "crypto init failed\n"); return 1; }

    /* --- Provisioning time (one offline step, NOT per unit) ---------- */
    puts("== Vendor setup (once, offline; not on the production line) ==");
    memset(seed, 0x42, sizeof seed);            /* HSM-managed in production */
    ocm_service_keygen(seed, svc_pk, svc_sk);
    memcpy(vendor.svc_pub, svc_pk, OCM_KEY_LEN);
    hex("svc public key", vendor.svc_pub, OCM_KEY_LEN);
    puts("  Firmware embeds only svc_pub. svc_sk stays in the HSM.\n");

    /* --- Factory line: identical image, blank storage ---------------- */
    puts("== Factory line: flash identical firmware, write nothing per unit ==");
    mock_init(&dev, 0x10, 0x31);               /* silicon id + chip root key */
    printf("  device_id (from eFuse, single barcode scan for the order DB): ");
    for (int i = 0; i < 16; i++) printf("%02x", dev.device_id[i]);
    printf("\n\n");

    /* --- First boot on the purchaser's premises --------------------- */
    puts("== First boot (on purchaser's premises) ==");
    e = ocm_startup(mock_storage(&dev), &sess, &hello, code);
    printf("  ocm_startup: %d\n", e);
    printf("  pairing code shown on device (BLE after button / LED): %s\n", code);
    ocm_hello_encode(&hello, hello_wire);
    puts("  device -> cloud: hello (what leaves the device):");
    hex("device_id", hello.device_id, 16);
    hex("nonce", hello.nonce, OCM_SESS_NONCE_LEN);
    hex("pairing_pub P", hello.pairing_pub, OCM_KEY_LEN);
    puts("  NOTE: the pairing code itself is NOT in the hello.\n");

    /* --- Purchaser app: account + order + code ---------------------- */
    puts("== Purchaser app ==");
    ocm_buyer_keygen(buyer_priv, buyer_pub);
    hex("buyer_pub", buyer_pub, OCM_KEY_LEN);
    puts("  app reads the code over the LOCAL link and sends it to the cloud,");
    puts("  together with the hello. The cloud checks the order owns device_id.\n");

    /* --- Cloud: verify presence, sign a grant ----------------------- */
    puts("== Cloud service (models the HSM) ==");
    memset(&grant, 0, sizeof grant);
    grant.type = OCM_GRANT_CLAIM;
    grant.boot_epoch[0] = 0; grant.boot_epoch[1] = 0;
    grant.counter[3] = 1;
    {
        uint32_t exp = dev.now + 600;           /* 10-minute claim window */
        grant.expiry[0] = (uint8_t)(exp >> 24); grant.expiry[1] = (uint8_t)(exp >> 16);
        grant.expiry[2] = (uint8_t)(exp >> 8);  grant.expiry[3] = (uint8_t)exp;
    }
    memcpy(grant.device_id, hello.device_id, 16);
    memcpy(grant.nonce, hello.nonce, OCM_SESS_NONCE_LEN);
    memcpy(grant.pairing_pub, hello.pairing_pub, OCM_KEY_LEN);
    memcpy(grant.buyer_pub, buyer_pub, OCM_KEY_LEN);
    ocm_service_sign_grant(svc_sk, &grant, sig);
    ocm_grant_encode(&grant, sig, grant_wire);
    puts("  signed grant (binds device, boot nonce, P, buyer key, expiry):");
    hex("device_id", grant.device_id, 16);
    hex("nonce", grant.nonce, OCM_SESS_NONCE_LEN);
    hex("buyer_pub", grant.buyer_pub, OCM_KEY_LEN);
    puts("  cloud -> app: grant (public, verifiable offline)\n");

    /* --- Device: step 1, issue the sealed blob ---------------------- */
    puts("== Device: claim step 1 ==");
    e = ocm_claim(mock_storage(&dev), &vendor, &sess, code, buyer_pub,
                  grant_wire, OCM_GRANT_WIRE_LEN, blob);
    printf("  ocm_claim (device verifies grant + live code + buyer key): %d\n", e);
    puts("  device -> app: blob (K_dev sealed to buyer_pub, keyed by the code)");
    puts("  A relay of this blob is useless without buyer_priv AND the code.\n");

    /* --- App: open the blob, build the receipt ---------------------- */
    puts("== Purchaser app: open the blob ==");
    e = ocm_buyer_accept(svc_pk, buyer_priv, code, grant_wire,
                         OCM_GRANT_WIRE_LEN, blob, OCM_BLOB_WIRE_LEN,
                         cred, receipt);
    printf("  ocm_buyer_accept (verify grant, decrypt K_dev): %d\n", e);
    if (e == OCM_OK) {
        hex("K_dev (secret!)", cred, OCM_SECRET_LEN);
        hex("receipt", receipt, 32);
    }
    puts("  app -> device: receipt (proves the app holds K_dev)\n");

    /* --- Device: step 2, burn S and commit -------------------------- */
    puts("== Device: claim step 2 (finalize) ==");
    e = ocm_finalize(mock_storage(&dev), &vendor, &sess,
                     grant_wire, OCM_GRANT_WIRE_LEN, receipt);
    printf("  ocm_finalize (burns S, stores K_dev): %d\n", e);
    printf("  commissioned now? %s\n", ocm_is_commissioned(mock_storage(&dev))
                                             ? "yes" : "no");
    e = ocm_take_credential(mock_storage(&dev), got);
    printf("  device's stored credential matches app's K_dev? %s\n",
           (e == OCM_OK && memcmp(got, cred, OCM_SECRET_LEN) == 0) ? "yes" : "NO");
    puts("");

    /* --- What an attacker with the flash sees ----------------------- */
    puts("== Attacker who desoldered the flash ==");
    {
        uint8_t dump[OCM_RECORD_LEN];
        mock_flash_dump(&dev, dump);
        hex("flash (all of it)", dump, OCM_RECORD_LEN);
        puts("  No plaintext secret, no K_dev. Without the chip root key and");
        puts("  secure boot off, this is the whole attack surface -- and it");
        puts("  yields one device, not the fleet.");
    }
    puts("");

    /* --- Boot again: commissioned device exposes nothing ----------- */
    puts("== Next boot (commissioned) ==");
    e = ocm_boot(mock_storage(&dev), &sess, &hello, code);
    printf("  ocm_boot: %d, code shown: %s (no claim possible)\n", e, code);

    ocm_secure_zero(cred, sizeof cred);
    ocm_secure_zero(got, sizeof got);
    ocm_secure_zero(buyer_priv, sizeof buyer_priv);
    ocm_secure_zero(svc_sk, sizeof svc_sk);
    return 0;
}
