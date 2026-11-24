/*
 * buyer.c --- the purchaser app side, plus the reference service key helper.
 *
 * This is what runs on the purchaser's phone, not on the device. It holds
 * buyer_priv (generated once at account setup), receives the grant from the
 * cloud, and reads the per-boot code over the local link. It verifies the
 * grant against the vendor key, opens the blob, and returns the receipt that
 * lets the device finalize.
 *
 * The cloud operator never runs this and never has buyer_priv, so it never
 * sees K_dev. This is the property the whole scheme turns on: the service can
 * authorise *who may claim*, but cannot itself read the credential.
 */

#include <string.h>

#include "ocm_internal.h"

ocm_err_t ocm_buyer_keygen(uint8_t priv[OCM_KEY_LEN], uint8_t pub[OCM_KEY_LEN])
{
    if (!priv || !pub)
        return OCM_E_INVALID;
    if (ocm_random(priv, OCM_KEY_LEN) != 0)
        return OCM_E_IO;
    if (ocm_x25519_base(pub, priv) != 0) {
        ocm_secure_zero(priv, OCM_KEY_LEN);
        return OCM_E_IO;
    }
    return OCM_OK;
}

ocm_err_t ocm_buyer_accept(const uint8_t svc_pub[OCM_KEY_LEN],
                           const uint8_t buyer_priv[OCM_KEY_LEN],
                           const char *code_str,
                           const uint8_t *grant_wire, size_t grant_len,
                           const uint8_t *blob_wire, size_t blob_len,
                           uint8_t cred_out[OCM_SECRET_LEN],
                           uint8_t receipt_out[32])
{
    ocm_grant_t g;
    ocm_blob_t b;
    uint8_t sig[OCM_SIG_LEN], sb[OCM_GRANT_SIGNED_LEN], gh[32];
    uint8_t mypub[OCM_KEY_LEN], code_raw[OCM_CODE_BYTES];
    uint8_t shared[OCM_KEY_LEN], bkey[OCM_KEY_LEN];
    uint8_t kdev[OCM_SECRET_LEN], aad[OCM_BLOB_AAD_LEN];
    ocm_err_t e = OCM_E_AUTH;

    if (!svc_pub || !buyer_priv || !code_str || !grant_wire || !blob_wire ||
        !cred_out || !receipt_out)
        return OCM_E_INVALID;
    if (grant_len != OCM_GRANT_WIRE_LEN || blob_len != OCM_BLOB_WIRE_LEN)
        return OCM_E_INVALID;

    if (!ocm_grant_decode(&g, sig, grant_wire) ||
        !ocm_blob_decode(&b, blob_wire))
        return OCM_E_INVALID;

    /* 1. The grant really came from the vendor service. */
    ocm_grant_signed_bytes(&g, sb);
    if (!ocm_ed25519_verify(sig, sb, sizeof sb, svc_pub))
        return OCM_E_AUTH;
    if (g.type != OCM_GRANT_CLAIM)
        return OCM_E_AUTH;
    ocm_sha256(gh, sb, sizeof sb);

    /* 2. The grant names *our* key -- otherwise this is someone else's claim. */
    if (ocm_x25519_base(mypub, buyer_priv) != 0)
        return OCM_E_IO;
    if (memcmp(g.buyer_pub, mypub, OCM_KEY_LEN) != 0)
        return OCM_E_AUTH;

    /* 3. The blob is bound to the same grant (device id, epoch, counter). */
    if (memcmp(b.device_id, g.device_id, 16) != 0 ||
        memcmp(b.boot_epoch, g.boot_epoch, 2) != 0 ||
        memcmp(b.counter, g.counter, 4) != 0)
        return OCM_E_AUTH;

    /* 4. Derive the blob key: needs buyer_priv (here) AND the live code. */
    if (!ocm_code_decode(code_raw, code_str))
        return OCM_E_AUTH;
    if (ocm_x25519(shared, buyer_priv, b.eph_pub) != 0)
        return OCM_E_IO;
    ocm_derive_blobkey(shared, gh, code_raw, bkey);

    /* 5. Open the blob. Wrong code or wrong key => AEAD failure. */
    ocm_blob_aad(&b, aad);
    if (ocm_aead_open(kdev, b.tag, b.nonce, aad, sizeof aad,
                      b.ct, OCM_SECRET_LEN, bkey) != 0)
        goto out;

    memcpy(cred_out, kdev, OCM_SECRET_LEN);

    /* 6. Receipt proves we hold K_dev and binds the exact grant bytes. */
    ocm_derive_receipt(kdev, gh, receipt_out);
    e = OCM_OK;

out:
    ocm_secure_zero(kdev, sizeof kdev);
    ocm_secure_zero(bkey, sizeof bkey);
    ocm_secure_zero(shared, sizeof shared);
    ocm_secure_zero(code_raw, sizeof code_raw);
    return e;
}

/* ---- reference service helper (models the cloud HSM) --------------- */

ocm_err_t ocm_service_keygen(const uint8_t seed[OCM_KEY_LEN],
                             uint8_t pk[OCM_KEY_LEN],
                             uint8_t sk[OCM_SIG_LEN])
{
    if (!seed || !pk || !sk)
        return OCM_E_INVALID;
    return ocm_ed25519_keypair(seed, pk, sk) == 0 ? OCM_OK : OCM_E_IO;
}

ocm_err_t ocm_service_sign_grant(const uint8_t sk[OCM_SIG_LEN],
                                 const ocm_grant_t *grant,
                                 uint8_t sig_out[OCM_SIG_LEN])
{
    uint8_t sb[OCM_GRANT_SIGNED_LEN];

    if (!sk || !grant || !sig_out)
        return OCM_E_INVALID;
    ocm_grant_signed_bytes(grant, sb);
    return ocm_ed25519_sign(sig_out, sb, sizeof sb, sk) == 0
               ? OCM_OK : OCM_E_IO;
}
