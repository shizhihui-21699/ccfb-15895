/*
 * ocm.h --- Open Commissioning Model
 *
 * Device-unique bootstrap credentials for headless IoT devices.
 * Read docs/DESIGN.md and docs/THREAT_MODEL.md before changing this header.
 *
 * ---------------------------------------------------------------------------
 * The design in one paragraph
 * ---------------------------------------------------------------------------
 * A factory device ships with one firmware image and blank storage: nothing
 * per-unit is written on the line.  On first boot the device draws a 32-byte
 * master secret S from its hardware RNG and seals it under a key only that
 * chip can obtain (HUK / eFuse-backed keystore / secure element).  S is never
 * printed and never transmitted.  From S the device derives
 *
 *     x    = HKDF(S,"x25519")            its pairing private key
 *     P    = X25519_base(x)              its public pairing key
 *     C    = base32( HMAC(S,"code"||epoch||nonce)[:5] )
 *                                        an 8-char PAIRING CODE
 *
 * C is a PER-BOOT code: it changes every boot because the boot nonce changes.
 * It is exposed only on a short-range physical channel (BLE GATT after a
 * setup-button press, LED blink, or a small display).  The device reports to
 * the cloud only {device_id, epoch, nonce, P} -- never C.
 *
 * The purchaser's account, bound to the device serial in the cloud order
 * database (one barcode scan at packing, not a per-unit secret write), obtains
 * a CLAIM GRANT signed by the vendor service key.  The grant binds
 * {device_id, epoch, nonce, P, counter, expiry, buyer_pub}, where buyer_pub is
 * the X25519 key of the purchaser's app.  The device verifies the grant against
 * the vendor public key compiled into firmware, checks that the app on the
 * LOCAL link holds the live code C and that its key equals grant.buyer_pub,
 * derives the long-term credential K_dev from S and the grant hash, and seals
 * K_dev into an AEAD blob whose key requires the purchaser's private key (via
 * X25519), the grant, and C.  The app -- physically present, holding
 * buyer_priv, and having read C over the local link -- opens the blob, obtains
 * K_dev, and returns a receipt.  Only then does the device burn S and store
 * K_dev.
 *
 * Why two independent factors are required:
 *   - order binding in the cloud answers "WHO may claim this device";
 *   - the per-boot code answers "is the claimer physically AT the device NOW".
 * A reseller whose account still owns warehouse stock cannot mass-claim it
 * remotely (it would need to read each device's rotating code in person), and a
 * compromised cloud operator cannot silently bind devices without presence.
 * Because the credential is unique per device (S is), a botnet's
 * default-password sweep finds nothing, and a factory reset always draws a new
 * S -- there is no shared or guessable state to return to.
 *
 * ---------------------------------------------------------------------------
 * Honest limitations -- see THREAT_MODEL.md
 * ---------------------------------------------------------------------------
 *  - The cloud is trusted to bind serial -> account correctly (ownership). It
 *    is NOT trusted for confidentiality: it never learns S, C, or K_dev.
 *  - Protected storage must resist extraction, with secure boot and debug lock
 *    on.  Reading one device's protected storage compromises that device, not
 *    the fleet.
 *  - If an attacker holds an UNCLAIMED device in hand and also has an account
 *    the cloud believes owns it, they can claim that one device.  No scheme
 *    that avoids per-unit provisioning and a screen/keyboard can prevent the
 *    physical holder who is also the rightful owner in the database from
 *    enrolling.  Order binding must therefore be correct.
 *  - The device trusts exactly one vendor service public key.  A thief who
 *    resets a stolen device and stands up their own "cloud" cannot provision
 *    it, because they cannot sign grants with the vendor key.
 */

#ifndef OCM_H
#define OCM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Tunables                                                           */
/* ------------------------------------------------------------------ */

#define OCM_KEY_LEN        32u   /* X25519 / Ed25519 / SHA-256 width        */
#define OCM_SECRET_LEN     32u   /* master secret S and credential K_dev    */
#define OCM_SIG_LEN        64u   /* Ed25519 signature                       */
#define OCM_TAG_LEN        16u   /* ChaCha20-Poly1305 tag                   */
#define OCM_NONCE_LEN      12u   /* ChaCha20-Poly1305 nonce                 */
#define OCM_SESS_NONCE_LEN 32u   /* per-boot wire nonce                     */

/*
 * The only persistent state: ChaCha20-Poly1305(nonce12 || ct45 || tag16).
 * 45-byte plaintext = ver(1) || epoch(2) || counter(4) || secret(32) ||
 *                     state(1) || failures(1) || last_fail(4).
 */
#define OCM_RECORD_LEN     73u

#define OCM_CODE_BYTES     5u    /* 40 bits of pairing-code entropy         */
#define OCM_CODE_CHARS     8u    /* Crockford base32, printed "XXXX-XXXX"   */
#define OCM_CODE_STR_LEN   10u   /* "XXXX-XXXX" + NUL                       */

#define OCM_FREE_ATTEMPTS  3u    /* bad codes tolerated before back-off      */
#define OCM_BACKOFF_BASE_S 5u    /* first retry delay once back-off starts    */
#define OCM_BACKOFF_MAX_S  3600u /* cap on retry delay                        */

#define OCM_HELLO_WIRE_LEN   83u /* 1+2+16+32+32                            */
#define OCM_GRANT_SIGNED_LEN 124u /* 1+1+2+4+4+16+32+32+32                  */
#define OCM_GRANT_WIRE_LEN  188u /* OCM_GRANT_SIGNED_LEN + 64               */
#define OCM_BLOB_WIRE_LEN   115u /* 1+2+4+16+32+12+32+16                    */

/* Error codes; all negative so callers may test `< 0`. */
typedef enum {
    OCM_OK          =  0,
    OCM_E_STATE     = -1,  /* not provisioned / wrong lifecycle state  */
    OCM_E_AUTH      = -2,  /* bad code, bad proof, bad signature       */
    OCM_E_BACKOFF   = -3,  /* wait before retrying                     */
    OCM_E_INVALID   = -4,  /* malformed / wrong-size input, bad HAL    */
    OCM_E_IO        = -5,  /* storage or RNG failure                   */
    OCM_E_LIFECYCLE = -6,  /* claim before boot, double claim, ...     */
    OCM_E_EXPIRED   = -7   /* grant past its expiry                    */
} ocm_err_t;

/* ------------------------------------------------------------------ */
/* Crypto primitives -- the entire porting surface.                   */
/* primitives.c implements these with libsodium for the reference     */
/* build; re-implement exactly these with mbedTLS/WolfSSL/PSA for a   */
/* real firmware. See docs/PORTING.md.                                */
/* ------------------------------------------------------------------ */

int  ocm_init(void);                      /* call once at startup */

int  ocm_random(uint8_t *out, size_t len);
void ocm_sha256(uint8_t out[32], const uint8_t *data, size_t len);
/* RFC 5869 HKDF-SHA256; out_len must be 1..32 (all uses here are 32). */
int  ocm_hkdf_sha256(uint8_t *out, size_t out_len,
                     const uint8_t *ikm, size_t ikm_len,
                     const uint8_t *salt, size_t salt_len,
                     const uint8_t *info, size_t info_len);
void ocm_hmac_sha256(uint8_t out[32],
                     const uint8_t *key, size_t key_len,
                     const uint8_t *data, size_t data_len);
int  ocm_x25519(uint8_t out[OCM_KEY_LEN],
                const uint8_t scalar[OCM_KEY_LEN],
                const uint8_t point[OCM_KEY_LEN]);
int  ocm_x25519_base(uint8_t out[OCM_KEY_LEN],
                     const uint8_t scalar[OCM_KEY_LEN]);
/* ChaCha20-Poly1305 (IETF, 96-bit nonce). Return 0 on success, neg on error. */
int  ocm_aead_seal(uint8_t *ct, uint8_t tag[OCM_TAG_LEN],
                   const uint8_t nonce[OCM_NONCE_LEN],
                   const uint8_t *aad, size_t aad_len,
                   const uint8_t *pt, size_t pt_len,
                   const uint8_t key[OCM_KEY_LEN]);
int  ocm_aead_open(uint8_t *pt,
                   const uint8_t tag[OCM_TAG_LEN],
                   const uint8_t nonce[OCM_NONCE_LEN],
                   const uint8_t *aad, size_t aad_len,
                   const uint8_t *ct, size_t ct_len,
                   const uint8_t key[OCM_KEY_LEN]);
int  ocm_ed25519_verify(const uint8_t sig[OCM_SIG_LEN],
                        const uint8_t *msg, size_t msg_len,
                        const uint8_t pk[OCM_KEY_LEN]);
/* Signing is used only by the reference service; devices never sign. */
int  ocm_ed25519_keypair(const uint8_t seed[OCM_KEY_LEN],
                         uint8_t pk[OCM_KEY_LEN],
                         uint8_t sk[OCM_SIG_LEN]);
int  ocm_ed25519_sign(uint8_t sig[OCM_SIG_LEN],
                      const uint8_t *msg, size_t msg_len,
                      const uint8_t sk[OCM_SIG_LEN]);
int  ocm_ct_equal(const uint8_t *a, const uint8_t *b, size_t len);
void ocm_secure_zero(void *p, size_t len);

/* ------------------------------------------------------------------ */
/* Device persistence: the HAL the firmware must supply.              */
/*                                                                    */
/*   load      -> 1 if a record exists (fills buf); 0 otherwise.      */
/*   store     -> atomically persist exactly OCM_RECORD_LEN bytes;    */
/*                must be power-fail safe (journal/NVS/double-buffer).*/
/*   wipe      -> erase; idempotent.                                  */
/*   device_id -> 16-byte stable id from eFuse/serial. NOT a secret;  */
/*                it is bound into the record key and into grants.    */
/*   root_key  -> 32 bytes only this chip can obtain from its         */
/*                protected keystore. MUST NOT derive from device_id. */
/*   now_s     -> coarse wall clock (seconds). Only bounds back-off   */
/*                and grant expiry; a wrong clock cannot break        */
/*                confidentiality or uniqueness.                      */
/* Any of these may be NULL only if the corresponding operation is    */
/* never invoked; the core fails closed (OCM_E_INVALID) otherwise.    */
/* ------------------------------------------------------------------ */

typedef struct {
    int      (*load)(void *ctx, uint8_t buf[OCM_RECORD_LEN]);
    int      (*store)(void *ctx, const uint8_t buf[OCM_RECORD_LEN]);
    int      (*wipe)(void *ctx);
    int      (*device_id)(void *ctx, uint8_t out[16]);
    int      (*root_key)(void *ctx, uint8_t out[OCM_KEY_LEN]);
    uint32_t (*now_s)(void *ctx);
    void     *ctx;
} ocm_storage_t;

/* Vendor public keys compiled into firmware. */
typedef struct {
    uint8_t svc_pub[OCM_KEY_LEN];   /* verifies claim / reset grants */
} ocm_vendor_t;

/* ------------------------------------------------------------------ */
/* Wire objects (all big-endian, leading version byte = 1)            */
/* ------------------------------------------------------------------ */

typedef struct {
    uint8_t boot_epoch[2];
    uint8_t device_id[16];
    uint8_t nonce[OCM_SESS_NONCE_LEN];      /* fresh every boot           */
    uint8_t pairing_pub[OCM_KEY_LEN];       /* X25519_base(x); 0 if done  */
} ocm_hello_t;

enum { OCM_GRANT_CLAIM = 1, OCM_GRANT_RESET = 2 };

typedef struct {
    uint8_t type;
    uint8_t boot_epoch[2];
    uint8_t counter[4];
    uint8_t expiry[4];                      /* unix seconds (BE; 0 = none) */
    uint8_t device_id[16];
    uint8_t nonce[OCM_SESS_NONCE_LEN];
    uint8_t pairing_pub[OCM_KEY_LEN];
    uint8_t buyer_pub[OCM_KEY_LEN];         /* purchaser app X25519        */
} ocm_grant_t;

/* Device -> purchaser credential delivery. */
typedef struct {
    uint8_t boot_epoch[2];
    uint8_t counter[4];
    uint8_t device_id[16];
    uint8_t eph_pub[OCM_KEY_LEN];           /* device ephemeral X25519     */
    uint8_t nonce[OCM_NONCE_LEN];
    uint8_t ct[OCM_SECRET_LEN];             /* K_dev sealed to buyer_pub   */
    uint8_t tag[OCM_TAG_LEN];
} ocm_blob_t;

void ocm_hello_encode(const ocm_hello_t *h, uint8_t out[OCM_HELLO_WIRE_LEN]);
int  ocm_hello_decode(ocm_hello_t *h, const uint8_t in[OCM_HELLO_WIRE_LEN]);
void ocm_grant_encode(const ocm_grant_t *g, const uint8_t sig[OCM_SIG_LEN],
                      uint8_t out[OCM_GRANT_WIRE_LEN]);
int  ocm_grant_decode(ocm_grant_t *g, uint8_t sig[OCM_SIG_LEN],
                      const uint8_t in[OCM_GRANT_WIRE_LEN]);
void ocm_blob_encode(const ocm_blob_t *b, uint8_t out[OCM_BLOB_WIRE_LEN]);
int  ocm_blob_decode(ocm_blob_t *b, const uint8_t in[OCM_BLOB_WIRE_LEN]);

/* Pairing code: 5 raw bytes <-> "XXXX-XXXX" (Crockford base32).
 * decode() accepts lower case, treats I/L as 1 and O as 0, ignores '-'. */
void ocm_code_encode(const uint8_t raw[OCM_CODE_BYTES],
                     char out[OCM_CODE_STR_LEN]);
int  ocm_code_decode(uint8_t raw[OCM_CODE_BYTES], const char *code);

/* ------------------------------------------------------------------ */
/* RAM-only boot session.  Produced by ocm_boot() and consumed by     */
/* ocm_claim()/ocm_finalize(). Keeping the boot nonce here (not in a  */
/* caller-supplied hello) is what makes replay of a grant from an     */
/* earlier boot impossible.  Never persist or transmit it.            */
/* ------------------------------------------------------------------ */

typedef struct {
    int      valid;
    uint16_t epoch;
    uint8_t  device_id[16];
    uint8_t  nonce[OCM_SESS_NONCE_LEN];
    uint8_t  pairing_pub[OCM_KEY_LEN];
    uint8_t  code_raw[OCM_CODE_BYTES];
} ocm_session_t;

/* ------------------------------------------------------------------ */
/* Device lifecycle                                                   */
/* ------------------------------------------------------------------ */

int ocm_is_provisioned(ocm_storage_t *st);   /* 1 if a record exists    */
int ocm_is_commissioned(ocm_storage_t *st);  /* 1 if K_dev is installed */

/*
 * First-boot provisioning. Idempotent: returns OCM_E_LIFECYCLE if a record
 * already exists. Fails closed (OCM_E_IO) if the RNG or protected storage
 * fails; there is deliberately no fallback to any default secret.
 */
ocm_err_t ocm_provision(ocm_storage_t *st);

/*
 * Every boot after provisioning. Emits the hello the local app relays to the
 * cloud and, while still factory-fresh, the pairing code to expose on a
 * short-range physical channel. When commissioned, pairing_pub is zero and
 * code_out is filled with "--------".
 */
ocm_err_t ocm_boot(ocm_storage_t *st, ocm_session_t *session,
                   ocm_hello_t *hello_out, char code_out[OCM_CODE_STR_LEN]);

/* Convenience: provision on first boot if absent, then boot. */
ocm_err_t ocm_startup(ocm_storage_t *st, ocm_session_t *session,
                      ocm_hello_t *hello_out, char code_out[OCM_CODE_STR_LEN]);

/*
 * Claim step 1. Verifies the CLAIM grant against this boot's session, checks
 * the live per-boot pairing code in constant time (rate-limited on failure),
 * and checks that the app on the local link (app_pub) is exactly the buyer the
 * grant names, so a malicious cloud cannot redirect the credential. Derives
 * K_dev and emits the blob sealed to buyer_pub under a key that also requires
 * the live code -- which only a party physically at the device can read. The
 * device stays factory-fresh (S retained); relaying the blob gains an observer
 * nothing without buyer_priv and the code.
 */
ocm_err_t ocm_claim(ocm_storage_t *st, const ocm_vendor_t *vendor,
                    const ocm_session_t *session,
                    const char *code_str,
                    const uint8_t app_pub[OCM_KEY_LEN],
                    const uint8_t *grant_wire, size_t grant_len,
                    uint8_t blob_out[OCM_BLOB_WIRE_LEN]);

/*
 * Claim step 2. The app proves it opened the blob with
 *   receipt = HMAC-SHA256(K_dev, "receipt" || SHA256(grant_signed_bytes)).
 * On success the device burns S (overwrites it with K_dev), stores K_dev
 * sealed and becomes commissioned.
 */
ocm_err_t ocm_finalize(ocm_storage_t *st, const ocm_vendor_t *vendor,
                       const ocm_session_t *session,
                       const uint8_t *grant_wire, size_t grant_len,
                       const uint8_t receipt[32]);

/*
 * Factory reset on authority request: verifies a service-signed RESET grant
 * (so a thief cannot reset a stolen device and re-claim it), then erases and
 * re-provisions with a BRAND-NEW secret and epoch+1.
 */
ocm_err_t ocm_factory_reset(ocm_storage_t *st, const ocm_vendor_t *vendor,
                            const uint8_t *reset_grant_wire, size_t len);

/*
 * Local factory reset (physical service button). Same re-provisioning
 * guarantee and no grant required: ownership is enforced cloud-side, so a
 * thief who resets a stolen device still cannot claim it to their account.
 */
ocm_err_t ocm_factory_reset_local(ocm_storage_t *st);

/* Copy the long-term credential into the firmware's own key slot. */
ocm_err_t ocm_take_credential(ocm_storage_t *st, uint8_t out[OCM_SECRET_LEN]);

/* ------------------------------------------------------------------ */
/* Purchaser app client (reference)                                   */
/* ------------------------------------------------------------------ */

ocm_err_t ocm_buyer_keygen(uint8_t priv[OCM_KEY_LEN], uint8_t pub[OCM_KEY_LEN]);

/*
 * Verify the cloud's grant, open the device blob to obtain K_dev, and produce
 * the receipt that finalizes the claim. Exactly what the purchaser's phone app
 * does with the code it read from the device. The cloud operator does not run
 * this and never sees K_dev.
 */
ocm_err_t ocm_buyer_accept(const uint8_t svc_pub[OCM_KEY_LEN],
                           const uint8_t buyer_priv[OCM_KEY_LEN],
                           const char *code_str,
                           const uint8_t *grant_wire, size_t grant_len,
                           const uint8_t *blob_wire, size_t blob_len,
                           uint8_t cred_out[OCM_SECRET_LEN],
                           uint8_t receipt_out[32]);

/* ------------------------------------------------------------------ */
/* Reference service helpers (NOT device code). Used by sim/ and tests*/
/* to model the cloud signing a grant.                                */
/* ------------------------------------------------------------------ */

ocm_err_t ocm_service_keygen(const uint8_t seed[OCM_KEY_LEN],
                             uint8_t pk[OCM_KEY_LEN],
                             uint8_t sk[OCM_SIG_LEN]);
/* Fill grant.type/epoch/counter/expiry/device_id/nonce/pairing_pub/buyer_pub,
 * then sign. Convenience wrapper that sets the fields and signs in one go. */
ocm_err_t ocm_service_sign_grant(const uint8_t sk[OCM_SIG_LEN],
                                 const ocm_grant_t *grant,
                                 uint8_t sig_out[OCM_SIG_LEN]);

#ifdef __cplusplus
}
#endif
#endif /* OCM_H */
