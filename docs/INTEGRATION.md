# Integration guide

Who implements what, and the exact calls at each layer. OCM is the device-side
core plus a reference purchaser-app client; the cloud and the UI around it are
yours to build, but this page pins down the interfaces so the three sides agree.

---

## 1. Firmware / device

### Build-time

1. Embed the vendor service **public** key (32 bytes) produced by your HSM:
   ```c
   static const ocm_vendor_t k_vendor = { .svc_pub = { 0x.., ... } };
   ```
2. Implement `ocm_storage_t` against the SoC keystore/NVS (see `docs/PORTING.md`
   and `sim/storage_mock.c`).
3. Call `ocm_init()` once at startup before anything else.

### Boot sequence

```c
ocm_session_t sess;
ocm_hello_t   hello;
char          code[OCM_CODE_STR_LEN];

ocm_err_t e = ocm_startup(&st, &sess, &hello, code);   /* provisions if blank */
if (e != OCM_OK) {
    /* Fail closed. Do NOT bring up management with any default credential.
     * Log the error code; do not log `code`. */
}

if (ocm_is_commissioned(&st)) {
    uint8_t cred[OCM_SECRET_LEN];
    if (ocm_take_credential(&st, cred) == OCM_OK) {
        /* Move cred into your normal auth stack's key slot, then wipe it. */
        ocm_secure_zero(cred, sizeof cred);
    }
} else {
    /* Factory-fresh: expose the pairing flow. */
    /*  - advertise `code` on BLE after a setup-button press, and/or blink it;
     *  - keep `hello` in RAM to relay to the app over the local link;
     *  - never log or transmit `code`. */
}
```

`code` is `"XXXX-XXXX"` while factory-fresh and `"--------"` once commissioned.
It is a per-boot presence token; treating it as a secret to persist would be a
bug.

### The local link (device ↔ phone app)

This is the one channel not fully specified here, because it is deployment
specific. The requirements:

- It carries, from the device: the `hello` (83 bytes), and the `code` (only to
  a party physically at the device — e.g. shown on a display, or sent over BLE
  only after a physical button press, optionally with a BLE pairing/PIN for
  extra hygiene).
- It carries, from the app: the `app_pub` (32 bytes) so the device can later
  check `grant.buyer_pub == app_pub`.
- It carries, device ← app: the `grant` (188 bytes).
- It carries, device → app: the `blob` (115 bytes).
- It carries, app → device: the `receipt` (32 bytes).

Model each step with:

```c
/* device, step 1 */
uint8_t blob[OCM_BLOB_WIRE_LEN];
e = ocm_claim(&st, &k_vendor, &sess, code_from_user_or_ble, app_pub,
              grant_wire, OCM_GRANT_WIRE_LEN, blob);
/* ... send blob to app, receive receipt ... */
/* device, step 2 */
e = ocm_finalize(&st, &k_vendor, &sess, grant_wire, OCM_GRANT_WIRE_LEN, receipt);
```

`ocm_claim` is safe to call repeatedly and is rate-limited on bad codes; a
relayed blob is useless without the app's private key and the code.

### Factory reset

- Physical service button → `ocm_factory_reset_local(&st)`. Ungated; yields a
  brand-new unique secret and epoch+1.
- Remote/operator command → obtain a RESET grant from the cloud
  (`ocm_service_sign_grant` with `type = OCM_GRANT_RESET`, bound to the device
  id) and call `ocm_factory_reset(&st, &k_vendor, grant, len)`.

After either, the device is factory-fresh again and will re-provision on the
next boot.

---

## 2. Cloud service

### At packing / order creation

- Scan the device serial barcode; record `serial → order → buyer_account`.
  **This binding is the trust anchor for ownership.** Make it auditable.
- You do **not** generate, store, or ship any per-device secret.

### At claim time

1. App (authenticated as the buyer) posts `{hello, code, app_pub}` and the
   order reference.
2. Verify the order belongs to this buyer and names `hello.device_id`.
3. Verify the code corresponds to this `(device_id, epoch, nonce, P)`. You
   cannot recompute `C` (you don't have `S`), so verification is by the device
   accepting the grant built from this hello — you simply bind the hello
   verbatim into the grant. Anti-abuse: rate-limit claims per device and per
   account; reject a hello whose `epoch`/`nonce` you have seen claimed before.
4. Build and sign the grant with the HSM key:

   ```c
   ocm_grant_t g = {0};
   g.type = OCM_GRANT_CLAIM;
   memcpy(g.boot_epoch,  hello.boot_epoch, 2);
   memcpy(g.device_id,   hello.device_id, 16);
   memcpy(g.nonce,       hello.nonce, OCM_SESS_NONCE_LEN);
   memcpy(g.pairing_pub, hello.pairing_pub, OCM_KEY_LEN);
   memcpy(g.buyer_pub,   app_pub, OCM_KEY_LEN);
   ocm_wr32(g.counter, next_rotation_counter());   /* your monotonic counter */
   ocm_wr32(g.expiry,  now() + 600);               /* short claim window     */
   uint8_t sig[OCM_SIG_LEN];
   ocm_service_sign_grant(svc_sk, &g, sig);        /* inside the HSM        */
   uint8_t wire[OCM_GRANT_WIRE_LEN];
   ocm_grant_encode(&g, sig, wire);
   ```

   `ocm_service_sign_grant` runs where `svc_sk` lives (HSM or a signer with the
   key pinned); the plaintext key never sits on a web server.

5. Return `wire` to the app. Relay the app's `blob`/`receipt` to the device
   only if your topology needs the cloud to act as a relay; ideally the app
   talks to the device directly over the local link and the blob never reaches
   you.

### At reset / re-claim

- Same as above with `type = OCM_GRANT_RESET` for a gated reset, or simply let
  the user press the physical button for a local reset.
- After a reset the device's `epoch` increments; the next claim uses a fresh
  hello, so old grants never apply.

### Rotation

The grant carries a `counter`; record it per device. If you later rotate the
long-term credential, derive a new one from the current `K_dev` (which only the
device and buyer hold) — the cloud still never needs the secret. The simplest
v1 is: no rotation; a reset produces a wholly new credential.

---

## 3. Purchaser app

The app is the only place `K_dev` is ever decrypted. It holds `buyer_priv`
(generate once per account/device with `ocm_buyer_keygen`, store in the phone
keystore).

```c
/* Read `code` from the device (local link / typed), fetch `grant_wire`
 * from the cloud, receive `blob` from the device. */
uint8_t cred[OCM_SECRET_LEN], receipt[32];
ocm_err_t e = ocm_buyer_accept(svc_pub,                /* embedded constant */
                               buyer_priv,
                               code,
                               grant_wire, OCM_GRANT_WIRE_LEN,
                               blob, OCM_BLOB_WIRE_LEN,
                               cred, receipt);
if (e == OCM_OK) {
    /* Hand receipt to the device to finalize; store cred securely (or let the
     * device keep it and use it as the management PSK). */
}
```

`ocm_buyer_accept` verifies the grant against the vendor public key, checks the
grant names this app's key, and opens the blob using the private key and the
code. A wrong code or a redirected grant fails here.

---

## 4. Error codes (all `< 0`)

| Code | Meaning | Typical action |
|---|---|---|
| `OCM_E_STATE` | Not provisioned / not commissioned where required | Provision / finish claiming |
| `OCM_E_AUTH` | Bad code, bad proof, bad signature, wrong buyer | Re-check the code; re-request a grant |
| `OCM_E_BACKOFF` | Too many bad codes; wait | Show "wait N seconds" |
| `OCM_E_INVALID` | Malformed input / missing HAL | Programming error |
| `OCM_E_IO` | Storage or RNG failure | Fail closed; do not proceed |
| `OCM_E_LIFECYCLE` | Claim before boot, double claim | Ignore / re-boot |
| `OCM_E_EXPIRED` | Grant past expiry | Request a fresh grant |

---

## 5. Do / don't

- **Do** keep `code` ephemeral; it rotates every boot.
- **Do** run the device's secret only from the RNG, and fail closed on RNG error.
- **Do** keep `svc_sk` in an HSM; sign grants where the key lives.
- **Do** make the serial→buyer scan verifiable and audited.
- **Don't** ever log `S`, `C`, `K_dev`, or `buyer_priv`.
- **Don't** add a "convenience" default credential path. That is the bug this
  design exists to remove.
- **Don't** persist the pairing code; recompute it from `S` on each boot.
