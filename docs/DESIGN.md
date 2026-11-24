# Open Commissioning Model (OCM)

Device-unique bootstrap credentials for headless IoT devices.

---

## The problem this solves

Millions of cameras shipped with one shared default password. A botnet that
scans the internet for default credentials enrolled them all in a single sweep.
The regulatory fix is that **every device's initial credential must be unique**,
but the obvious implementations all collide with the physical constraints:

| Constraint | Naive "unique password per unit" |
|---|---|
| No screen, no keyboard | Can't display or type a password |
| The line can't write a per-unit secret | Serialised, slow, error-prone, needs a secure vault on the line |
| Resellers/installers handle the device | They would see or could copy the written password |
| Factory reset must not weaken security | Reset must not restore the shared default |
| Tiny flash, no secure element | Can't afford per-unit key material or an HSM in the device |

OCM's answer: **the device generates its own credential, and the credential is
delivered only to the buyer who is physically present and whose account the
cloud has bound to that device's serial.**

Nothing per-unit is written at the factory. The production line flashes one
image and moves on. Uniqueness comes from the device's hardware RNG, not from
the line.

---

## The flow, in one screen

```
  FACTORY LINE                DEVICE (first boot)              CLOUD / BUYER APP
  ------------                ------------------               -----------------
  flash one image    ───────► generate S (RNG)
  write nothing per unit      seal S under chip root key
  one barcode scan            derive P = X25519(S)
  -> order DB: serial->buyer  derive C = code(S,epoch,nonce)  ── programming ──┐
                                                                               │
                              show C on BLE/LED/NFC ──────────────────────────►│
                              send hello {id,epoch,nonce,P} ────────────────►│
                                                                              ▼
                                                         buyer app reads C,
                                                         posts {hello, C}
                                                         cloud checks:
                                                           order owns id?
                                                           C is live?
                                                         signs GRANT
                              ◄──────────── grant {id,epoch,nonce,P,buyer_pub,counter,expiry}
  STEP 1 verify grant (vendor key baked in)
         check live C, check app_pub==buyer_pub
         derive K_dev = HKDF(S, hash(grant))
         seal K_dev -> buyer_pub (blob key needs C too)
                              ───────────── blob ─────────────────────────────►
                                                            app opens blob:
                                                            needs buyer_priv + C
                                                            learns K_dev
                              ◄──────────── receipt = HMAC(K_dev, grant) ─────
  STEP 2 verify receipt
         burn S (overwrite with K_dev)
         store K_dev, become commissioned
```

After that the device is commissioned: it holds a credential that is unique to
it and that only the buyer's account ever saw. A second boot exposes no pairing
material at all.

---

## Why each requirement is met

**Unique per device, with nothing written per unit.**
`S` comes from the hardware RNG at first boot. Two devices with identical
firmware and identical blank flash get different `S`, hence different `P`,
different codes, and different `K_dev`. (Test: `unique_secret_per_device`,
`credential_unique_per_device`.)

**No screen or keyboard.**
The pairing code `C` is an 8-character Crockford-base32 string (40 bits),
shown over a short-range channel: BLE GATT after a setup-button press, an LED
blink sequence, or a tiny display if one exists. The buyer's phone app reads or
types it. No input device is needed on the camera.

**No per-unit production write.**
The line flashes the same image. The only per-unit act is scanning the serial
barcode into the order database — which most lines already do for
traceability. There is no secret to generate, store, or transport on the line.
Compromise of the line yields the firmware and public keys, not any device's
credential.

**Resellers and installers can't get the credential.**
An installer who holds the device in a warehouse can read `C` — but `C` is
worthless without (a) an account the cloud believes owns that serial, and (b) a
grant. The installer has neither. Even handed a valid grant, they cannot open
the blob: its key needs the buyer's **private** X25519 key *and* C. The
credential never exists anywhere except encrypted to the buyer. (Test:
`blob_relay_without_buyer_priv`.)

**Factory reset never returns to a guessable state.**
`ocm_factory_reset*` wipes the record and draws a **brand-new `S`** with a
bumped epoch. There is no code path that writes a default or reuses the old
secret. A reset device is as unique and unpredictable as a freshly built one.
(Test: `reset_yields_new_secret`, `reset_burns_old_credential`.)

**Tiny storage.**
Persistent state is one 73-byte authenticated record. Firmware embeds exactly
one 32-byte Ed25519 public key (the vendor service key). No per-device key
material is provisioned. (See `include/ocm.h` `OCM_RECORD_LEN`.)

---

## Design choices worth defending

**The pairing code is per-boot, not per-device.**
`C = HMAC(S, "code" || epoch || nonce)[:5]`, and `nonce` is fresh every boot.
So a code photographed in a warehouse, or logged by a compromised BLE sniffer,
does not work against a later boot. This closes the "pre-harvest the whole
shelf" attack that a static per-device code would allow.

**The code is a *key ingredient*, not a checked password.**
The blob is AEAD-sealed under a key derived from `(X25519 shared secret, grant
hash, C)`. Getting the code wrong doesn't merely fail a comparison — it makes
the blob undecryptable. That means even a fully malicious cloud cannot extract
`K_dev` for a device it never had physical access to.

**The device checks `app_pub == grant.buyer_pub`.**
A malicious cloud could otherwise issue a grant naming *its own* buyer key and
capture the credential. The device compares the grant's buyer key against the
key the app presents on the **local** link, so a substitution is rejected on
the device. (Test: `wrong_buyer_key_rejected`.)

**Two-step claim (blob, then receipt).**
Step 1 is idempotent and leaves `S` in place; only after the app proves it
decrypted `K_dev` (step 2) does the device burn `S`. A power loss or storage
failure between the steps is safe and retryable, and nothing half-committed
survives. (Test: `store_failure_is_safe`.)

**Reset is authority-gated when remote.**
A thief can't reset a stolen device to re-claim it: `ocm_factory_reset` demands
a service-signed RESET grant. The physical-button path
(`ocm_factory_reset_local`) is ungated because a thief who resets still can't
claim the device to their own account — ownership is enforced cloud-side.
(Tests: `reset_requires_valid_grant`, `reset_burns_old_credential`.)

**Back-off, not lockout.**
The first few wrong codes are free (typos happen). After that, exponential
back-off up to one hour makes online guessing of a 40-bit code pointless while
keeping the honest user unblocked. (Test: `backoff_and_lockout`.) There is no
permanent brick, so a forgotten code cannot produce an RMA avalanche.

**Failure is always closed.**
If the RNG, protected storage, or keystore is unavailable, provisioning and
boot return an error. There is deliberately **no fallback default secret** —
the exact failure that created the original problem. (Test:
`provision_fails_closed`.)

---

## Threat model summary

See `docs/THREAT_MODEL.md` for the full adversary-by-adversary table and the
residual risks we accept and why. The short version:

- **Default-password scanner / botnet:** finds nothing to guess. Credentials
  are unique and never leave the device except sealed to the buyer.
- **Network eavesdropper:** sees public wire objects only. No secret, no code,
  no `K_dev`.
- **Installer / reseller in transit:** sees a rotating, presence-only code.
  Cannot obtain the credential without an owning account and the buyer's key.
- **Thief who resets the device:** gets a fresh unique device they cannot
  provision (they can't sign grants) and cannot claim to their account.
- **Malicious cloud operator:** cannot read `K_dev`; cannot redirect it to
  another key (device checks `buyer_pub`).
- **Attacker with physical flash access:** must also defeat secure boot, debug
  lock, and the chip root key. Best case they own one device, not the fleet.

Residual, acknowledged risks: the cloud must bind serial→buyer correctly (a
mistake there is an ownership error, not a crypto break); and a party who holds
an unclaimed device *and* is the rightful owner in the database is, by
definition, the buyer.

---

## Layout

```
include/ocm.h          public API, wire formats, constants, design notes
include/ocm_internal.h private layout, derivations, record helpers
src/primitives.c       the entire crypto porting surface (libsodium backend)
src/codec.c            wire encoders/decoders + Crockford base32 code
src/derive.c           every key derivation, one auditable place
src/store.c            the 73-byte sealed persistent record
src/core.c             lifecycle: provision / boot / claim / finalize / reset
src/buyer.c            purchaser-app client + reference service key helper
sim/storage_mock.c     in-memory HAL that models flash vs. keystore separation
sim/flow_demo.c        narrated end-to-end run (make demo)
tests/test_ocm.c       127 assertions, mostly adversarial (make test)
docs/DESIGN.md         this document
docs/THREAT_MODEL.md   full threat analysis and residual risks
docs/PORTING.md        how to port primitives.c to mbedTLS/WolfSSL/PSA
docs/INTEGRATION.md    what the firmware, cloud, and app each must implement
```

## Build and run

Requires a C11 compiler and libsodium (`brew install libsodium` /
`apt install libsodium-dev`).

```
make          # build build/libocm.a
make demo     # narrated end-to-end protocol run
make test     # 127-assertion test suite (adversarial cases included)
```

The suite also runs clean under AddressSanitizer + UndefinedBehaviorSanitizer,
and a malformed-input stress run (200k random grants) accepts zero of them.
