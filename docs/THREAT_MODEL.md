# Threat model

This document states the adversaries, what each can and cannot do, and the
residual risks we accept. It is the security contract for the implementation in
`src/`. Each claim references the test that exercises it.

---

## 1. Assets

| Asset | Where it lives | Who may see it |
|---|---|---|
| Bootstrap secret `S` | Device protected storage only | Nobody, ever (not even the cloud) |
| Device credential `K_dev` | Device storage after claim; buyer app after claim | Device, buyer app |
| Pairing code `C` | On-device display/BLE; buyer app memory | Whoever is physically at the device |
| Vendor service signing key `svc_sk` | Cloud HSM | Cloud only |
| Vendor public keys | Compiled into firmware | Public |

The thing that made the original deployment catastrophic — one secret shared
across millions of devices — does not exist here. `S` and `K_dev` are unique per
device by construction (see §2).

---

## 2. Uniqueness and unpredictability

`S` ← hardware RNG at first boot. Two devices with identical firmware and
identical blank flash produce different `S`, therefore different `P`, `C`, and
`K_dev`.

- Test: `unique_secret_per_device` (same firmware, same flash → different P/C).
- Test: `credential_unique_per_device` (same buyer key, same counter → different K_dev).

If the RNG fails, provisioning fails closed (`OCM_E_IO`) with no fallback.

---

## 3. Adversary table

### A. Internet-wide default-credential scanner / botnet (the original attack)

**Capability:** connect to any device, try known/default passwords at scale.

**Outcome:** finds nothing. There is no default password. A device in factory
state exposes no management credential at all, only a rotating presence code on
a short-range channel. A commissioned device has a credential whose print space
is 256 bits and which no one has ever published.

- Test: `no_double_claim` (factory device exposes nothing remotely usable).

### B. Passive network eavesdropper

**Capability:** reads every byte on the wire.

**Outcome:** sees only public wire objects: the hello (`device_id, epoch,
nonce, P`), the signed grant (public, verifiable, but useless without the
purchaser key and code), and the blob (AEAD-sealed to the purchaser). No `S`,
no `C`, no `K_dev` ever crosses the wire in the clear. The receipt is an HMAC
under `K_dev` and reveals nothing about it.

- Wire sizes: hello 83 B, grant 188 B, blob 115 B; see `include/ocm.h`.

### C. Reseller / installer who physically handles the device

**Capability:** holds the device, can read the short-range code, can sniff or
proxy the local BLE link, can be the one who powers it on.

**Outcome:** can read a **per-boot** code `C`. `C` is worthless without:
1. an account the cloud believes owns that serial, and
2. a grant signed by the vendor service key.

Even if handed a valid grant (e.g. by a colluding insider), the installer cannot
open the blob: its key is derived from the **buyer's private key** and the live
`C`. The installer has neither the buyer's private key nor, at that moment, a
grant bound to the current boot.

- Test: `blob_relay_without_buyer_priv` (wrong key and wrong code both fail).
- Anti-harvest: `code_rotates_each_boot` (a code captured at boot N fails at
  boot N+1).

Note the honest limit: an installer who *is* the rightful owner in the order
database can claim the device. That is correct behaviour — they bought it. The
scheme prevents a reseller from claiming devices **they do not own** in bulk.

### D. Thief who steals a device and factory-resets it

**Capability:** physical possession, presses the reset button.

**Outcome:** `ocm_factory_reset_local` wipes `S`/`K_dev` and draws a brand-new
`S` with epoch+1. The thief now holds a factory-state device. To claim it they
need (a) the device serial registered to *their* account — impossible, the order
DB still says the victim — and (b) a grant signed by the vendor key, which they
do not have and cannot forge. They cannot run their own "cloud" against the
device because the device trusts only the compiled-in vendor public key.

- Test: `reset_burns_old_credential`, `reset_yields_new_secret`.
- Remote reset additionally requires a service-signed RESET grant bound to the
  device id: `reset_requires_valid_grant`.

### E. Malicious or compromised cloud operator

**Capability:** full control of the cloud, issues grants, sees all hellos.

**Cannot:**
- read `S`, `C`, or `K_dev` (never sent; `C` only leaves the device on the
  local link, and only a commitment-free public hello goes to the cloud);
- redirect a credential to a key of its choosing: the device checks
  `grant.buyer_pub == app_pub` on the local link
  (`wrong_buyer_key_rejected`);
- silently enrol devices it has no physical access to, because a claim requires
  the live per-boot code `C`, which is only readable in person.

**Can:** refuse service, or mis-bind serial→account (an *ownership* error, not
a cryptographic break — see §4).

### F. Attacker with physical access to one device's flash

**Capability:** desolders flash, dumps it, perhaps replays old dumps.

**Outcome:** the record is AEAD-sealed under a key derived from the chip root
key (HUK/eFuse/secure element). Without defeating secure boot, debug lock, and
that root key, the dump is ciphertext (`flash_holds_no_plaintext_secret`).
Tampering is detected, never silently used (`tamper_detected`). If they *do*
defeat all of that, they own **that one device** — not the fleet, because
nothing fleet-wide is shared.

### G. Attacker replaying an old grant or an old flash image

**Capability:** records a grant, or restores an old flash dump, then retries.

**Outcome:** grants bind the per-boot `nonce`; a grant from an earlier boot
fails against a new session. A boot nonce never repeats
(`grant_replay_after_reboot_rejected`). Restoring old flash resets `S` to an
*older* value but does not let anyone who lacked the code and buyer key extract
anything, and the epoch in grants would no longer match a fresh boot.

### H. Online code guesser (someone with the hello, guessing C)

**Capability:** has a hello (public), tries codes against the device.

**Outcome:** 40-bit code space, and after `OCM_FREE_ATTEMPTS` (3) failures the
device applies exponential back-off up to one hour
(`backoff_and_lockout`). Guessing at scale is impractical. Offline guessing from
a flash dump faces ~2^39 MACs at 50% and still needs the chip root key.

---

## 4. Residual risks we accept

1. **Order-DB correctness.** The cloud must bind serial→buyer correctly. A
   mis-binding is an ownership fraud, not a cryptographic failure; it is why the
   barcode scan at packing is the single most important operational control.
   Mitigation: signed shipping manifests, scan verification, and an audit trail
   on rolls back to the physical device.

2. **The physical holder who is the rightful owner** can always claim. This is
   inherent to any scheme without a screen/keyboard: if you are the buyer and
   you are holding the device, you should be able to enrol it. Presence is the
   whole point.

3. **Cloud availability / coercion.** A cloud operator can refuse or be coerced
   into issuing a grant to the wrong party *who is physically present with the
   live code*. It still cannot read the credential, and the device still checks
   the buyer key, so the blast radius is one device.

4. **Physical extraction of a single device.** Assumed out of scope beyond
   secure boot + debug lock; documented as "one device, not the fleet."

5. **40-bit code.** Deliberately small for human transcription. Its role is
   possession proof and an online rate-limit anchor, not credential strength —
   the credential is 256-bit and sealed to the purchaser key. If a deployment
   wants more, raise `OCM_CODE_BYTES` (cost: longer code to type/display).

---

## 5. Cryptographic choices

| Purpose | Primitive | Rationale |
|---|---|---|
| Pairing key | X25519 | Small, fast, constant-time, widely implemented |
| Grant signature | Ed25519 | Small sigs, fast verify, one 32-byte public key on device |
| Code / receipt / KDF | HMAC-SHA-256, HKDF-SHA-256 | Minimal, portable, no exotic assumptions |
| Record & blob sealing | ChaCha20-Poly1305 | AEAD, no padding oracle, constant-time in software |
| Randomness | platform RNG via libsodium `randombytes` | Hardware RNG on real silicon |

All primitives are available in mbedTLS and PSA Crypto, so the port is a
drop-in of `src/primitives.c` (see `docs/PORTING.md`). Ed25519 signing exists
only for the reference service; devices only ever verify.
