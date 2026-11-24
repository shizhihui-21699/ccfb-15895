# OCM — Open Commissioning Model

**Device-unique bootstrap credentials for headless IoT devices, with nothing
written per unit on the production line.**

A reference C implementation of a fix for the shared-default-password problem
that let one botnet sweep enrol millions of cameras at once. Each device
generates its own credential in firmware at first boot and delivers it only to
the buyer who owns it in the cloud and is physically present at it — while
resellers, installers, eavesdroppers, thieves, and even a compromised cloud
never obtain it.

```
make demo                  # narrated end-to-end protocol run
make test                  # 127 assertions, mostly adversarial
make fleet N=20000         # prove uniqueness across a simulated fleet
```

Requires a C11 compiler and libsodium (`brew install libsodium` /
`apt install libsodium-dev`).

---

## The five constraints, and how each is answered

| Constraint | How OCM answers it |
|---|---|
| **No screen, no keyboard** | An 8-character pairing code shown over BLE/LED/NFC; the buyer's phone reads it |
| **No per-unit production write** | The line flashes one image; uniqueness comes from the device RNG, not the line |
| **Resellers/installers must not get the credential** | The credential is sealed to the buyer's *private* key + a per-boot code; handlers have neither |
| **Factory reset must not be guessable** | Reset draws a **brand-new** secret and bumps the epoch; there is no default to return to |
| **Tiny storage** | 73-byte authenticated record + one 32-byte vendor public key, total |

---

## The idea in one paragraph

At first boot the device draws a 32-byte secret `S` from its hardware RNG and
seals it under a key only that chip can obtain. `S` is never printed, never
transmitted, never stored anywhere else. It derives a public pairing key `P`
and a **per-boot** 8-character pairing code `C`. The buyer's account — which
the cloud bound to the device serial with one barcode scan — reads `C` in
person and gets a vendor-signed **grant** binding the device, the boot nonce,
`P`, and the buyer's own X25519 key. The device verifies the grant, derives the
long-term credential `K_dev` from `S` and the grant, and seals it to the buyer
in an AEAD blob whose key needs `buyer_priv` **and** `C`. The app opens it,
returns a receipt, and only then does the device burn `S` and keep `K_dev`.

The botnet's default-password sweep finds nothing: every credential is unique,
and it only ever exists sealed to the buyer.

See [`docs/DESIGN.md`](docs/DESIGN.md) for the full rationale,
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the adversary-by-adversary
analysis and accepted residual risks, [`docs/PORTING.md`](docs/PORTING.md) for
the mbedTLS/PSA port (one file), and
[`docs/INTEGRATION.md`](docs/INTEGRATION.md) for what firmware, cloud, and app
each implement.

---

## What runs

`make demo` walks the whole protocol and prints what crosses each boundary —
notably, what the pairing code is not (it never appears in the hello), and what
a desoldered flash contains (ciphertext only):

```
== First boot (on purchaser's premises) ==
  pairing code shown on device: 28QZ-ZAE0
  device -> cloud hello: {device_id, nonce, pairing_pub P}   (no code)
...
== Purchaser app: open the blob ==
  ocm_buyer_accept: 0
  K_dev (secret!) 9953c397...
== Device: claim step 2 (finalize) ==
  ocm_finalize (burns S, stores K_dev): 0
  device's stored credential matches app's K_dev? yes
== Attacker who desoldered the flash ==
  flash (all of it) d6d24f8f...   (no plaintext secret, no K_dev)
```

`make test` is the interesting one: 127 assertions that try to **break** the
scheme — replay a grant after reboot, harvest a code and reuse it, relay a blob,
forge a receipt, reset to fall back to a known state, claim a device you don't
own, brute-force the code, tamper with flash, fail storage mid-claim. All pass,
and the suite is clean under AddressSanitizer + UndefinedBehaviorSanitizer; a
200k-input malformed-grant stress run accepts zero of them.

---

## Honest limitations (not buried — see THREAT_MODEL.md §4)

- The cloud is trusted to bind **serial → buyer** correctly. That is the
  operational crux; it is an ownership control, not a cryptographic one.
- The physical holder who is the rightful owner can claim the device. That is
  correct: if you bought it and you're holding it, you should be able to
  enrol it.
- A malicious cloud cannot read `K_dev` or redirect it to another key (the
  device checks the buyer key on the local link), and cannot silently enrol
  devices it has no physical access to (claims need the live per-boot code).
- Reading one device's protected storage yields that device, not the fleet.
- The 40-bit pairing code is a presence token, not the credential; codes will
  collide across a multi-million fleet, which is harmless because the
  credential is 256-bit.

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
sim/storage_mock.c     in-memory HAL modelling flash vs. keystore separation
sim/flow_demo.c        narrated end-to-end run
sim/fleet_sim.c        uniqueness at fleet scale
tests/test_ocm.c       127 assertions, adversarial
docs/                  DESIGN, THREAT_MODEL, PORTING, INTEGRATION
```
