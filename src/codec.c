/*
 * codec.c --- wire encoders/decoders and the Crockford base32 pairing code.
 *
 * Every wire object starts with a version byte (1) and is fixed-length with
 * big-endian integers, so a parser can never be tricked into reading a length
 * that was not validated. decode() returns 0 (failure) on any unknown version.
 */

#include <string.h>

#include "ocm_internal.h"

/* ---- big-endian field copies -------------------------------------- */

static void put8(uint8_t *p, uint8_t v)  { p[0] = v; }
static void put_bytes(uint8_t *p, const uint8_t *s, size_t n)
{
    memcpy(p, s, n);
}

/* ---- hello --------------------------------------------------------- */

void ocm_hello_encode(const ocm_hello_t *h,
                      uint8_t out[OCM_HELLO_WIRE_LEN])
{
    put8(out, OCM_VERSION);
    put_bytes(out + 1, h->boot_epoch, 2);
    put_bytes(out + 3, h->device_id, 16);
    put_bytes(out + 19, h->nonce, OCM_SESS_NONCE_LEN);
    put_bytes(out + 51, h->pairing_pub, OCM_KEY_LEN);
}

int ocm_hello_decode(ocm_hello_t *h, const uint8_t in[OCM_HELLO_WIRE_LEN])
{
    if (in[0] != OCM_VERSION)
        return 0;
    memcpy(h->boot_epoch, in + 1, 2);
    memcpy(h->device_id, in + 3, 16);
    memcpy(h->nonce, in + 19, OCM_SESS_NONCE_LEN);
    memcpy(h->pairing_pub, in + 51, OCM_KEY_LEN);
    return 1;
}

/* ---- grant --------------------------------------------------------- */

void ocm_grant_signed_bytes(const ocm_grant_t *g,
                            uint8_t out[OCM_GRANT_SIGNED_LEN])
{
    out[0] = OCM_VERSION;
    out[1] = g->type;
    put_bytes(out + 2,  g->boot_epoch, 2);
    put_bytes(out + 4,  g->counter, 4);
    put_bytes(out + 8,  g->expiry, 4);
    put_bytes(out + 12, g->device_id, 16);
    put_bytes(out + 28, g->nonce, OCM_SESS_NONCE_LEN);
    put_bytes(out + 60, g->pairing_pub, OCM_KEY_LEN);
    put_bytes(out + 92, g->buyer_pub, OCM_KEY_LEN);
}

void ocm_grant_encode(const ocm_grant_t *g, const uint8_t sig[OCM_SIG_LEN],
                      uint8_t out[OCM_GRANT_WIRE_LEN])
{
    ocm_grant_signed_bytes(g, out);
    put_bytes(out + OCM_GRANT_SIGNED_LEN, sig, OCM_SIG_LEN);
}

int ocm_grant_decode(ocm_grant_t *g, uint8_t sig[OCM_SIG_LEN],
                     const uint8_t in[OCM_GRANT_WIRE_LEN])
{
    if (in[0] != OCM_VERSION)
        return 0;
    g->type = in[1];
    memcpy(g->boot_epoch, in + 2, 2);
    memcpy(g->counter, in + 4, 4);
    memcpy(g->expiry, in + 8, 4);
    memcpy(g->device_id, in + 12, 16);
    memcpy(g->nonce, in + 28, OCM_SESS_NONCE_LEN);
    memcpy(g->pairing_pub, in + 60, OCM_KEY_LEN);
    memcpy(g->buyer_pub, in + 92, OCM_KEY_LEN);
    memcpy(sig, in + OCM_GRANT_SIGNED_LEN, OCM_SIG_LEN);
    return 1;
}

/* ---- blob ---------------------------------------------------------- */

void ocm_blob_encode(const ocm_blob_t *b, uint8_t out[OCM_BLOB_WIRE_LEN])
{
    put8(out, OCM_VERSION);
    put_bytes(out + 1,  b->boot_epoch, 2);
    put_bytes(out + 3,  b->counter, 4);
    put_bytes(out + 7,  b->device_id, 16);
    put_bytes(out + 23, b->eph_pub, OCM_KEY_LEN);
    put_bytes(out + 55, b->nonce, OCM_NONCE_LEN);
    put_bytes(out + 67, b->ct, OCM_SECRET_LEN);
    put_bytes(out + 99, b->tag, OCM_TAG_LEN);
}

int ocm_blob_decode(ocm_blob_t *b, const uint8_t in[OCM_BLOB_WIRE_LEN])
{
    if (in[0] != OCM_VERSION)
        return 0;
    memcpy(b->boot_epoch, in + 1, 2);
    memcpy(b->counter, in + 3, 4);
    memcpy(b->device_id, in + 7, 16);
    memcpy(b->eph_pub, in + 23, OCM_KEY_LEN);
    memcpy(b->nonce, in + 55, OCM_NONCE_LEN);
    memcpy(b->ct, in + 67, OCM_SECRET_LEN);
    memcpy(b->tag, in + 99, OCM_TAG_LEN);
    return 1;
}

/* ---- Crockford base32 pairing code --------------------------------- */

static const char B32[] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

void ocm_code_encode(const uint8_t raw[OCM_CODE_BYTES],
                     char out[OCM_CODE_STR_LEN])
{
    /* 40 bits -> 8 x 5-bit symbols, most-significant first. */
    char d[8];
    uint64_t v = 0;
    int i;

    for (i = 0; i < (int)OCM_CODE_BYTES; i++)
        v = (v << 8) | raw[i];
    for (i = 7; i >= 0; i--) {
        d[i] = B32[v & 0x1f];
        v >>= 5;
    }
    out[0] = d[0]; out[1] = d[1]; out[2] = d[2]; out[3] = d[3];
    out[4] = '-';
    out[5] = d[4]; out[6] = d[5]; out[7] = d[6]; out[8] = d[7];
    out[9] = '\0';
}

static int b32_val(char c)
{
    if (c >= 'a' && c <= 'z') c = (char)(c - 'a' + 'A');
    if (c == 'I' || c == 'L') c = '1';
    if (c == 'O') c = '0';
    for (int i = 0; i < 32; i++)
        if (B32[i] == c)
            return i;
    return -1;
}

int ocm_code_decode(uint8_t raw[OCM_CODE_BYTES], const char *code)
{
    uint64_t v = 0;
    int n = 0;
    if (!code)
        return 0;
    for (const char *p = code; *p; p++) {
        if (*p == '-' || *p == ' ')
            continue;
        int d = b32_val(*p);
        if (d < 0 || n >= 8)
            return 0;
        v = (v << 5) | (uint64_t)d;
        n++;
    }
    if (n != 8)
        return 0;
    for (int i = (int)OCM_CODE_BYTES - 1; i >= 0; i--) {
        raw[i] = (uint8_t)(v & 0xff);
        v >>= 8;
    }
    return 1;
}
