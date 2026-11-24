/*
 * storage_mock.h --- in-memory HAL for the reference build and tests.
 */

#ifndef STORAGE_MOCK_H
#define STORAGE_MOCK_H

#include "ocm.h"

/* A plausible-but-past "now": 2024-01-01 00:00:00 UTC, so the core treats the
 * clock as set and enforces back-off / expiry in tests. */
#define MOCK_T0 1704067200u

typedef struct {
    uint8_t       flash[OCM_RECORD_LEN];
    int           has_record;
    int           stores;
    uint8_t       device_id[16];
    uint8_t       root_key[OCM_KEY_LEN];
    int           has_keystore;
    uint32_t      now;
    int           io_error;      /* when 1, every load/store/wipe fails */
    int           fail_after;    /* -1 = never fail; N = fail the Nth store */
    ocm_storage_t st;
} mock_device_t;

void mock_init(mock_device_t *d, uint8_t id_seed, uint8_t root_seed);
ocm_storage_t *mock_storage(mock_device_t *d);

/* What an attacker who desoldered the flash can read (ciphertext only). */
void mock_flash_dump(const mock_device_t *d, uint8_t out[OCM_RECORD_LEN]);
void mock_tamper_flash(mock_device_t *d, unsigned byte_index);

void mock_set_clock(mock_device_t *d, uint32_t t);
void mock_advance(mock_device_t *d, uint32_t s);

#endif /* STORAGE_MOCK_H */
