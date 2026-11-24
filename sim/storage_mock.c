/*
 * storage_mock.c --- an in-memory stand-in for the device's protected storage,
 * for the reference build and the test suite. On real hardware each of these
 * hooks maps to the chip's keystore (see docs/PORTING.md); this mock exists so
 * the whole flow can be exercised on a laptop.
 *
 * The mock models the security-relevant properties, not just the API:
 *   - the record lives in `flash`, and `flash_dump()` returns exactly what an
 *     attacker who desoldered the flash would read (ciphertext only);
 *   - root_key is held out-of-band in `keystore` and never appears in `flash`;
 *   - `tamper_flash()` flips a byte so tests can prove authentication fails;
 *   - `set_clock()` and `advance()` drive back-off and expiry deterministically.
 */

#include <string.h>

#include "storage_mock.h"

static int m_load(void *ctx, uint8_t buf[OCM_RECORD_LEN])
{
    mock_device_t *d = ctx;
    if (!d->has_record)
        return 0;
    if (d->io_error)
        return -1;
    memcpy(buf, d->flash, OCM_RECORD_LEN);
    return 1;
}

static int m_store(void *ctx, const uint8_t buf[OCM_RECORD_LEN])
{
    mock_device_t *d = ctx;
    if (d->io_error)
        return -1;
    if (d->fail_after == 0)
        return -1;                 /* simulate a full/failing NVS */
    if (d->fail_after > 0)
        d->fail_after--;
    memcpy(d->flash, buf, OCM_RECORD_LEN);
    d->has_record = 1;
    d->stores++;
    return 0;
}

static int m_wipe(void *ctx)
{
    mock_device_t *d = ctx;
    if (d->io_error)
        return -1;
    memset(d->flash, 0, OCM_RECORD_LEN);
    d->has_record = 0;
    return 0;
}

static int m_device_id(void *ctx, uint8_t out[16])
{
    mock_device_t *d = ctx;
    memcpy(out, d->device_id, 16);
    return 0;
}

static int m_root_key(void *ctx, uint8_t out[OCM_KEY_LEN])
{
    mock_device_t *d = ctx;
    if (!d->has_keystore)
        return -1;
    memcpy(out, d->root_key, OCM_KEY_LEN);
    return 0;
}

static uint32_t m_now(void *ctx)
{
    mock_device_t *d = ctx;
    return d->now;
}

void mock_init(mock_device_t *d, uint8_t id_seed, uint8_t root_seed)
{
    memset(d, 0, sizeof *d);
    for (int i = 0; i < 16; i++)
        d->device_id[i] = (uint8_t)(id_seed + i);
    for (int i = 0; i < (int)OCM_KEY_LEN; i++)
        d->root_key[i] = (uint8_t)(root_seed * 7u + (unsigned)i);
    d->has_keystore = 1;
    d->now = MOCK_T0;
    d->fail_after = -1;
    d->st.ctx = d;
    d->st.load = m_load;
    d->st.store = m_store;
    d->st.wipe = m_wipe;
    d->st.device_id = m_device_id;
    d->st.root_key = m_root_key;
    d->st.now_s = m_now;
}

ocm_storage_t *mock_storage(mock_device_t *d)
{
    return &d->st;
}

void mock_flash_dump(const mock_device_t *d, uint8_t out[OCM_RECORD_LEN])
{
    memcpy(out, d->flash, OCM_RECORD_LEN);
}

void mock_tamper_flash(mock_device_t *d, unsigned byte_index)
{
    d->flash[byte_index % OCM_RECORD_LEN] ^= 0x01;
}

void mock_set_clock(mock_device_t *d, uint32_t t) { d->now = t; }
void mock_advance(mock_device_t *d, uint32_t s)   { d->now += s; }
