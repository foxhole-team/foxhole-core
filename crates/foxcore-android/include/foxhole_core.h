#ifndef FOXHOLE_CORE_H
#define FOXHOLE_CORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FOXHOLE_CORE_ABI_VERSION 1u

uint32_t foxhole_core_abi_version(void);
uint32_t foxhole_core_config_schema_version(void);

/* Required byte count includes the trailing NUL. */
size_t foxhole_core_capabilities_json_len(void);

/*
 * Returns the required byte count including the trailing NUL.
 * A NULL or undersized buffer is not written. Zero reports an internal failure.
 */
size_t foxhole_core_capabilities_json_write(uint8_t *buffer, size_t capacity);

#ifdef __cplusplus
}
#endif

#endif
