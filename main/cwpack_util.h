#pragma once 
#include "cwpack.h"
#include <stddef.h>
#include <string.h>

#define CW_UNPACK_MAP_ERR_MISSING_KEY -1
#define CW_UNPACK_MAP_ERR_INVALID_TYPE -2

void cw_pack_cstr(cw_pack_context *pc, const char *str);
void cw_unpack_restore(cw_unpack_context *upc);
char *cw_unpack_cstr(cw_unpack_context *upc, char *buf, size_t bsize);
int cw_unpack_cmp_str(cw_unpack_context *upc, const char *str);
int cw_unpack_map_search(cw_unpack_context *upc, const char *key);
int cw_unpack_map_get_buf(const cw_unpack_context *upcc, const char *key, uint8_t *buf, size_t bsize, size_t *used);
int cw_unpack_map_get_bufptr(const cw_unpack_context *upcc, const char *key, uint8_t **buf, size_t *bsize);
int cw_unpack_map_get_str(const cw_unpack_context *upcc, const char *key, char *buf, size_t bsize, size_t *used);
int cw_unpack_map_get_i64(const cw_unpack_context *upcc, const char *key, int64_t *i64p);
int cw_unpack_map_get_u64(const cw_unpack_context *upcc, const char *key, uint64_t *u64p);
int cw_unpack_map_get_i32(const cw_unpack_context *upcc, const char *key, int32_t *i32p);
int cw_unpack_map_get_u32(const cw_unpack_context *upcc, const char *key, uint32_t *u32p);
int cw_unpack_map_get_i16(const cw_unpack_context *upcc, const char *key, int16_t *i16p);
int cw_unpack_map_get_u16(const cw_unpack_context *upcc, const char *key, uint16_t *u16p);
int cw_unpack_map_get_i8(const cw_unpack_context *upcc, const char *key, int8_t *i8p);
int cw_unpack_map_get_u8(const cw_unpack_context *upcc, const char *key, uint8_t *u8p);
int cw_unpack_map_get_size_t(const cw_unpack_context *upcc, const char *key, size_t *size_t_p);
int cw_unpack_map_get_int(const cw_unpack_context *upcc, const char *key, int *int_p);
int cw_unpack_map_get_uint(const cw_unpack_context *upcc, const char *key, unsigned int *uint_p);
char *cw_unpack_map_strerr(int err);
