#include "cwpack_util.h"

void cw_pack_cstr(cw_pack_context *pc, const char *str) {
    cw_pack_str(pc, str, strlen(str));
}

void cw_unpack_restore(cw_unpack_context *upc){
    upc->item.type = CWP_NOT_AN_ITEM;
    upc->current = upc->start;
    upc->return_code = CWP_RC_OK;
    upc->err_no = 0;
}

char *cw_unpack_cstr(cw_unpack_context *upc, char *buf, size_t bsize) {
    memset(buf, 0, bsize);
    size_t sz = upc->item.as.str.length;
    if (sz > bsize - 1) {
        sz = bsize - 1;
    }
    strncpy(buf, upc->item.as.str.start, sz);
    return buf;
}

int cw_unpack_cmp_str(cw_unpack_context *upc, const char *str){
    if (upc->item.type != CWP_ITEM_STR) return -1;
    if (upc->item.as.str.length != strlen(str)) return -1;
    if (strncmp(upc->item.as.str.start, str, upc->item.as.str.length) != 0) return -1;
    return 0;
}

int cw_unpack_map_search(cw_unpack_context *upc, const char *key){
    cw_unpack_next(upc);
    if (upc->return_code != CWP_RC_OK || upc->item.type != CWP_ITEM_MAP) return -1;
    for (uint32_t ms = upc->item.as.map.size; ms > 0 ; ms --) {
        cw_unpack_next(upc);
        if (upc->return_code != CWP_RC_OK || upc->item.type != CWP_ITEM_STR) return -1;
        if (cw_unpack_cmp_str(upc, key) == 0) return 0;
        cw_skip_items(upc, 1); // Skip value item
    }
    return -1;
}

int cw_unpack_map_get_buf(const cw_unpack_context *upcc, const char *key, uint8_t *buf, size_t bsize, size_t *used) {
    int ret = 0;
    cw_unpack_context upc = *upcc;

    ret = cw_unpack_map_search(&upc, key);
    if (ret != 0) return ret;
    cw_unpack_next(&upc);
    if (upc.return_code != CWP_RC_OK || (upc.item.type != CWP_ITEM_BIN)) {
        return -2;
    }
    size_t sz = upc.item.as.bin.length;
    if (sz > bsize) {
        sz = bsize;
    }
    memcpy(buf, upc.item.as.bin.start, sz);
    if (used != NULL) *used = sz;
    return 0;
}

int cw_unpack_map_get_bufptr(const cw_unpack_context *upcc, const char *key, uint8_t **buf, size_t *bsize) {
    int ret = 0;
    cw_unpack_context upc = *upcc;

    ret = cw_unpack_map_search(&upc, key);
    if (ret != 0) return ret;
    cw_unpack_next(&upc);
    if (upc.return_code != CWP_RC_OK || (upc.item.type != CWP_ITEM_BIN)) {
        return -2;
    }
    *buf = (uint8_t *)upc.item.as.bin.start;
    if (bsize != NULL) *bsize = upc.item.as.bin.length;
    return 0;
}

int cw_unpack_map_get_array(const cw_unpack_context *upcc, const char *key, cw_unpack_context *array_ctx) {
    int ret = 0;

    *array_ctx = *upcc;
    ret = cw_unpack_map_search(array_ctx, key);
    if (ret != 0) return ret;
    cw_unpack_next(array_ctx);
    if (array_ctx->return_code != CWP_RC_OK || (array_ctx->item.type != CWP_ITEM_ARRAY)) {
        return -2;
    }
    return 0;
}

int cw_unpack_map_get_str(const cw_unpack_context *upcc, const char *key, char *buf, size_t bsize, size_t *used) {
    int ret = 0;
    cw_unpack_context upc = *upcc;

    ret = cw_unpack_map_search(&upc, key);
    if (ret != 0) return ret;
    cw_unpack_next(&upc);
    if (upc.return_code != CWP_RC_OK || (upc.item.type != CWP_ITEM_STR)) {
        return -2;
    }
    size_t sz = upc.item.as.str.length;
    if (sz > bsize - 1) {
        sz = bsize - 1;
    }
    memcpy(buf, upc.item.as.str.start, sz);
    buf[sz] = 0;
    if (used != NULL) *used = sz;
    return 0;
}

int cw_unpack_map_get_i64(const cw_unpack_context *upcc, const char *key, int64_t *i64p) {
    int ret = 0;
    cw_unpack_context upc = *upcc;

    ret = cw_unpack_map_search(&upc, key);
    if (ret != 0) return -1;
    cw_unpack_next(&upc);
    if (upc.return_code != CWP_RC_OK || (upc.item.type != CWP_ITEM_POSITIVE_INTEGER && upc.item.type != CWP_ITEM_NEGATIVE_INTEGER)) {
        return -2;
    }
    *i64p = upc.item.as.i64;
    return 0;
}

int cw_unpack_map_get_u64(const cw_unpack_context *upcc, const char *key, uint64_t *u64p) {
    int ret = 0;
    cw_unpack_context upc = *upcc;

    ret = cw_unpack_map_search(&upc, key);
    if (ret != 0) return -1;
    cw_unpack_next(&upc);
    if (upc.return_code != CWP_RC_OK || upc.item.type != CWP_ITEM_POSITIVE_INTEGER) {
        return -2;
    }
    *u64p = upc.item.as.u64;
    return 0;
}

int cw_unpack_map_get_size_t(const cw_unpack_context *upcc, const char *key, size_t *size_t_p) {
    int ret = 0;
    uint64_t val;

    ret = cw_unpack_map_get_u64(upcc, key, &val);
    if (ret != 0) return ret;
    *size_t_p = (size_t)val;
    return 0;
}

int cw_unpack_map_get_int(const cw_unpack_context *upcc, const char *key, int *int_p) {
    int ret = 0;
    int64_t val;

    ret = cw_unpack_map_get_i64(upcc, key, &val);
    if (ret != 0) return ret;
    *int_p = (int)val;
    return 0;
}

int cw_unpack_map_get_uint(const cw_unpack_context *upcc, const char *key, unsigned int *uint_p) {
    int ret = 0;
    uint64_t val;

    ret = cw_unpack_map_get_u64(upcc, key, &val);
    if (ret != 0) return ret;
    *uint_p = (unsigned int)val;
    return 0;
}

int cw_unpack_map_get_i32(const cw_unpack_context *upcc, const char *key, int32_t *i32p) {
    int ret = 0;
    int64_t val;

    ret = cw_unpack_map_get_i64(upcc, key, &val);
    if (ret != 0) return ret;
    *i32p = (int32_t)val;
    return 0;
}

int cw_unpack_map_get_u32(const cw_unpack_context *upcc, const char *key, uint32_t *u32p) {
    int ret = 0;
    uint64_t val;

    ret = cw_unpack_map_get_u64(upcc, key, &val);
    if (ret != 0) return ret;
    *u32p = (uint32_t)val;
    return 0;
}

int cw_unpack_map_get_i16(const cw_unpack_context *upcc, const char *key, int16_t *i16p) {
    int ret = 0;
    int64_t val;

    ret = cw_unpack_map_get_i64(upcc, key, &val);
    if (ret != 0) return ret;
    *i16p = (int16_t)val;
    return 0;
}

int cw_unpack_map_get_u16(const cw_unpack_context *upcc, const char *key, uint16_t *u16p) {
    int ret = 0;
    uint64_t val;

    ret = cw_unpack_map_get_u64(upcc, key, &val);
    if (ret != 0) return ret;
    *u16p = (uint16_t)val;
    return 0;
}

int cw_unpack_map_get_i8(const cw_unpack_context *upcc, const char *key, int8_t *i8p) {
    int ret = 0;
    int64_t val;

    ret = cw_unpack_map_get_i64(upcc, key, &val);
    if (ret != 0) return ret;
    *i8p = (int8_t)val;
    return 0;
}

int cw_unpack_map_get_u8(const cw_unpack_context *upcc, const char *key, uint8_t *u8p) {
    int ret = 0;
    uint64_t val;

    ret = cw_unpack_map_get_u64(upcc, key, &val);
    if (ret != 0) return ret;
    *u8p = (uint8_t)val;
    return 0;
}

char *cw_unpack_map_strerr(int err) {
    switch (err) {
        case CW_UNPACK_MAP_ERR_MISSING_KEY:
            return "missing key";
        case CW_UNPACK_MAP_ERR_INVALID_TYPE:
            return "invalid type";
    }
    return "unknown error";
}
