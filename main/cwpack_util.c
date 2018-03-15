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

char *cw_unpack_cstr(cw_unpack_context *upc, char *buff, size_t bsize) {
    memset(buff, 0, bsize);
    size_t sz = upc->item.as.str.length;
    if (sz > bsize - 1) {
        sz = bsize - 1;
    }
    strncpy(buff, upc->item.as.str.start, sz);
    return buff;
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
