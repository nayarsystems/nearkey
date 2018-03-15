#pragma once 
#include "cwpack.h"
#include <stddef.h>
#include <string.h>

void cw_pack_cstr(cw_pack_context *pc, const char *str);
void cw_unpack_restore(cw_unpack_context *upc);
char *cw_unpack_cstr(cw_unpack_context *upc, char *buff, size_t bsize);
int cw_unpack_cmp_str(cw_unpack_context *upc, const char *str);
int cw_unpack_map_search(cw_unpack_context *upc, const char *key);
