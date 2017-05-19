/* parseutils.c -- string parse utils
 *
 *  Created on: 2015/10/22
 *      Author: Jose Luis Aracil Gomez
 *      E-Mail: pepe.aracil.gomez@gmail.com
 *
 *  parseutils is released under the BSD license (see LICENSE). Go to the project
 *  home page (http://github.com/jaracil/parseutils) for more info.
 */

#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "parseutils.h"

str_list* str_list_append(str_list* sl, char* s) {
    if(sl == NULL) {
        sl = calloc(1, sizeof(str_list));
    } else {
        while(sl->next != NULL)
            sl = sl->next;
        sl->next = calloc(1, sizeof(str_list));
        sl = sl->next;
    }
    sl->s = s;
    return sl;
}

/* Releases str_list */
void str_list_free(str_list* p) {
    str_list* oldp;
    while(p != NULL) {
        if(p->s != NULL)
            free(p->s);
        oldp = p;
        p = p->next;
        free(oldp);
    }
}

size_t str_list_len(const str_list* p) {
    size_t l;
    for(l = 0; p != NULL; l++)
        p = p->next;
    return l;
}

kv_list* kv_list_append(kv_list* kvl, char* k, char* v) {
    if(kvl == NULL) {
        kvl = calloc(1, sizeof(kv_list));
    } else {
        while(kvl->next != NULL)
            kvl = kvl->next;
        kvl->next = calloc(1, sizeof(kv_list));
        kvl = kvl->next;
    }
    kvl->k = k;
    kvl->v = v;
    return kvl;
}

void kv_list_free(kv_list* p) {
    kv_list* oldp;
    while(p != NULL) {
        if(p->k != NULL)
            free(p->k);
        if(p->v != NULL)
            free(p->v);
        oldp = p;
        p = p->next;
        free(oldp);
    }
}

size_t kv_list_len(const kv_list* p) {
    size_t l;
    for(l = 0; p != NULL; l++)
        p = p->next;
    return l;
}

kv_list* kv_list_search(kv_list* p, const char* key) {
    while(p != NULL) {
        if(strcmp(p->k, key) == 0)
            break;
        p = p->next;
    }
    return p;
}

char* str_slice(const char* str, int start, int end) {
    if(str == NULL)
        return NULL;
    int len = (int)strlen(str);
    if(start < 0)
        start = len - start;
    if(start > (len - 1))
        return calloc(1, 1);
    if(start < 0)
        start = 0;
    if(end < 0)
        end = len - end;
    if(end > (len - 1))
        end = len - 1;
    if(end < 0)
        return calloc(1, 1);
    if(start > end)
        return calloc(1, 1);
    char* r = malloc(end - start + 2);
    memcpy(r, &str[start], end - start + 1);
    r[end - start + 1] = 0;
    return r;
}

char* str_slice_free(char* str, int start, int end) {
    char* r = str_slice(str, start, end);
    free(str);
    return r;
}

static str_list* _str_split_n_safe(const char* str, const char* sep, size_t n, int safe) {
    char literal_delim = 0;
    int into_literal = 0;
    str_list *head = NULL, *p = NULL;
    size_t l = strlen(str), ls = strlen(sep), chunks = 0, pos = 0, ini = 0;
    if(n == 0) {
        n = SIZE_MAX;
    }
    while(pos <= l) {
        if(safe && (str[pos] == '"' || str[pos] == '\'')) {
            if(!into_literal) {
                literal_delim = str[pos];
                into_literal = 1;
            } else {
                if(str[pos] == literal_delim) {
                    literal_delim = 0;
                    into_literal = 0;
                }
            }
        }
        if(str[pos] == 0 || (chunks < (n - 1) && !into_literal && strncmp(&str[pos], sep, ls) == 0)) {
            if(head == NULL) {
                p = head = calloc(1, sizeof(str_list));
            } else {
                p->next = calloc(1, sizeof(str_list));
                p = p->next;
            }
            p->s = calloc(1, pos - ini + 1);
            memcpy(p->s, &str[ini], pos - ini);
            pos += ls;
            ini = pos;
            chunks++;
        } else
            pos++;
    }
    return head;
}

str_list* str_split_n(const char* str, const char* sep, size_t n) {
    return _str_split_n_safe(str, sep, n, 0);
}

str_list* str_split_n_safe(const char* str, const char* sep, size_t n) {
    return _str_split_n_safe(str, sep, n, 1);
}

str_list* str_split(const char* str, const char* sep) {
    return _str_split_n_safe(str, sep, 0, 0);
}

str_list* str_split_safe(const char* str, const char* sep) {
    return _str_split_n_safe(str, sep, 0, 1);
}

str_list* trim_list(str_list* p) {
    str_list* head = p;
    while(p != NULL) {
        p->s = str_trim_free(p->s, " ");
        p = p->next;
    }
    return head;
}

char* str_trim(const char* str, const char* strip) {
    if(str == NULL)
        return NULL;
    int len = (int)strlen(str), start = 0, end = len - 1;
    while(start < len && strchr(strip, str[start]) != NULL)
        start++;
    if(start >= len)
        return calloc(1, 1);
    while(end >= 0 && strchr(strip, str[end]) != NULL)
        end--;
    if(end < 0)
        return calloc(1, 1);
    return str_slice(str, start, end);
}

char* str_trim_free(char* str, const char* strip) {
    char* r = str_trim(str, strip);
    free(str);
    return r;
}

char* str_ltrim(const char* str, const char* strip) {
    if(str == NULL)
        return NULL;
    int len = (int)strlen(str), start = 0;
    while(start < len && strchr(strip, str[start]) != NULL)
        start++;
    if(start >= len)
        return calloc(1, 1);
    return str_slice(str, start, -1);
}

char* str_ltrim_free(char* str, const char* strip) {
    char* r = str_ltrim(str, strip);
    free(str);
    return r;
}

char* str_rtrim(const char* str, const char* strip) {
    if(str == NULL)
        return NULL;
    int end = (int)strlen(str) - 1;
    while(end >= 0 && strchr(strip, str[end]) != NULL)
        end--;
    if(end < 0)
        return calloc(1, 1);
    return str_slice(str, 0, end);
}

char* str_rtrim_free(char* str, const char* strip) {
    char* r = str_rtrim(str, strip);
    free(str);
    return r;
}

int str_has_prefix(const char* str, const char* pre) {
    return strncmp(pre, str, strlen(pre)) == 0;
}

int str_has_suffix(const char* str, const char* suf) {
    size_t lsuf = strlen(suf), lstr = strlen(str);
    if(lsuf <= lstr) {
        return strcmp(suf, &str[lstr - lsuf]) == 0;
    }
    return 0;
}

char* str_upper(const char* str) {
    char* r = str_slice(str, 0, -1);
    int c = 0;
    while(r[c]) {
        r[c] = toupper((int)r[c]);
        c++;
    }
    return r;
}

char* str_upper_free(char* str) {
    char* r = str_upper(str);
    free(str);
    return r;
}

char* str_lower(const char* str) {
    char* r = str_slice(str, 0, -1);
    int c = 0;
    while(r[c]) {
        r[c] = tolower((int)r[c]);
        c++;
    }
    return r;
}

char* str_lower_free(char* str) {
    char* r = str_lower(str);
    free(str);
    return r;
}

char* str_repl(const char* str, const char* old, const char* new) {
    /* Adjust each of the below values to suit your needs. */
    /* Increment positions cache size initially by this number. */
    size_t cache_sz_inc = 16;
    /* Thereafter, each time capacity needs to be increased,
     * multiply the increment by this factor. */
    const size_t cache_sz_inc_factor = 3;
    /* But never increment capacity by more than this number. */
    const size_t cache_sz_inc_max = 1048576;
    char *pret, *ret = NULL;
    const char *pstr2, *pstr = str;
    size_t i, count = 0;
    ptrdiff_t* pos_cache = NULL;
    size_t cache_sz = 0;
    size_t cpylen, orglen, retlen, newlen, oldlen = strlen(old);
    /* Find all matches and cache their positions. */
    while((pstr2 = strstr(pstr, old)) != NULL) {
        count++;
        /* Increase the cache size when necessary. */
        if(cache_sz < count) {
            cache_sz += cache_sz_inc;
            pos_cache = realloc(pos_cache, sizeof(*pos_cache) * cache_sz);
            if(pos_cache == NULL) {
                goto end_str_repl;
            }
            cache_sz_inc *= cache_sz_inc_factor;
            if(cache_sz_inc > cache_sz_inc_max) {
                cache_sz_inc = cache_sz_inc_max;
            }
        }

        pos_cache[count - 1] = pstr2 - str;
        pstr = pstr2 + oldlen;
    }
    orglen = pstr - str + strlen(pstr);
    /* Allocate memory for the post-replacement string. */
    if(count > 0) {
        newlen = strlen(new);
        retlen = orglen + (newlen - oldlen) * count;
    } else
        retlen = orglen;
    ret = malloc(retlen + 1);
    if(ret == NULL) {
        goto end_str_repl;
    }
    if(count == 0) {
        /* If no matches, then just duplicate the string. */
        strcpy(ret, str);
    } else {
        /* Otherwise, duplicate the string whilst performing
         * the replacements using the position cache. */
        pret = ret;
        memcpy(pret, str, pos_cache[0]);
        pret += pos_cache[0];
        for(i = 0; i < count; i++) {
            memcpy(pret, new, newlen);
            pret += newlen;
            pstr = str + pos_cache[i] + oldlen;
            cpylen = (i == count - 1 ? orglen : (size_t)(pos_cache[i + 1])) - pos_cache[i] - oldlen;
            memcpy(pret, pstr, cpylen);
            pret += cpylen;
        }
        ret[retlen] = '\0';
    }
end_str_repl:
    /* Free the cache and return the post-replacement string,
     * which will be NULL in the event of an error. */
    free(pos_cache);
    return ret;
}

char* str_repl_free(char* str, const char* old, const char* new) {
    char* r = str_repl(str, old, new);
    free(str);
    return r;
}

int parse_bool(const char* str) {
    char* s = str_upper(str);
    s = str_trim_free(s, " ");
    if(strcmp(s, "1") == 0 || strcmp(s, "T") == 0 || strcmp(s, "TRUE") == 0 || strcmp(s, "Y") == 0 ||
       strcmp(s, "YES") == 0) {
        free(s);
        return 1;
    }
    if(strcmp(s, "0") == 0 || strcmp(s, "F") == 0 || strcmp(s, "FALSE") == 0 || strcmp(s, "N") == 0 ||
       strcmp(s, "NO") == 0) {
        free(s);
        return 0;
    }
    free(s);
    return -1;
}

str_list* hex_dump(size_t col, uint8_t* buf, size_t buf_len) {
    static const char* hexconv = "0123456789abcdef";
    str_list *root = NULL, *p = NULL;
    size_t ncol = 0, offset = 0;

    while(offset < buf_len) {
        if(ncol == 0) {
            if(root == NULL) {
                root = calloc(1, sizeof(str_list));
                p = root;
            } else {
                p->next = calloc(1, sizeof(str_list));
                p = p->next;
            }
            p->s = calloc(1, col * 3 + col + 1);
            memset(p->s, ' ', col * 3 + col);
        }
        p->s[ncol * 3] = hexconv[(buf[offset] >> 4) & 0x0f];
        p->s[ncol * 3 + 1] = hexconv[buf[offset] & 0x0f];
        if(isprint(buf[offset]))
            p->s[col * 3 + ncol] = buf[offset];
        else
            p->s[col * 3 + ncol] = '.';
        if(++ncol == col)
            ncol = 0;
        offset++;
    }
    return root;
}

/* Parses text buffer and returns a kv_list linked list */
kv_list* kv_parse(const char* text) {
    str_list *lines = NULL, *line = NULL, *kv = NULL;
    kv_list *head = NULL, *p = NULL;
    char *k, *v;

    lines = str_split(text, "\n");
    for(line = lines; line != NULL; line = line->next) {
        kv = str_split_n(line->s, "=", 2);
        if(str_list_len(kv) != 2) {
            str_list_free(kv);
            break;
        }
        k = str_trim(kv->s, " \r");
        v = str_trim(kv->next->s, " \r");
        str_list_free(kv);
        if(head == NULL) {
            head = calloc(1, sizeof(kv_list));
            p = head;
        } else {
            p->next = calloc(1, sizeof(kv_list));
            p = p->next;
        }
        p->k = k;
        p->v = v;
    }
    str_list_free(lines);
    return head;
}
