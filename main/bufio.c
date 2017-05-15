/* bufio.c -- I/O buffer management
 *
 *  Created on: 2015/10/22
 *      Author: Jose Luis Aracil Gomez
 *      E-Mail: pepe.aracil.gomez@gmail.com
 *
 *  bufio is released under the BSD license (see LICENSE). Go to the project
 *  home page (http://github.com/jaracil/bufio) for more info.
 */

#include "bufio.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int bufio_init(bufio_t* p, size_t sz) {
    p->buf = malloc(sz + 1);
    if(p->buf == NULL)
        return -1;
    p->rp = 0;
    p->wp = 0;
    p->cap = sz;
    p->buf[0] = 0;
    return 0;
}

void bufio_free(bufio_t* p) {
    if(p->buf != NULL) {
        free(p->buf);
        p->buf = NULL;
    }
    p->rp = 0;
    p->wp = 0;
    p->cap = 0;
}

int bufio_is_empty(bufio_t* p) {
    return p->rp == p->wp;
}

int bufio_is_full(bufio_t* p) {
    return (p->wp - p->rp) == p->cap;
}

size_t bufio_used(bufio_t* p) {
    return p->wp - p->rp;
}

size_t bufio_avail(bufio_t* p) {
    return p->cap - (p->wp - p->rp);
}

size_t bufio_maxblk(bufio_t* p) {
    return p->cap - p->wp;
}

size_t bufio_cap(bufio_t* p) {
    return p->cap;
}

void* bufio_tail(bufio_t* p) {
    return p->buf + p->rp;
}

void* bufio_head(bufio_t* p) {
    return p->buf + p->wp;
}

void bufio_shift(bufio_t* p) {
    if(p->rp == 0)
        return;
    if(p->rp == p->wp) {
        p->rp = 0;
        p->wp = 0;
        p->buf[0] = 0;
        return;
    }
    memmove(p->buf, p->buf + p->rp, p->wp - p->rp);
    p->wp -= p->rp;
    p->rp = 0;
    p->buf[p->wp] = 0;
}

void bufio_discard(bufio_t* p, ssize_t sz) {
    int r = 0;
    if(sz < 0) {
        r = 1;
        sz *= -1;
    }
    if(sz > (ssize_t)bufio_used(p))
        sz = bufio_used(p);
    if(r) {
        p->wp -= sz;
        p->buf[p->wp] = 0;
    } else {
        p->rp += sz;
    }
    if(p->rp == p->wp) {
        p->rp = 0;
        p->wp = 0;
        p->buf[0] = 0;
    }
}

void bufio_discard_all(bufio_t* p) {
    p->rp = 0;
    p->wp = 0;
    p->buf[0] = 0;
}

void bufio_extend(bufio_t* p, size_t sz) {
    if(sz > bufio_maxblk(p))
        sz = bufio_maxblk(p);
    p->wp += sz;
    p->buf[p->wp] = 0;
}

ssize_t bufio_printf(bufio_t* p, const char* fmt, ...) {
    int n;
    va_list ap;
    bufio_shift(p);
    va_start(ap, fmt);
    n = vsnprintf((char*)bufio_head(p), bufio_maxblk(p), fmt, ap);
    va_end(ap);
    if(n > 0)
        bufio_extend(p, n);
    return n;
}

size_t bufio_push_buffer(bufio_t* p, bufio_t* s) {
    size_t sz = bufio_used(s), sa = bufio_avail(p);
    if(sz == 0 || sa == 0)
        return 0;
    if(sz > sa)
        sz = sa;
    if(sz > bufio_maxblk(p))
        bufio_shift(p);
    memcpy(bufio_head(p), bufio_tail(s), sz);
    bufio_extend(p, sz);
    bufio_discard(s, sz);
    return sz;
}

size_t bufio_push_bytes(bufio_t* p, const void* s, size_t sz) {
    if(bufio_avail(p) < sz)
        sz = bufio_avail(p);
    if(bufio_maxblk(p) < sz)
        bufio_shift(p);
    memcpy(bufio_head(p), s, sz);
    bufio_extend(p, sz);
    return sz;
}

size_t bufio_push_byte(bufio_t* p, uint8_t ch) {
    if(!bufio_is_full(p)) {
        if(bufio_maxblk(p) == 0)
            bufio_shift(p);
        *((char*)bufio_head(p)) = ch;
        bufio_extend(p, 1);
        return 1;
    }
    return 0;
}

size_t bufio_pull_bytes(bufio_t* p, void* t, size_t sz) {
    if(bufio_used(p) < sz)
        sz = bufio_used(p);
    memcpy(t, bufio_tail(p), sz);
    bufio_discard(p, sz);
    return sz;
}

int bufio_pull_byte(bufio_t* p) {
    uint8_t ch;
    if(bufio_is_empty(p))
        return -1;
    ch = *((char*)bufio_tail(p));
    bufio_discard(p, 1);
    return (int)ch;
}

int bufio_peek_byte(bufio_t* p) {
    if(bufio_is_empty(p))
        return -1;
    return *((char*)bufio_tail(p));
}
