/* bufio.h -- I/O buffer management
 *
 *  Created on: 2015/10/22
 *      Author: Jose Luis Aracil Gomez
 *      E-Mail: pepe.aracil.gomez@gmail.com
 *
 *  bufio is released under the BSD license (see LICENSE). Go to the project
 *  home page (http://github.com/jaracil/bufio) for more info.
 */

#ifndef BUFIO_H_
#define BUFIO_H_

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>

typedef struct {
    uint8_t* buf;
    size_t rp;
    size_t wp;
    size_t cap;
} bufio_t;

/* Initialize and allocate bufio resources*/
int bufio_init(bufio_t* p, size_t sz);

/* Free bufio resources */
void bufio_free(bufio_t* p);

/* Returns 1 if bufio is empty 0 otherwise */
int bufio_is_empty(bufio_t* p);

/* Returns 1 if bufio is full 0 otherwise */
int bufio_is_full(bufio_t* p);

/* Returns size of bufio used space */
size_t bufio_used(bufio_t* p);

/* Returns bufio available space (capacity - used space) */
size_t bufio_avail(bufio_t* p);

/* Returns maximum contiguous free space */
size_t bufio_maxblk(bufio_t* p);

/* Returns bufio capacity */
size_t bufio_cap(bufio_t* p);

/* returns bufio tail pointer */
void* bufio_tail(bufio_t* p);

/* returns bufio head pointer */
void* bufio_head(bufio_t* p);

/* shift buffio data to maximize contiguous free space. */
void bufio_shift(bufio_t* p);

/* Discard data from bufio.
 * if sz > 0 data is discarded from bufio tail.
 * if sz < 0 data is discarded from bufio head.
 */
void bufio_discard(bufio_t* p, ssize_t sz);

/* Discard all bufio data, bufio will be empty after this function call */
void bufio_discard_all(bufio_t* p);

/* Extends bufio data after direct write.
 * If you write data to bufio's head pointer, you must call this
 * function to update bufio's internal index.
 */
void bufio_extend(bufio_t* p, size_t sz);

/* Prints data into the buffer */
ssize_t bufio_printf(bufio_t* p, const char* fmt, ...);

/* Pulls data from (s) bufio and pushes it to (p) bufio.
 * Data transfer size is limited by (p) available space or (s) used space.
 */
size_t bufio_push_buffer(bufio_t* p, bufio_t* s);

/* Push up to (sz) bytes or bufio's available space into bufio. */
size_t bufio_push_bytes(bufio_t* p, const void* s, size_t sz);

/* Push one byte into bufio. */
size_t bufio_push_byte(bufio_t* p, uint8_t ch);

/* Pulls up to (sz) bytes or bufio's used space into (t) buffer. */
size_t bufio_pull_bytes(bufio_t* p, void* t, size_t sz);

/* Pulls one byte from bufio. */
int bufio_pull_byte(bufio_t* p);

/* Returns next byte from tail without remove it. */
int bufio_peek_byte(bufio_t* p);

#endif /* BUFIO_H_ */
