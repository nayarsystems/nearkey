/* parseutils.h -- string parse utils
 *
 *  Created on: 2015/10/22
 *      Author: Jose Luis Aracil Gomez
 *      E-Mail: pepe.aracil.gomez@gmail.com
 *
 *  parseutils is released under the BSD license (see LICENSE). Go to the project
 *  home page (http://github.com/jaracil/parseutils) for more info.
 */

#ifndef PARSEUTILS_H_
#define PARSEUTILS_H_

#include <stddef.h>
#include <stdint.h>

typedef struct str_list {
	char *s;
	struct str_list *next;
} str_list;

typedef struct kv_list {
	char *k;
	char *v;
	struct kv_list *next;
} kv_list;

str_list *str_list_append(str_list *sl, char *s);
void str_list_free(str_list *p);
size_t str_list_len(const str_list *p);
kv_list *kv_list_append(kv_list *kvl, char *k, char *v);
void kv_list_free(kv_list *p);
size_t kv_list_len(const kv_list *p);
kv_list *kv_list_search(kv_list *p, const char *key);
kv_list *kv_parse(const char *text);
char *str_slice(const char *str, int start, int end);
char *str_slice_free(char *str, int start, int end);
str_list *str_split_n(const char *str, const char *sep, size_t n);
str_list *str_split(const char *str, const char *sep);
str_list *str_split_n_safe(const char *str, const char *sep, size_t n);
str_list *str_split_safe(const char *str, const char *sep);
str_list *trim_list(str_list *p);
char *str_trim(const char *str, const char *strip);
char *str_trim_free(char *str, const char *strip);
char *str_ltrim(const char *str, const char *strip);
char *str_ltrim_free(char *str, const char *strip);
char *str_rtrim(const char *str, const char *strip);
char *str_rtrim_free(char *str, const char *strip);
int str_has_prefix(const char *str, const char *pre);
int str_has_suffix(const char *str, const char *suf);
char *str_upper(const char *str);
char *str_upper_free(char *str);
char *str_lower(const char *str);
char *str_lower_free(char *str);
char *str_repl(const char *str, const char *old, const char *new);
char *str_repl_free(char *str, const char *old, const char *new);
int parse_bool(const char *str);
str_list *hex_dump(size_t col, uint8_t *buf, size_t buf_len);

#endif /* PARSEUTILS_H_ */
