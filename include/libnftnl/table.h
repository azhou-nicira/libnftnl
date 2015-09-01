#ifndef _LIBNFTNL_TABLE_H_
#define _LIBNFTNL_TABLE_H_

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

#include <libnftnl/common.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nftnl_table;

struct nftnl_table *nftnl_table_alloc(void);
void nftnl_table_free(struct nftnl_table *);

enum {
	NFTNL_TABLE_ATTR_NAME	= 0,
	NFTNL_TABLE_ATTR_FAMILY,
	NFTNL_TABLE_ATTR_FLAGS,
	NFTNL_TABLE_ATTR_USE,
	__NFTNL_TABLE_ATTR_MAX
};
#define NFTNL_TABLE_ATTR_MAX (__NFTNL_TABLE_ATTR_MAX - 1)

bool nftnl_table_attr_is_set(const struct nftnl_table *t, uint16_t attr);
void nftnl_table_attr_unset(struct nftnl_table *t, uint16_t attr);
void nftnl_table_attr_set(struct nftnl_table *t, uint16_t attr, const void *data);
void nftnl_table_attr_set_data(struct nftnl_table *t, uint16_t attr,
			     const void *data, uint32_t data_len);
const void *nftnl_table_attr_get(struct nftnl_table *t, uint16_t attr);
const void *nftnl_table_attr_get_data(struct nftnl_table *t, uint16_t attr,
				    uint32_t *data_len);

void nftnl_table_attr_set_u8(struct nftnl_table *t, uint16_t attr, uint8_t data);
void nftnl_table_attr_set_u32(struct nftnl_table *t, uint16_t attr, uint32_t data);
void nftnl_table_attr_set_str(struct nftnl_table *t, uint16_t attr, const char *str);
uint8_t nftnl_table_attr_get_u8(struct nftnl_table *t, uint16_t attr);
uint32_t nftnl_table_attr_get_u32(struct nftnl_table *t, uint16_t attr);
const char *nftnl_table_attr_get_str(struct nftnl_table *t, uint16_t attr);

struct nlmsghdr;

void nftnl_table_nlmsg_build_payload(struct nlmsghdr *nlh, const struct nftnl_table *t);

int nftnl_table_parse(struct nftnl_table *t, enum nftnl_parse_type type,
		    const char *data, struct nftnl_parse_err *err);
int nftnl_table_parse_file(struct nftnl_table *t, enum nftnl_parse_type type,
			 FILE *fp, struct nftnl_parse_err *err);
int nftnl_table_snprintf(char *buf, size_t size, struct nftnl_table *t, uint32_t type, uint32_t flags);
int nftnl_table_fprintf(FILE *fp, struct nftnl_table *t, uint32_t type, uint32_t flags);

#define nftnl_table_nlmsg_build_hdr	nftnl_nlmsg_build_hdr
int nftnl_table_nlmsg_parse(const struct nlmsghdr *nlh, struct nftnl_table *t);

struct nftnl_table_list;

struct nftnl_table_list *nftnl_table_list_alloc(void);
void nftnl_table_list_free(struct nftnl_table_list *list);
int nftnl_table_list_is_empty(struct nftnl_table_list *list);
int nftnl_table_list_foreach(struct nftnl_table_list *table_list, int (*cb)(struct nftnl_table *t, void *data), void *data);

void nftnl_table_list_add(struct nftnl_table *r, struct nftnl_table_list *list);
void nftnl_table_list_add_tail(struct nftnl_table *r, struct nftnl_table_list *list);
void nftnl_table_list_del(struct nftnl_table *r);

struct nftnl_table_list_iter;

struct nftnl_table_list_iter *nftnl_table_list_iter_create(struct nftnl_table_list *l);
struct nftnl_table *nftnl_table_list_iter_next(struct nftnl_table_list_iter *iter);
void nftnl_table_list_iter_destroy(struct nftnl_table_list_iter *iter);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _LIBNFTNL_TABLE_H_ */
