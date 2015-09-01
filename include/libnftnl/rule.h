#ifndef _LIBNFTNL_RULE_H_
#define _LIBNFTNL_RULE_H_

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

#include <libnftnl/common.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nftnl_rule;
struct nftnl_rule_expr;

struct nftnl_rule *nftnl_rule_alloc(void);
void nftnl_rule_free(struct nftnl_rule *);

enum {
	NFTNL_RULE_ATTR_FAMILY	= 0,
	NFTNL_RULE_ATTR_TABLE,
	NFTNL_RULE_ATTR_CHAIN,
	NFTNL_RULE_ATTR_HANDLE,
	NFTNL_RULE_ATTR_COMPAT_PROTO,
	NFTNL_RULE_ATTR_COMPAT_FLAGS,
	NFTNL_RULE_ATTR_POSITION,
	NFTNL_RULE_ATTR_USERDATA,
	__NFTNL_RULE_ATTR_MAX
};
#define NFTNL_RULE_ATTR_MAX (__NFTNL_RULE_ATTR_MAX - 1)

void nftnl_rule_attr_unset(struct nftnl_rule *r, uint16_t attr);
bool nftnl_rule_attr_is_set(const struct nftnl_rule *r, uint16_t attr);
void nftnl_rule_attr_set(struct nftnl_rule *r, uint16_t attr, const void *data);
void nftnl_rule_attr_set_data(struct nftnl_rule *r, uint16_t attr,
			    const void *data, uint32_t data_len);
void nftnl_rule_attr_set_u32(struct nftnl_rule *r, uint16_t attr, uint32_t val);
void nftnl_rule_attr_set_u64(struct nftnl_rule *r, uint16_t attr, uint64_t val);
void nftnl_rule_attr_set_str(struct nftnl_rule *r, uint16_t attr, const char *str);

const void *nftnl_rule_attr_get(const struct nftnl_rule *r, uint16_t attr);
const void *nftnl_rule_attr_get_data(const struct nftnl_rule *r, uint16_t attr,
				   uint32_t *data_len);
const char *nftnl_rule_attr_get_str(const struct nftnl_rule *r, uint16_t attr);
uint8_t nftnl_rule_attr_get_u8(const struct nftnl_rule *r, uint16_t attr);
uint32_t nftnl_rule_attr_get_u32(const struct nftnl_rule *r, uint16_t attr);
uint64_t nftnl_rule_attr_get_u64(const struct nftnl_rule *r, uint16_t attr);

void nftnl_rule_add_expr(struct nftnl_rule *r, struct nftnl_rule_expr *expr);

struct nlmsghdr;

void nftnl_rule_nlmsg_build_payload(struct nlmsghdr *nlh, struct nftnl_rule *t);

int nftnl_rule_parse(struct nftnl_rule *r, enum nftnl_parse_type type,
		   const char *data, struct nftnl_parse_err *err);
int nftnl_rule_parse_file(struct nftnl_rule *r, enum nftnl_parse_type type,
			FILE *fp, struct nftnl_parse_err *err);
int nftnl_rule_snprintf(char *buf, size_t size, struct nftnl_rule *t, uint32_t type, uint32_t flags);
int nftnl_rule_fprintf(FILE *fp, struct nftnl_rule *r, uint32_t type, uint32_t flags);

#define nftnl_rule_nlmsg_build_hdr	nftnl_nlmsg_build_hdr
int nftnl_rule_nlmsg_parse(const struct nlmsghdr *nlh, struct nftnl_rule *t);

int nftnl_rule_expr_foreach(struct nftnl_rule *r,
			  int (*cb)(struct nftnl_rule_expr *e, void *data),
			  void *data);

struct nftnl_rule_expr_iter;

struct nftnl_rule_expr_iter *nftnl_rule_expr_iter_create(struct nftnl_rule *r);
struct nftnl_rule_expr *nftnl_rule_expr_iter_next(struct nftnl_rule_expr_iter *iter);
void nftnl_rule_expr_iter_destroy(struct nftnl_rule_expr_iter *iter);

struct nftnl_rule_list;

struct nftnl_rule_list *nftnl_rule_list_alloc(void);
void nftnl_rule_list_free(struct nftnl_rule_list *list);
int nftnl_rule_list_is_empty(struct nftnl_rule_list *list);
void nftnl_rule_list_add(struct nftnl_rule *r, struct nftnl_rule_list *list);
void nftnl_rule_list_add_tail(struct nftnl_rule *r, struct nftnl_rule_list *list);
void nftnl_rule_list_del(struct nftnl_rule *r);
int nftnl_rule_list_foreach(struct nftnl_rule_list *rule_list, int (*cb)(struct nftnl_rule *t, void *data), void *data);

struct nftnl_rule_list_iter;

struct nftnl_rule_list_iter *nftnl_rule_list_iter_create(struct nftnl_rule_list *l);
struct nftnl_rule *nftnl_rule_list_iter_cur(struct nftnl_rule_list_iter *iter);
struct nftnl_rule *nftnl_rule_list_iter_next(struct nftnl_rule_list_iter *iter);
void nftnl_rule_list_iter_destroy(struct nftnl_rule_list_iter *iter);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _LIBNFTNL_RULE_H_ */
