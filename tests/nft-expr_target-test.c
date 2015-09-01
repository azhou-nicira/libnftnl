/*
 * (C) 2013 by Ana Rey Botello <anarey@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/netfilter/nf_tables.h>
#include <libmnl/libmnl.h>
#include <libnftnl/rule.h>
#include <libnftnl/expr.h>

static int test_ok = 1;

static void print_err(const char *msg)
{
	test_ok = 0;
	printf("\033[31mERROR:\e[0m %s\n", msg);
}

static void print_err2(const char *msg, uint32_t a, uint32_t b)
{
	test_ok = 0;
	printf("\033[31mERROR:\e[0m %s size a: %d b: %d \n",msg, a, b);
}

static void cmp_nftnl_rule_expr(struct nftnl_rule_expr *rule_a,
			      struct nftnl_rule_expr *rule_b)
{
	uint32_t lena, lenb;

	if (strcmp(nftnl_rule_expr_get_str(rule_a, NFTNL_EXPR_TG_NAME),
		   nftnl_rule_expr_get_str(rule_b, NFTNL_EXPR_TG_NAME)) != 0)
		print_err("Expr NFTNL_EXPR_TG_NAME mismatches");
	if (nftnl_rule_expr_get_u32(rule_a, NFTNL_EXPR_TG_REV) !=
	    nftnl_rule_expr_get_u32(rule_b, NFTNL_EXPR_TG_REV))
		print_err("Expr NFTNL_EXPR_TG_REV mismatches");
	nftnl_rule_expr_get(rule_a, NFTNL_EXPR_TG_INFO, &lena);
	nftnl_rule_expr_get(rule_b, NFTNL_EXPR_TG_INFO, &lenb);
	if (lena != lenb)
		print_err2("Expr NFTNL_EXPR_TG_INFO size mismatches", lena, lenb);
}

int main(int argc, char *argv[])
{
	struct nftnl_rule *a, *b;
	struct nftnl_rule_expr *ex;
	struct nlmsghdr *nlh;
	char buf[4096];
	struct nftnl_rule_expr_iter *iter_a, *iter_b;
	struct nftnl_rule_expr *rule_a, *rule_b;
	char data[16] = "0123456789abcdef";

	a = nftnl_rule_alloc();
	b = nftnl_rule_alloc();
	if (a == NULL || b == NULL)
		print_err("OOM");

	ex = nftnl_rule_expr_alloc("target");
	if (ex == NULL)
		print_err("OOM");

	nftnl_rule_expr_set(ex, NFTNL_EXPR_TG_NAME, "test", strlen("test"));
	nftnl_rule_expr_set_u32(ex, NFTNL_EXPR_TG_REV, 0x12345678);
	nftnl_rule_expr_set(ex, NFTNL_EXPR_TG_INFO, strdup(data), sizeof(data));
	nftnl_rule_add_expr(a, ex);

	nlh = nftnl_rule_nlmsg_build_hdr(buf, NFT_MSG_NEWRULE, AF_INET, 0, 1234);
	nftnl_rule_nlmsg_build_payload(nlh, a);

	if (nftnl_rule_nlmsg_parse(nlh, b) < 0)
		print_err("parsing problems");

	iter_a = nftnl_rule_expr_iter_create(a);
	iter_b = nftnl_rule_expr_iter_create(b);
	if (iter_a == NULL || iter_b == NULL)
		print_err("OOM");

	rule_a = nftnl_rule_expr_iter_next(iter_a);
	rule_b = nftnl_rule_expr_iter_next(iter_b);
	if (rule_a == NULL || rule_b == NULL)
		print_err("OOM");

	cmp_nftnl_rule_expr(rule_a, rule_b);

	if (nftnl_rule_expr_iter_next(iter_a) != NULL ||
	    nftnl_rule_expr_iter_next(iter_b) != NULL)
		print_err("More 1 expr.");

	nftnl_rule_expr_iter_destroy(iter_a);
	nftnl_rule_expr_iter_destroy(iter_b);
	nftnl_rule_free(a);
	nftnl_rule_free(b);

	if (!test_ok)
		exit(EXIT_FAILURE);
	printf("%s: \033[32mOK\e[0m\n", argv[0]);
	return EXIT_SUCCESS;
}
