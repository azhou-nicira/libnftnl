/*
 * (C) 2017 by Andy Zhou <azhou@ovn.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>

#include <linux/netfilter/nf_tables.h>

#include "internal.h"
#include <libmnl/libmnl.h>
#include <libnftnl/object.h>

#include "obj.h"

struct nftnl_obj_meter *g_meter = NULL;

static int nftnl_obj_meter_set(struct nftnl_obj *e, uint16_t type,
			       const void *data, uint32_t data_len)
{
	struct nftnl_obj_meter *meter = nftnl_obj_data(e);

	switch (type) {
	case NFTNL_OBJ_METER_BYTES:
		meter->bytes = *((uint64_t *)data);
		break;
	case NFTNL_OBJ_METER_PACKETS:
		meter->pkts = *((uint64_t *)data);
		break;
	case NFTNL_OBJ_METER_FLAGS:
		meter->flags = *((uint32_t *)data);
		break;
	case NFTNL_OBJ_METER_BANDS:
		meter->n_bands = data_len;
		meter->bands = *(struct nftnl_meter_band **)data;
		break;
	default:
		return -1;
	}
	return 0;
}

static const void *nftnl_obj_meter_get(const struct nftnl_obj *e,
					uint16_t type, uint32_t *data_len)
{
	struct nftnl_obj_meter *meter = nftnl_obj_data(e);

	switch (type) {
	case NFTNL_OBJ_METER_BYTES:
		*data_len = sizeof(meter->bytes);
		return &meter->bytes;
	case NFTNL_OBJ_METER_PACKETS:
		*data_len = sizeof(meter->pkts);
		return &meter->pkts;
	case NFTNL_OBJ_METER_FLAGS:
		*data_len = sizeof(meter->flags);
		return &meter->flags;
	case NFTNL_OBJ_METER_BANDS:
		*data_len = meter->n_bands;
		return &meter->bands;
	}
	return NULL;
}

static int nftnl_obj_meter_cb(const struct nlattr *attr, void *data)
{
	int type = mnl_attr_get_type(attr);
	const struct nlattr **tb = data;

	if (mnl_attr_type_valid(attr, NFTA_METER_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_METER_BYTES:
	case NFTA_METER_PACKETS:
		if (mnl_attr_validate(attr, MNL_TYPE_U64) < 0)
			abi_breakage();
		break;
	case NFTA_METER_FLAGS:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			abi_breakage();
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static void nftnl_obj_meter_band_build(struct nlmsghdr *nlh,
				       const struct nftnl_meter_band *band)
{
	struct nlattr *start;

	start = mnl_attr_nest_start(nlh, NFTA_METER_BAND);
	if (start) {
		mnl_attr_put_u64(nlh, NFTA_METER_BAND_BYTES,
				 htobe64(band->bytes));
		mnl_attr_put_u64(nlh, NFTA_METER_BAND_PACKETS,
				 htobe64(band->pkts));
		mnl_attr_put_u64(nlh, NFTA_METER_BAND_RATE,
				 htobe64(band->rate));
		mnl_attr_put_u64(nlh, NFTA_METER_BAND_UNIT,
				 htobe64(band->unit));
		mnl_attr_put_u64(nlh, NFTA_METER_BAND_BURST,
				 htobe64(band->burst));
		mnl_attr_put_u32(nlh, NFTA_METER_BAND_TYPE,
				 htonl(band->type));
		mnl_attr_nest_end(nlh, start);
	}
}

static void nftnl_obj_meter_bands_build(struct nlmsghdr *nlh,
					const struct nftnl_meter_band *bands,
					const int n_bands)
{
	struct nlattr *start;
	int i;

	if (n_bands <= 0)
		return;

	if (n_bands == 1)
		return nftnl_obj_meter_band_build(nlh, bands);

	start = mnl_attr_nest_start(nlh, NFTA_METER_BANDS);
	if (start) {
		for (i = 0; i < n_bands; i++)
			nftnl_obj_meter_band_build(nlh, &bands[i]);
		mnl_attr_nest_end(nlh, start);
	}
}

static void nftnl_obj_meter_build(struct nlmsghdr *nlh,
				  const struct nftnl_obj *e)
{
	struct nftnl_obj_meter *meter = nftnl_obj_data(e);

	g_meter = meter;

	if (e->flags & (1 << NFTNL_OBJ_METER_BYTES))
		mnl_attr_put_u64(nlh, NFTA_METER_BYTES,
				 htobe64(meter->bytes));

	if (e->flags & (1 << NFTNL_OBJ_METER_PACKETS))
		mnl_attr_put_u64(nlh, NFTA_METER_PACKETS,
				 htobe64(meter->pkts));

	if (e->flags & (1 << NFTNL_OBJ_METER_FLAGS))
		mnl_attr_put_u32(nlh, NFTA_METER_FLAGS, htonl(meter->flags));

	if (e->flags & (1 << NFTNL_OBJ_METER_BANDS))
		nftnl_obj_meter_bands_build(nlh, meter->bands, meter->n_bands);
}

static int nftnl_obj_meter_band_cb(const struct nlattr *attr, void *data)
{
	int type = mnl_attr_get_type(attr);
	const struct nlattr **tb = data;

	if (mnl_attr_type_valid(attr, NFTA_METER_BAND_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_METER_BAND_BYTES:
	case NFTA_METER_BAND_PACKETS:
	case NFTA_METER_BAND_RATE:
	case NFTA_METER_BAND_UNIT:
	case NFTA_METER_BAND_BURST:
		if (mnl_attr_validate(attr, MNL_TYPE_U64) < 0)
			abi_breakage();
		break;
	case NFTA_METER_BAND_TYPE:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			abi_breakage();
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static int nftnl_obj_meter_band_parse(const struct nlattr *attr,
				      struct nftnl_meter_band *band)
{
	struct nlattr *tb[NFTA_METER_BAND_MAX + 1] = {};
	if (mnl_attr_parse_nested(attr, nftnl_obj_meter_band_cb, tb) < 0)
		return -1;

	if (tb[NFTA_METER_BAND_BYTES])
		band->bytes = be64toh(
			mnl_attr_get_u64(tb[NFTA_METER_BAND_BYTES]));

	if (tb[NFTA_METER_BAND_PACKETS])
		band->pkts = be64toh(
			mnl_attr_get_u64(tb[NFTA_METER_BAND_PACKETS]));

	if (tb[NFTA_METER_BAND_RATE])
		band->rate = be64toh(
			mnl_attr_get_u64(tb[NFTA_METER_BAND_RATE]));

	if (tb[NFTA_METER_BAND_UNIT])
		band->unit = be64toh(
			mnl_attr_get_u64(tb[NFTA_METER_BAND_UNIT]));

	if (tb[NFTA_METER_BAND_BURST])
		band->burst = be64toh(
			mnl_attr_get_u64(tb[NFTA_METER_BAND_BURST]));

	if (tb[NFTA_METER_BAND_TYPE])
		band->type = be32toh(
			mnl_attr_get_u64(tb[NFTA_METER_BAND_TYPE]));

	return 0;
}

static int nftnl_obj_meter_bands_parse(const struct nlattr *bands,
				       const struct nlattr *band,
				       struct nftnl_obj_meter *meter)
{
	int n;

	if (band) {
		meter->n_bands=1;
	} else {
		meter->n_bands=0;
		mnl_attr_for_each_nested(band, bands) meter->n_bands++;
	}

	meter->bands = malloc(sizeof (*meter->bands) * meter->n_bands);
	if (!meter->bands)
		return -1;

	if (bands) {
		n = 0;
		mnl_attr_for_each_nested(band, bands) {
			if (nftnl_obj_meter_band_parse(band,
						       &meter->bands[n]) < 0)
				goto err;
			n++;
		}
	} else {
		if (nftnl_obj_meter_band_parse(band, meter->bands) < 0)
			goto err;
	}
	return 0;
err:
	free(meter->bands);
	meter->n_bands = 0;
	meter->bands = NULL;
	return -1;
}

static int
nftnl_obj_meter_parse(struct nftnl_obj *e, struct nlattr *attr)
{
	struct nftnl_obj_meter *meter = nftnl_obj_data(e);
	struct nlattr *tb[NFTA_METER_MAX + 1] = {};

	if (mnl_attr_parse_nested(attr, nftnl_obj_meter_cb, tb) < 0)
		return -1;

	if (tb[NFTA_METER_BYTES]) {
		meter->bytes =
			be64toh(mnl_attr_get_u64(tb[NFTA_METER_BYTES]));
		e->flags |= (1 << NFTNL_OBJ_METER_BYTES);
	}
	if (tb[NFTA_METER_PACKETS]) {
		meter->pkts =
			be64toh(mnl_attr_get_u64(tb[NFTA_METER_PACKETS]));
		e->flags |= (1 << NFTNL_OBJ_METER_PACKETS);
	}
	if (tb[NFTA_METER_FLAGS]) {
		meter->flags = ntohl(mnl_attr_get_u32(tb[NFTA_METER_FLAGS]));
		e->flags |= (1 << NFTNL_OBJ_METER_FLAGS);
	}
	if (tb[NFTA_METER_BAND] || tb[NFTA_METER_BANDS]) {
		if (nftnl_obj_meter_bands_parse(tb[NFTA_METER_BANDS],
						tb[NFTA_METER_BAND],
						meter) < 0)
			return -1;

		e->flags |= (1 << NFTNL_OBJ_METER_BANDS);
	}
	return 0;
}

#ifdef JSON_PARSING
static int nftnl_obj_meter_band_json_parse(json_t *root,
		struct nftnl_meter_band *band,
		struct nftnl_parse_err *err)
{
	bool error;
	error = nftnl_jansson_parse_val(root, "bytes",
				NFTNL_TYPE_U64, &band->bytes, err) < 0 ||
		nftnl_jansson_parse_val(root, "packets",
				NFTNL_TYPE_U64, &band->pkts, err) < 0 ||
		nftnl_jansson_parse_val(root, "rate",
				NFTNL_TYPE_U64, &band->rate, err) < 0 ||
		nftnl_jansson_parse_val(root, "units",
				NFTNL_TYPE_U64, &band->unit, err) < 0 ||
		nftnl_jansson_parse_val(root, "burst",
				NFTNL_TYPE_U64, &band->burst, err) < 0 ||
		nftnl_jansson_parse_val(root, "type",
				NFTNL_TYPE_U32, &band->type, err) < 0;

	return error ? -1 : 0;
}
#endif

#ifdef JSON_PARSING
static int nftnl_obj_meter_bands_json_parse(json_t *tree,
		struct nftnl_meter_band **bands_p, int *n_bands_p,
		struct nftnl_parse_err *err)
{
	struct nftnl_meter_band *bands;
	json_t *root;
	int n_bands;

	root = nftnl_jansson_get_node(tree, "bands", err);

	if (root) {
		int i;
		n_bands = json_array_size(root);
		bands = malloc(sizeof *bands * n_bands);

		if (!bands)
			return -1;

		for (i = 0; i < n_bands; i++) {
			json_t *node = json_array_get(root, i);
			if (nftnl_obj_meter_band_json_parse(node,
						&bands[i], err) < 0) {
				free(bands);
				return -1;
			}
		}
	} else {
		root = nftnl_jansson_get_node(tree, "band", err);
		n_bands = 1;
		bands = malloc(sizeof *bands);
		if (!bands)
			return -1;

		if (nftnl_obj_meter_band_json_parse(root, bands, err) < 0) {
				free(bands);
				return -1;
		}
	}

	*bands_p = bands;
	*n_bands_p = n_bands;
	return 0;
}
#endif

static int nftnl_obj_meter_json_parse(struct nftnl_obj *e, json_t *root,
				      struct nftnl_parse_err *err)
{
#ifdef JSON_PARSING
	uint64_t bytes, packets;
	uint32_t flags;
	struct nftnl_meter_band *bands;
	int n_bands;

	if (nftnl_jansson_parse_val(root, "bytes", NFTNL_TYPE_U64, &bytes,
				  err) == 0)
		nftnl_obj_set_u64(e, NFTNL_OBJ_METER_BYTES, bytes);
	if (nftnl_jansson_parse_val(root, "packets", NFTNL_TYPE_U64, &packets,
				    err) == 0)
		nftnl_obj_set_u64(e, NFTNL_OBJ_METER_PACKETS, packets);
	if (nftnl_jansson_parse_val(root, "flags", NFTNL_TYPE_U32, &flags,
				  err) == 0)
		nftnl_obj_set_u32(e, NFTNL_OBJ_METER_FLAGS, flags);

	if (nftnl_jansson_node_exist(root, "bands")) {

		if (nftnl_obj_meter_bands_json_parse(root, &bands,
					&n_bands, err) < 0)
			return -1;

		nftnl_obj_set_data(e, NFTNL_OBJ_METER_BANDS,
				   bands, sizeof (*bands) * n_bands);
	} else {
		nftnl_obj_set_data(e, NFTNL_OBJ_METER_BANDS, NULL, 0);
	}

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int nftnl_obj_meter_band_export(struct nftnl_buf *b, int type,
				const struct nftnl_meter_band *band)
{
	nftnl_buf_open(b, type, BAND);
	nftnl_buf_u64(b, type, band->bytes, BYTES);
	nftnl_buf_u64(b, type, band->pkts, PACKETS);
	nftnl_buf_u64(b, type, band->rate, RATE);
	nftnl_buf_u64(b, type, band->unit, UNIT);
	nftnl_buf_u64(b, type, band->burst, BURST);
	nftnl_buf_u64(b, type, band->type, TYPE);
	return nftnl_buf_close(b, type, BAND);
}

static int nftnl_obj_meter_bands_export(struct nftnl_buf *b, int type,
			const struct nftnl_meter_band *bands, int n_bands)
{
	int i;

	nftnl_buf_open(b, type, BANDS);
	for(i = 0; i < n_bands; i++)
		nftnl_obj_meter_band_export(b, type, &bands[i]);

	return nftnl_buf_close(b, type, BANDS);
}

static int nftnl_obj_meter_export(char *buf, size_t size,
				  const struct nftnl_obj *e, int type)
{
	struct nftnl_obj_meter *meter = nftnl_obj_data(e);
	NFTNL_BUF_INIT(b, buf, size);

	if (e->flags & (1 << NFTNL_OBJ_METER_BYTES)) {
		nftnl_buf_u64(&b, type, meter->bytes, BYTES);
	}
	if (e->flags & (1 << NFTNL_OBJ_METER_PACKETS)) {
		nftnl_buf_u64(&b, type, meter->pkts, PACKETS);
	}
	if (e->flags & (1 << NFTNL_OBJ_METER_FLAGS)) {
		nftnl_buf_u32(&b, type, meter->flags, FLAGS);
	}
	if (e->flags & (1 << NFTNL_OBJ_METER_BANDS)) {
		nftnl_obj_meter_bands_export(&b, type,
				meter->bands, meter->n_bands);
	}

	return nftnl_buf_done(&b);
}

static int nftnl_obj_meter_snprintf_default(char *buf, size_t len,
					    const struct nftnl_obj *e)
{
	struct nftnl_obj_meter *meter = nftnl_obj_data(e);
	int n;

	n = snprintf(buf, len, "flags %u bands %d", meter->flags,
		     meter->n_bands);

	return n;
}

static int nftnl_obj_meter_snprintf(char *buf, size_t len, uint32_t type,
				    uint32_t flags,
				    const struct nftnl_obj *e)
{
	switch (type) {
	case NFTNL_OUTPUT_DEFAULT:
		return nftnl_obj_meter_snprintf_default(buf, len, e);
	case NFTNL_OUTPUT_XML:
	case NFTNL_OUTPUT_JSON:
		return nftnl_obj_meter_export(buf, len, e, type);
	default:
		break;
	}
	return -1;
}

struct nftnl_meter_band *nftnl_meter_bands_alloc(int
		n_bands)
{
	return calloc(1, sizeof (struct nftnl_meter_band) * n_bands);
}
EXPORT_SYMBOL(nftnl_meter_bands_alloc);

static void nftnl_meter_band_set_data(struct nftnl_meter_band *bands, int idx,
				      uint16_t attr, const void *data,
				      uint32_t data_len)
{
	switch (attr) {
	case NFTNL_METER_BAND_BYTES:
		bands[idx].bytes = *((uint64_t *)data);
		break;
	case NFTNL_METER_BAND_PACKETS:
		bands[idx].pkts = *((uint64_t *)data);
		break;
	case NFTNL_METER_BAND_RATE:
		bands[idx].rate = *((uint64_t *)data);
		break;
	case NFTNL_METER_BAND_UNIT:
		bands[idx].unit = *((uint64_t *)data);
		break;
	case NFTNL_METER_BAND_BURST:
		bands[idx].burst = *((uint64_t *)data);
		break;
	case NFTNL_METER_BAND_TYPE:
		bands[idx].type = *((uint32_t *)data);
		break;
	default:
		break;
	}
}

static const void *nftnl_meter_band_get_data(struct nftnl_meter_band *bands,
					     int idx, uint16_t attr,
					     uint32_t *data_len)
{
	switch (attr) {
	case NFTNL_METER_BAND_BYTES:
		*data_len = sizeof(uint64_t);
		return &bands[idx].bytes;
	case NFTNL_METER_BAND_PACKETS:
		*data_len = sizeof(uint64_t);
		return &bands[idx].pkts;
	case NFTNL_METER_BAND_RATE:
		*data_len = sizeof(uint64_t);
		return &bands[idx].rate;
	case NFTNL_METER_BAND_UNIT:
		*data_len = sizeof(uint64_t);
		return &bands[idx].unit;
		break;
	case NFTNL_METER_BAND_BURST:
		*data_len = sizeof(uint64_t);
		return &bands[idx].burst;
	case NFTNL_METER_BAND_TYPE:
		*data_len = sizeof(uint32_t);
		return &bands[idx].type;
	default:
		*data_len = 0;
		return NULL;
	}
}

void nftnl_meter_band_set_u32(struct nftnl_meter_band *bands, int idx,
			      uint16_t attr, uint32_t val)
{
	nftnl_meter_band_set_data(bands, idx, attr, &val, sizeof(val));
}
EXPORT_SYMBOL(nftnl_meter_band_set_u32);

void nftnl_meter_band_set_u64(struct nftnl_meter_band *bands, int idx,
			      uint16_t attr, uint64_t val)
{
	nftnl_meter_band_set_data(bands, idx, attr, &val, sizeof(val));
}
EXPORT_SYMBOL(nftnl_meter_band_set_u64);

uint64_t nftnl_meter_band_get_u64(struct nftnl_meter_band *bands, int idx,
				  uint16_t attr)
{
	uint32_t data_len;
	const uint64_t *val;

	val = nftnl_meter_band_get_data(bands, idx, attr, &data_len);

	if (!val || data_len != sizeof *val) {
		return 0;
	};

	return *val;
}
EXPORT_SYMBOL(nftnl_meter_band_get_u64);

uint32_t nftnl_meter_band_get_u32(struct nftnl_meter_band *bands, int idx,
				  uint16_t attr)
{
	uint32_t data_len;
	const uint32_t *val;

	val = nftnl_meter_band_get_data(bands, idx, attr, &data_len);

	if (!val || data_len != sizeof *val) {
		return 0;
	};

	return *val;
}
EXPORT_SYMBOL(nftnl_meter_band_get_u32);

struct obj_ops obj_ops_meter = {
	.name		= "meter",
	.type		= NFT_OBJECT_METER,
	.alloc_len	= sizeof(struct nftnl_obj_meter),
	.max_attr	= NFTA_METER_MAX,
	.set		= nftnl_obj_meter_set,
	.get		= nftnl_obj_meter_get,
	.parse		= nftnl_obj_meter_parse,
	.build		= nftnl_obj_meter_build,
	.snprintf	= nftnl_obj_meter_snprintf,
	.json_parse	= nftnl_obj_meter_json_parse,
};
