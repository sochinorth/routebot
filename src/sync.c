#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <linux/fib_rules.h>
#include <linux/rtnetlink.h>

#include "log.h"
#include "sync.h"

static const int families[2] = { AF_INET, AF_INET6 };

/* --- rendering --- */

static void render(struct route_spec *r, const struct ifrender *ir)
{
	if (ir->usable) {
		r->type = RTN_UNICAST;
		r->oif = ir->ifindex;
		r->has_gw = ir->has_gw;
		if (ir->has_gw)
			memcpy(r->gw, ir->gw, sizeof(r->gw));
	} else {
		r->type = RTN_BLACKHOLE;
	}
}

static bool route_key_eq(const struct route_spec *a, const struct route_spec *b)
{
	return a->family == b->family && a->plen == b->plen && a->table == b->table &&
	       !memcmp(a->dst, b->dst, sizeof(a->dst));
}

static bool route_eq(const struct route_spec *a, const struct route_spec *b)
{
	return route_key_eq(a, b) && a->proto == b->proto && a->type == b->type &&
	       a->oif == b->oif && a->has_gw == b->has_gw &&
	       !memcmp(a->gw, b->gw, sizeof(a->gw));
}

static bool rule_eq(const struct rule_spec *a, const struct rule_spec *b)
{
	return a->family == b->family && a->proto == b->proto && a->prio == b->prio &&
	       a->mark == b->mark && a->mask == b->mask && a->table == b->table;
}

static size_t gen_rules(const struct world *w, struct rule_spec *out)
{
	const struct config *c = w->cfg;
	size_t n = 0;

	if (!c)
		return 0;

	for (int f = 0; f < 2; f++) {
		for (size_t i = 0; i < c->n_ifaces; i++) {
			if (!c->ifaces[i].fwmark)
				continue;
			out[n++] = (struct rule_spec){
				.family = families[f],
				.proto = c->rt_proto,
				.prio = cfg_iface_prio(c, i),
				.mark = c->ifaces[i].fwmark,
				.mask = c->fwmask,
				.table = cfg_iface_table(c, i),
			};
		}
		out[n++] = (struct rule_spec){
			.family = families[f],
			.proto = c->rt_proto,
			.prio = c->rule_prio,
			.mark = 0,
			.mask = c->fwmask,
			.table = c->table_id,
		};
	}

	return n;
}

static size_t gen_defaults(const struct world *w, struct route_spec *out)
{
	const struct config *c = w->cfg;
	size_t n = 0;

	if (!c)
		return 0;

	for (size_t i = 0; i < c->n_ifaces; i++) {
		if (!c->ifaces[i].fwmark)
			continue;
		for (int f = 0; f < 2; f++) {
			struct route_spec *r = &out[n++];

			memset(r, 0, sizeof(*r));
			r->family = families[f];
			r->table = cfg_iface_table(c, i);
			r->proto = c->rt_proto;
			render(r, &w->ifs[i].fam[f]);
		}
	}

	return n;
}

static void prefix_route(const struct world *w, const struct prefix *p, struct route_spec *r)
{
	memset(r, 0, sizeof(*r));
	r->family = p->family;
	r->plen = p->plen;
	memcpy(r->dst, p->addr, family_alen(p->family));
	r->table = w->cfg->table_id;
	r->proto = w->cfg->rt_proto;
	render(r, &w->ifs[p->iface].fam[fam_idx(p->family)]);
}

/* --- diffing --- */

/* Set everything in new that old doesn't have identically. */
static void small_routes_set(struct nl *nl, const struct route_spec *o, size_t no,
			     const struct route_spec *n, size_t nn, struct sync_stats *st)
{
	for (size_t j = 0; j < nn; j++) {
		size_t i;

		for (i = 0; i < no; i++)
			if (route_eq(&o[i], &n[j]))
				break;
		if (i == no) {
			nl_route(nl, NL_SET, &n[j]);
			st->route_set++;
		}
	}
}

/* Delete everything in old whose key is gone from new. */
static void small_routes_del(struct nl *nl, const struct route_spec *o, size_t no,
			     const struct route_spec *n, size_t nn, struct sync_stats *st)
{
	for (size_t i = 0; i < no; i++) {
		size_t j;

		for (j = 0; j < nn; j++)
			if (route_key_eq(&o[i], &n[j]))
				break;
		if (j == nn) {
			nl_route(nl, NL_DEL, &o[i]);
			st->route_del++;
		}
	}
}

/* Rules in a but not in b get op applied. */
static void rules_diff(struct nl *nl, enum nl_op op, const struct rule_spec *a, size_t na,
		       const struct rule_spec *b, size_t nb, unsigned *count)
{
	for (size_t i = 0; i < na; i++) {
		size_t j;

		for (j = 0; j < nb; j++)
			if (rule_eq(&a[i], &b[j]))
				break;
		if (j == nb) {
			nl_rule(nl, op, &a[i]);
			(*count)++;
		}
	}
}

/*
 * Same table and tag means old and new routes share keys and can be
 * merge-walked; otherwise they are disjoint sets.
 */
static bool prefixes_comparable(const struct world *old, const struct world *new)
{
	return old->cfg && new->cfg && old->cfg->table_id == new->cfg->table_id &&
	       old->cfg->rt_proto == new->cfg->rt_proto;
}

static void prefixes_set(struct nl *nl, const struct world *old, const struct world *new,
			 struct sync_stats *st)
{
	const struct prefix *op = NULL, *np;
	size_t no = 0, nn, i = 0, j = 0;
	struct route_spec ro, rn;

	if (!new->cfg)
		return;
	np = new->cfg->prefixes;
	nn = new->cfg->n_prefixes;
	if (prefixes_comparable(old, new)) {
		op = old->cfg->prefixes;
		no = old->cfg->n_prefixes;
	}

	while (j < nn) {
		int cmp = i < no ? prefix_cmp(&op[i], &np[j]) : 1;

		if (cmp < 0) {
			i++;
			continue;
		}

		prefix_route(new, &np[j], &rn);
		if (cmp == 0) {
			prefix_route(old, &op[i], &ro);
			i++;
			if (route_eq(&ro, &rn)) {
				j++;
				continue;
			}
		}
		nl_route(nl, NL_SET, &rn);
		st->route_set++;
		j++;
	}
}

static void prefixes_del(struct nl *nl, const struct world *old, const struct world *new,
			 struct sync_stats *st)
{
	const struct prefix *op, *np = NULL;
	size_t no, nn = 0, i = 0, j = 0;
	struct route_spec ro;

	if (!old->cfg)
		return;
	op = old->cfg->prefixes;
	no = old->cfg->n_prefixes;
	if (prefixes_comparable(old, new)) {
		np = new->cfg->prefixes;
		nn = new->cfg->n_prefixes;
	}

	while (i < no) {
		int cmp = j < nn ? prefix_cmp(&op[i], &np[j]) : -1;

		if (cmp > 0) {
			j++;
			continue;
		}
		if (cmp == 0) {
			i++;
			j++;
			continue;
		}
		prefix_route(old, &op[i], &ro);
		nl_route(nl, NL_DEL, &ro);
		st->route_del++;
		i++;
	}
}

void sync_apply(struct nl *nl, const struct world *old, const struct world *new,
		struct sync_stats *st)
{
	size_t no_if = old->cfg ? old->cfg->n_ifaces : 0;
	size_t nn_if = new->cfg ? new->cfg->n_ifaces : 0;
	struct rule_spec *ro, *rn;
	struct route_spec *dro, *drn;
	size_t n_ro, n_rn, n_dro, n_drn;

	memset(st, 0, sizeof(*st));

	ro = calloc(2 * (no_if + 1), sizeof(*ro));
	rn = calloc(2 * (nn_if + 1), sizeof(*rn));
	dro = calloc(2 * no_if + 1, sizeof(*dro));
	drn = calloc(2 * nn_if + 1, sizeof(*drn));
	if (!ro || !rn || !dro || !drn) {
		err("out of memory");
		st->errors++;
		goto out;
	}

	n_ro = gen_rules(old, ro);
	n_rn = gen_rules(new, rn);
	n_dro = gen_defaults(old, dro);
	n_drn = gen_defaults(new, drn);

	nl_batch_begin(nl);

	/* make before break: fill tables, then point rules at them, then clean up */
	small_routes_set(nl, dro, n_dro, drn, n_drn, st);
	prefixes_set(nl, old, new, st);
	rules_diff(nl, NL_SET, rn, n_rn, ro, n_ro, &st->rule_add);
	rules_diff(nl, NL_DEL, ro, n_ro, rn, n_rn, &st->rule_del);
	small_routes_del(nl, dro, n_dro, drn, n_drn, st);
	prefixes_del(nl, old, new, st);

	st->errors = nl_batch_end(nl);

out:
	free(ro);
	free(rn);
	free(dro);
	free(drn);
}

/* --- flush --- */

struct flush_ctx {
	uint8_t proto;
	struct route_spec *routes;
	size_t n_routes, cap_routes;
	struct rule_spec *rules;
	size_t n_rules, cap_rules;
	bool oom;
};

static void *grow(void *p, size_t *cap, size_t n, size_t size)
{
	void *np;

	if (n < *cap)
		return p;
	*cap = *cap ? *cap * 2 : 256;
	np = realloc(p, *cap * size);
	return np;
}

struct attrs {
	const struct nlattr *tb[32];
};

static int attrs_cb(const struct nlattr *a, void *data)
{
	struct attrs *t = data;
	unsigned type = mnl_attr_get_type(a);

	if (type < 32)
		t->tb[type] = a;
	return MNL_CB_OK;
}

static int flush_route_cb(const struct nlmsghdr *nlh, void *data)
{
	struct flush_ctx *fc = data;
	const struct rtmsg *rtm = mnl_nlmsg_get_payload(nlh);
	struct attrs t = {};
	struct route_spec *r, *nr;

	if (rtm->rtm_protocol != fc->proto ||
	    (rtm->rtm_family != AF_INET && rtm->rtm_family != AF_INET6))
		return MNL_CB_OK;

	nr = grow(fc->routes, &fc->cap_routes, fc->n_routes, sizeof(*nr));
	if (!nr) {
		fc->oom = true;
		return MNL_CB_ERROR;
	}
	fc->routes = nr;
	r = &fc->routes[fc->n_routes++];
	memset(r, 0, sizeof(*r));

	mnl_attr_parse(nlh, sizeof(*rtm), attrs_cb, &t);
	r->family = rtm->rtm_family;
	r->plen = rtm->rtm_dst_len;
	r->proto = rtm->rtm_protocol;
	r->table = t.tb[RTA_TABLE] ? mnl_attr_get_u32(t.tb[RTA_TABLE]) : rtm->rtm_table;
	if (t.tb[RTA_DST] && mnl_attr_get_payload_len(t.tb[RTA_DST]) <= sizeof(r->dst))
		memcpy(r->dst, mnl_attr_get_payload(t.tb[RTA_DST]),
		       mnl_attr_get_payload_len(t.tb[RTA_DST]));
	return MNL_CB_OK;
}

static int flush_rule_cb(const struct nlmsghdr *nlh, void *data)
{
	struct flush_ctx *fc = data;
	const struct fib_rule_hdr *frh = mnl_nlmsg_get_payload(nlh);
	struct attrs t = {};
	struct rule_spec *r, *nr;

	mnl_attr_parse(nlh, sizeof(*frh), attrs_cb, &t);
	if (!t.tb[FRA_PROTOCOL] || mnl_attr_get_u8(t.tb[FRA_PROTOCOL]) != fc->proto)
		return MNL_CB_OK;

	nr = grow(fc->rules, &fc->cap_rules, fc->n_rules, sizeof(*nr));
	if (!nr) {
		fc->oom = true;
		return MNL_CB_ERROR;
	}
	fc->rules = nr;
	r = &fc->rules[fc->n_rules++];
	*r = (struct rule_spec){
		.family = frh->family,
		.proto = fc->proto,
		.prio = t.tb[FRA_PRIORITY] ? mnl_attr_get_u32(t.tb[FRA_PRIORITY]) : 0,
		.mark = t.tb[FRA_FWMARK] ? mnl_attr_get_u32(t.tb[FRA_FWMARK]) : 0,
		.mask = t.tb[FRA_FWMASK] ? mnl_attr_get_u32(t.tb[FRA_FWMASK]) : 0,
		.table = t.tb[FRA_TABLE] ? mnl_attr_get_u32(t.tb[FRA_TABLE]) : frh->table,
	};
	return MNL_CB_OK;
}

int sync_flush(struct nl *nl, uint8_t proto)
{
	char buf[128] __attribute__((aligned(4)));
	struct flush_ctx fc = { .proto = proto };
	struct nlmsghdr *nlh;
	struct fib_rule_hdr *frh;
	struct rtmsg *rtm;
	unsigned errors;
	int ret;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = RTM_GETRULE;
	frh = mnl_nlmsg_put_extra_header(nlh, sizeof(*frh));
	frh->family = AF_UNSPEC;
	ret = nl_dump(nl, nlh, flush_rule_cb, &fc);
	if (ret)
		goto fail;

	/* with NETLINK_GET_STRICT_CHK the kernel filters by protocol already */
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = RTM_GETROUTE;
	rtm = mnl_nlmsg_put_extra_header(nlh, sizeof(*rtm));
	rtm->rtm_family = AF_UNSPEC;
	rtm->rtm_protocol = proto;
	ret = nl_dump(nl, nlh, flush_route_cb, &fc);
	if (ret)
		goto fail;

	nl_batch_begin(nl);
	for (size_t i = 0; i < fc.n_rules; i++)
		nl_rule(nl, NL_DEL, &fc.rules[i]);
	for (size_t i = 0; i < fc.n_routes; i++)
		nl_route(nl, NL_DEL, &fc.routes[i]);
	errors = nl_batch_end(nl);

	if (fc.n_rules || fc.n_routes)
		info("flush: removed %zu rules, %zu routes with proto %u%s",
		     fc.n_rules, fc.n_routes, proto, errors ? " (with errors)" : "");

	free(fc.routes);
	free(fc.rules);
	return errors ? -EIO : 0;

fail:
	err("flush: dump failed: %s", fc.oom ? "out of memory" : strerror(-ret));
	free(fc.routes);
	free(fc.rules);
	return ret;
}
