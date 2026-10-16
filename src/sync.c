#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <linux/fib_rules.h>
#include <linux/nexthop.h>
#include <linux/rtnetlink.h>

#include "log.h"
#include "sync.h"

static const int families[2] = { AF_INET, AF_INET6 };

/* --- rendering --- */

size_t cfg_member_index(const struct config *c, size_t g, size_t m)
{
	for (size_t i = 0; i < g; i++)
		m += c->groups[i].n_members;
	return m;
}

bool world_member_usable(const struct world *w, size_t g, size_t m, int f)
{
	const struct cfg_group *grp = &w->cfg->groups[g];

	return w->ifs[grp->members[m].dev].fam[f].usable &&
	       w->member_up[cfg_member_index(w->cfg, g, m)];
}

static bool any_probe(const struct config *c)
{
	for (size_t g = 0; g < c->n_groups; g++)
		if (c->groups[g].has_probe[0] || c->groups[g].has_probe[1])
			return true;
	return false;
}

/* Is device d a member of any group, of any probed group if probed? */
static bool dev_member(const struct config *c, size_t d, bool probed)
{
	for (size_t g = 0; g < c->n_groups; g++) {
		const struct cfg_group *grp = &c->groups[g];

		if (probed && !grp->has_probe[0] && !grp->has_probe[1])
			continue;
		for (size_t m = 0; m < grp->n_members; m++)
			if (grp->members[m].dev == d)
				return true;
	}
	return false;
}

/* Everything one world renders to, except the prefix routes. */
struct plan {
	struct nexthop_spec *members;	/* device nexthops */
	size_t n_members;
	struct nexthop_spec *groups;	/* resilient groups */
	size_t n_groups;
	uint32_t *group_nh;		/* [2 * g + f]: group nexthop id, 0 = blackhole */
	struct route_spec *small;	/* group defaults and the probe table */
	size_t n_small;
	struct rule_spec *rules;
	size_t n_rules;
};

static void gen_members(const struct world *w, struct plan *p)
{
	const struct config *c = w->cfg;

	for (size_t d = 0; d < c->n_devices; d++) {
		if (!dev_member(c, d, false))
			continue;
		for (int f = 0; f < 2; f++) {
			const struct ifrender *ir = &w->ifs[d].fam[f];
			struct nexthop_spec *n;

			if (!ir->usable)
				continue;
			n = &p->members[p->n_members++];
			n->id = cfg_member_nhid(c, d, f);
			n->family = families[f];
			n->proto = c->rt_proto;
			n->oif = ir->ifindex;
			n->has_gw = ir->has_gw;
			if (ir->has_gw)
				memcpy(n->gw, ir->gw, sizeof(n->gw));
		}
	}
}

static void gen_groups(const struct world *w, struct plan *p)
{
	const struct config *c = w->cfg;

	for (size_t g = 0; g < c->n_groups; g++) {
		const struct cfg_group *grp = &c->groups[g];

		for (int f = 0; f < 2; f++) {
			struct nexthop_spec *n = &p->groups[p->n_groups];

			for (size_t m = 0; m < grp->n_members && n->n_grp < MAX_NH_GROUP; m++) {
				if (!world_member_usable(w, g, m, f))
					continue;
				n->grp[n->n_grp].id = cfg_member_nhid(c, grp->members[m].dev, f);
				n->grp[n->n_grp].weight = grp->members[m].weight;
				n->n_grp++;
			}
			if (!n->n_grp)
				continue;

			n->id = cfg_group_nhid(c, g, f);
			n->family = families[f];	/* bookkeeping, sent as AF_UNSPEC */
			n->proto = c->rt_proto;
			n->buckets = grp->buckets;
			n->timer_idle = grp->timer_idle;
			n->timer_busy = grp->timer_busy;
			p->group_nh[2 * g + f] = n->id;
			p->n_groups++;
		}
	}
}

/* Unicast via the group's nexthop if it has one, blackhole otherwise. */
static void render(struct route_spec *r, const struct plan *p, size_t g, int f)
{
	r->nh_id = p->group_nh[2 * g + f];
	r->type = r->nh_id ? RTN_UNICAST : RTN_BLACKHOLE;
}

static void gen_small(const struct world *w, struct plan *p)
{
	const struct config *c = w->cfg;

	for (size_t g = 0; g < c->n_groups; g++) {
		if (!c->groups[g].fwmark)
			continue;
		for (int f = 0; f < 2; f++) {
			struct route_spec *r = &p->small[p->n_small++];

			r->family = families[f];
			r->table = cfg_group_table(c, g);
			r->proto = c->rt_proto;
			render(r, p, g, f);
		}
	}

	if (!any_probe(c))
		return;

	/* one route per link, probe health aside: dead members keep being probed */
	for (size_t d = 0; d < c->n_devices; d++) {
		if (!dev_member(c, d, true))
			continue;
		for (int f = 0; f < 2; f++) {
			const struct ifrender *ir = &w->ifs[d].fam[f];
			struct route_spec *r;

			if (!ir->usable)
				continue;
			r = &p->small[p->n_small++];
			r->family = families[f];
			r->type = RTN_UNICAST;
			r->table = cfg_probe_table(c);
			r->proto = c->rt_proto;
			r->metric = d + 1;
			r->oif = ir->ifindex;
			r->has_gw = ir->has_gw;
			if (ir->has_gw)
				memcpy(r->gw, ir->gw, sizeof(r->gw));
		}
	}
}

static void gen_rules(const struct config *c, struct plan *p)
{
	bool probe = any_probe(c);

	for (int f = 0; f < 2; f++) {
		for (size_t g = 0; g < c->n_groups; g++) {
			if (!c->groups[g].fwmark)
				continue;
			p->rules[p->n_rules++] = (struct rule_spec){
				.family = families[f],
				.proto = c->rt_proto,
				.prio = cfg_group_prio(c, g),
				.mark = c->groups[g].fwmark,
				.mask = c->fwmask,
				.table = cfg_group_table(c, g),
			};
		}
		if (probe)
			p->rules[p->n_rules++] = (struct rule_spec){
				.family = families[f],
				.proto = c->rt_proto,
				.prio = cfg_probe_prio(c),
				.mark = c->probe_mark,
				.mask = c->fwmask,
				.table = cfg_probe_table(c),
			};
		p->rules[p->n_rules++] = (struct rule_spec){
			.family = families[f],
			.proto = c->rt_proto,
			.prio = c->rule_prio,
			.mark = 0,
			.mask = c->fwmask,
			.table = c->table_id,
		};
	}
}

static void plan_free(struct plan *p)
{
	free(p->members);
	free(p->groups);
	free(p->group_nh);
	free(p->small);
	free(p->rules);
	memset(p, 0, sizeof(*p));
}

static int plan_build(const struct world *w, struct plan *p)
{
	const struct config *c = w->cfg;
	size_t nd = c ? c->n_devices : 0, ng = c ? c->n_groups : 0;

	memset(p, 0, sizeof(*p));
	p->members = calloc(2 * nd + 1, sizeof(*p->members));
	p->groups = calloc(2 * ng + 1, sizeof(*p->groups));
	p->group_nh = calloc(2 * ng + 1, sizeof(*p->group_nh));
	p->small = calloc(2 * (ng + nd) + 1, sizeof(*p->small));
	p->rules = calloc(2 * (ng + 2), sizeof(*p->rules));
	if (!p->members || !p->groups || !p->group_nh || !p->small || !p->rules) {
		plan_free(p);
		return -1;
	}

	if (c) {
		gen_members(w, p);
		gen_groups(w, p);
		gen_small(w, p);
		gen_rules(c, p);
	}
	return 0;
}

/* Entry i of c's family f list: addr, then plen right after it, then rule. */
static const uint8_t *prefix_at(const struct config *c, int f, size_t i, uint16_t *rule)
{
	if (f) {
		*rule = c->p6[i].rule;
		return c->p6[i].addr;
	}
	*rule = c->p4[i].rule;
	return c->p4[i].addr;
}

static size_t prefixes_n(const struct config *c, int f)
{
	return f ? c->n_p6 : c->n_p4;
}

static const void *prefixes_of(const struct config *c, int f)
{
	return f ? (const void *)c->p6 : (const void *)c->p4;
}

/* The one place a prefix route is built: entry i of w's family f list. */
static void prefix_route(const struct world *w, const struct plan *p, int f, size_t i,
                         struct route_spec *r)
{
	const struct config *c = w->cfg;
	const uint8_t *addr;
	uint16_t rule;

	memset(r, 0, sizeof(*r));
	r->family = families[f];
	addr = prefix_at(c, f, i, &rule);
	r->plen = addr[f ? 16 : 4];
	memcpy(r->dst, addr, f ? 16 : 4);
	r->table = c->table_id;
	r->proto = c->rt_proto;
	render(r, p, c->rule_group[rule], f);
}

static void prefix_send(struct nl *nl, enum nl_op op, const struct world *w,
                        const struct plan *p, int f, size_t i, struct sync_stats *st)
{
	struct route_spec r;

	prefix_route(w, p, f, i, &r);
	nl_route(nl, op, &r);
	if (op == NL_DEL)
		st->route_del++;
	else
		st->route_set++;
}

static bool route_key_eq(const struct route_spec *a, const struct route_spec *b)
{
	return a->family == b->family && a->plen == b->plen && a->table == b->table &&
	       a->metric == b->metric && !memcmp(a->dst, b->dst, sizeof(a->dst));
}

static bool route_eq(const struct route_spec *a, const struct route_spec *b)
{
	return route_key_eq(a, b) && a->proto == b->proto && a->type == b->type &&
	       a->nh_id == b->nh_id && a->oif == b->oif && a->has_gw == b->has_gw &&
	       !memcmp(a->gw, b->gw, sizeof(a->gw));
}

static bool rule_eq(const struct rule_spec *a, const struct rule_spec *b)
{
	return a->family == b->family && a->proto == b->proto && a->prio == b->prio &&
	       a->mark == b->mark && a->mask == b->mask && a->table == b->table;
}

static bool nh_eq(const struct nexthop_spec *a, const struct nexthop_spec *b)
{
	if (a->id != b->id || a->family != b->family || a->proto != b->proto ||
	    a->oif != b->oif || a->has_gw != b->has_gw || memcmp(a->gw, b->gw, sizeof(a->gw)) ||
	    a->n_grp != b->n_grp || a->buckets != b->buckets ||
	    a->timer_idle != b->timer_idle || a->timer_busy != b->timer_busy)
		return false;
	for (size_t i = 0; i < a->n_grp; i++)
		if (a->grp[i].id != b->grp[i].id || a->grp[i].weight != b->grp[i].weight)
			return false;
	return true;
}

/* Can the kernel turn a into b with a replace? */
static bool nh_replaceable(const struct nexthop_spec *a, const struct nexthop_spec *b)
{
	return !a->n_grp == !b->n_grp && a->family == b->family && a->proto == b->proto &&
	       a->buckets == b->buckets;
}

/* --- diffing --- */

/*
 * Nexthop ids deleted and created anew in this apply. The kernel drops
 * routes using a deleted nexthop and removes it from its groups, so those
 * have to be set again even if their rendering is unchanged.
 */
struct redo {
	uint32_t *ids;
	size_t n;
};

static bool redo_has(const struct redo *rd, uint32_t id)
{
	for (size_t i = 0; id && i < rd->n; i++)
		if (rd->ids[i] == id)
			return true;
	return false;
}

static bool redo_grp(const struct redo *rd, const struct nexthop_spec *n)
{
	for (size_t i = 0; i < n->n_grp; i++)
		if (redo_has(rd, n->grp[i].id))
			return true;
	return false;
}

static const struct nexthop_spec *nh_find(const struct plan *p, uint32_t id)
{
	for (size_t i = 0; i < p->n_members; i++)
		if (p->members[i].id == id)
			return &p->members[i];
	for (size_t i = 0; i < p->n_groups; i++)
		if (p->groups[i].id == id)
			return &p->groups[i];
	return NULL;
}

/* Set everything in n that old doesn't have identically. */
static void nexthops_set(struct nl *nl, const struct plan *old, const struct nexthop_spec *n,
                         size_t nn, struct redo *rd, struct sync_stats *st)
{
	for (size_t j = 0; j < nn; j++) {
		const struct nexthop_spec *o = nh_find(old, n[j].id);

		if (o && nh_eq(o, &n[j]) && !redo_grp(rd, &n[j]))
			continue;
		if (o && !nh_replaceable(o, &n[j])) {
			nl_nexthop(nl, NL_DEL, o);
			st->nh_del++;
			rd->ids[rd->n++] = o->id;
		}
		nl_nexthop(nl, NL_SET, &n[j]);
		st->nh_set++;
	}
}

/* Delete everything in o whose id is gone from new. */
static void nexthops_del(struct nl *nl, const struct nexthop_spec *o, size_t no,
                         const struct plan *new, struct sync_stats *st)
{
	for (size_t i = 0; i < no; i++) {
		if (nh_find(new, o[i].id))
			continue;
		nl_nexthop(nl, NL_DEL, &o[i]);
		st->nh_del++;
	}
}

/* Set everything in new that old doesn't have identically. */
static void small_routes_set(struct nl *nl, const struct route_spec *o, size_t no,
                             const struct route_spec *n, size_t nn, const struct redo *rd,
                             struct sync_stats *st)
{
	for (size_t j = 0; j < nn; j++) {
		size_t i;

		for (i = 0; i < no; i++)
			if (route_eq(&o[i], &n[j]))
				break;
		if (i == no || redo_has(rd, n[j].nh_id)) {
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

/*
 * Old and new hold the very same family f list (the same config, or one
 * shared across a reload): same keys and rule indexes, nothing to merge or
 * delete. A rule may still map to another group.
 */
static bool prefixes_shared(const struct world *old, const struct world *new, int f)
{
	const struct config *oc = old->cfg, *nc = new->cfg;

	return prefixes_comparable(old, new) && prefixes_of(oc, f) == prefixes_of(nc, f) &&
	       prefixes_n(oc, f) == prefixes_n(nc, f) && oc->n_rules == nc->n_rules;
}

/* One family's prefixes, old and new, as prefix_changed() sees them. */
struct prefix_diff {
	const struct config *oc, *nc;
	const struct plan *opl, *npl;
	const struct redo *rd;
	int f;
};

/*
 * A prefix route depends on nothing but its group's nexthop (0 = blackhole),
 * given comparable table and tag: it changed if that nexthop id did, or if
 * the nexthop was deleted and created anew, taking the route with it.
 */
static bool prefix_changed(const struct prefix_diff *d, uint16_t orule, uint16_t nrule)
{
	uint32_t onh = d->opl->group_nh[2 * d->oc->rule_group[orule] + d->f];
	uint32_t nnh = d->npl->group_nh[2 * d->nc->rule_group[nrule] + d->f];

	return onh != nnh || redo_has(d->rd, nnh);
}

/* Shared lists: set what changed, after checking per rule whether anything did. */
static void prefixes_set_shared(struct nl *nl, const struct prefix_diff *d,
                                const struct world *new, struct sync_stats *st)
{
	size_t r, n = prefixes_n(d->nc, d->f);
	uint16_t rule;

	for (r = 0; r < d->nc->n_rules; r++)
		if (prefix_changed(d, r, r))
			break;
	if (r == d->nc->n_rules)
		return;

	for (size_t i = 0; i < n; i++) {
		prefix_at(d->nc, d->f, i, &rule);
		if (prefix_changed(d, rule, rule))
			prefix_send(nl, NL_SET, new, d->npl, d->f, i, st);
	}
}

/* Orders entry i of a and entry j of b, both family f, by (addr, plen). */
static int prefix_cmp(const struct config *a, size_t i, const struct config *b, size_t j, int f,
                      uint16_t *ra, uint16_t *rb)
{
	return memcmp(prefix_at(a, f, i, ra), prefix_at(b, f, j, rb), f ? 17 : 5);
}

static void prefixes_set(struct nl *nl, const struct world *old, const struct plan *opl,
                         const struct world *new, const struct plan *npl,
                         const struct redo *rd, struct sync_stats *st)
{
	const struct config *oc = old->cfg, *nc = new->cfg;
	bool comparable = prefixes_comparable(old, new);

	if (!nc)
		return;

	/* v4 then v6: the order of one (family, addr, plen) sorted walk */
	for (int f = 0; f < 2; f++) {
		struct prefix_diff d = { oc, nc, opl, npl, rd, f };
		size_t no = comparable ? prefixes_n(oc, f) : 0, nn = prefixes_n(nc, f);
		size_t i = 0, j = 0;
		uint16_t ro = 0, rn = 0;

		if (prefixes_shared(old, new, f)) {
			prefixes_set_shared(nl, &d, new, st);
			continue;
		}

		while (j < nn) {
			int cmp = i < no ? prefix_cmp(oc, i, nc, j, f, &ro, &rn) : 1;

			if (cmp < 0) {
				i++;
				continue;
			}
			if (cmp > 0 || prefix_changed(&d, ro, rn))
				prefix_send(nl, NL_SET, new, npl, f, j, st);
			i += !cmp;
			j++;
		}
	}
}

static void prefixes_del(struct nl *nl, const struct world *old, const struct plan *opl,
                         const struct world *new, struct sync_stats *st)
{
	const struct config *oc = old->cfg, *nc = new->cfg;
	bool comparable = prefixes_comparable(old, new);

	if (!oc)
		return;

	for (int f = 0; f < 2; f++) {
		size_t no = prefixes_n(oc, f), nn = comparable ? prefixes_n(nc, f) : 0;
		size_t i = 0, j = 0;
		uint16_t ro, rn;

		if (prefixes_shared(old, new, f))
			continue;

		while (i < no) {
			int cmp = j < nn ? prefix_cmp(oc, i, nc, j, f, &ro, &rn) : -1;

			if (cmp < 0)
				prefix_send(nl, NL_DEL, old, opl, f, i, st);
			i += cmp <= 0;
			j += cmp >= 0;
		}
	}
}

void sync_apply(struct nl *nl, const struct world *old, const struct world *new,
		struct sync_stats *st)
{
	struct plan po, pn;
	struct redo rd = {};

	memset(st, 0, sizeof(*st));

	if (plan_build(old, &po)) {
		err("out of memory");
		st->errors++;
		return;
	}
	if (plan_build(new, &pn)) {
		err("out of memory");
		st->errors++;
		plan_free(&po);
		return;
	}
	rd.ids = calloc(po.n_members + po.n_groups + 1, sizeof(*rd.ids));
	if (!rd.ids) {
		err("out of memory");
		st->errors++;
		goto out;
	}

	nl_batch_begin(nl);

	/*
	 * make before break: nexthops bottom up, fill tables, then point rules
	 * at them, then clean up top down
	 */
	nexthops_set(nl, &po, pn.members, pn.n_members, &rd, st);
	nexthops_set(nl, &po, pn.groups, pn.n_groups, &rd, st);
	small_routes_set(nl, po.small, po.n_small, pn.small, pn.n_small, &rd, st);
	prefixes_set(nl, old, &po, new, &pn, &rd, st);
	rules_diff(nl, NL_SET, pn.rules, pn.n_rules, po.rules, po.n_rules, &st->rule_add);
	rules_diff(nl, NL_DEL, po.rules, po.n_rules, pn.rules, pn.n_rules, &st->rule_del);
	small_routes_del(nl, po.small, po.n_small, pn.small, pn.n_small, st);
	prefixes_del(nl, old, &po, new, st);
	nexthops_del(nl, po.groups, po.n_groups, &pn, st);
	nexthops_del(nl, po.members, po.n_members, &pn, st);

	st->errors = nl_batch_end(nl);

out:
	free(rd.ids);
	plan_free(&po);
	plan_free(&pn);
}

/* --- flush --- */

/*
 * Routes are deleted in chunks of this many: a dump collects at most a
 * chunk, the rest of it is drained and dumped again after the deletes.
 */
#define FLUSH_CHUNK 1024

/* What a route delete matches on; nl_route ignores the rest for NL_DEL. */
struct flush_route {
	uint8_t family;
	uint8_t plen;
	uint32_t table;
	uint32_t metric;
	uint8_t dst[16];
};

struct flush_nh {
	uint32_t id;
	bool group;
};

struct flush_ctx {
	uint8_t proto;
	struct rule_spec *rules;
	size_t n_rules, cap_rules;
	struct flush_nh *nhs;
	size_t n_nhs, cap_nhs;
	struct flush_route *routes;	/* FLUSH_CHUNK */
	size_t n_routes;
	size_t n_seen;		/* routes in this dump, kept or not */
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
	struct flush_route *r;

	if (rtm->rtm_protocol != fc->proto ||
	    (rtm->rtm_family != AF_INET && rtm->rtm_family != AF_INET6))
		return MNL_CB_OK;
	/* past a full chunk, only count: the dump has to be read to its end */
	if (fc->n_seen++ >= FLUSH_CHUNK)
		return MNL_CB_OK;

	r = &fc->routes[fc->n_routes++];
	memset(r, 0, sizeof(*r));
	mnl_attr_parse(nlh, sizeof(*rtm), attrs_cb, &t);
	r->family = rtm->rtm_family;
	r->plen = rtm->rtm_dst_len;
	r->table = t.tb[RTA_TABLE] ? mnl_attr_get_u32(t.tb[RTA_TABLE]) : rtm->rtm_table;
	r->metric = t.tb[RTA_PRIORITY] ? mnl_attr_get_u32(t.tb[RTA_PRIORITY]) : 0;
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

static int flush_nh_cb(const struct nlmsghdr *nlh, void *data)
{
	struct flush_ctx *fc = data;
	const struct nhmsg *nhm = mnl_nlmsg_get_payload(nlh);
	struct attrs t = {};
	struct flush_nh *nn;

	if (nhm->nh_protocol != fc->proto)
		return MNL_CB_OK;
	mnl_attr_parse(nlh, sizeof(*nhm), attrs_cb, &t);
	if (!t.tb[NHA_ID])
		return MNL_CB_OK;

	nn = grow(fc->nhs, &fc->cap_nhs, fc->n_nhs, sizeof(*nn));
	if (!nn) {
		fc->oom = true;
		return MNL_CB_ERROR;
	}
	fc->nhs = nn;
	fc->nhs[fc->n_nhs++] = (struct flush_nh){
		.id = mnl_attr_get_u32(t.tb[NHA_ID]),
		.group = !!t.tb[NHA_GROUP],
	};
	return MNL_CB_OK;
}

static void flush_free(struct flush_ctx *fc)
{
	free(fc->routes);
	free(fc->rules);
	free(fc->nhs);
}

/* Delete fc's nexthops that are groups, or that aren't. */
static void flush_nexthops(struct nl *nl, const struct flush_ctx *fc, bool groups)
{
	for (size_t i = 0; i < fc->n_nhs; i++)
		if (fc->nhs[i].group == groups)
			nl_nexthop(nl, NL_DEL, &(struct nexthop_spec){ .id = fc->nhs[i].id });
}

/*
 * Delete what's left of the routes with fc's proto, a chunk per dump, and
 * count them. Stops when a dump finds no fewer than the one before: those
 * routes can't be deleted by key (a v6 source prefix, say).
 */
static int flush_routes(struct nl *nl, struct flush_ctx *fc, size_t *n_deleted,
                        unsigned *errors)
{
	char buf[128] __attribute__((aligned(4)));
	size_t last = SIZE_MAX;

	for (;;) {
		struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
		struct rtmsg *rtm;
		int ret;

		/* with NETLINK_GET_STRICT_CHK the kernel filters by protocol already */
		nlh->nlmsg_type = RTM_GETROUTE;
		rtm = mnl_nlmsg_put_extra_header(nlh, sizeof(*rtm));
		rtm->rtm_family = AF_UNSPEC;
		rtm->rtm_protocol = fc->proto;
		fc->n_routes = fc->n_seen = 0;
		ret = nl_dump(nl, nlh, flush_route_cb, fc);
		if (ret)
			return ret;
		if (!fc->n_seen)
			return 0;
		if (fc->n_seen >= last) {
			warn("flush: %zu routes with proto %u can't be deleted", fc->n_seen, fc->proto);
			(*errors)++;
			return 0;
		}
		last = fc->n_seen;

		nl_batch_begin(nl);
		for (size_t i = 0; i < fc->n_routes; i++) {
			const struct flush_route *k = &fc->routes[i];
			struct route_spec r = {
				.family = k->family,
				.plen = k->plen,
				.proto = fc->proto,
				.table = k->table,
				.metric = k->metric,
			};

			memcpy(r.dst, k->dst, sizeof(r.dst));
			nl_route(nl, NL_DEL, &r);
		}
		*errors += nl_batch_end(nl);
		*n_deleted += fc->n_routes;
		if (fc->n_seen == fc->n_routes)
			return 0;
	}
}

/*
 * Rules first, then the groups: the kernel deletes every route on a deleted
 * nexthop by itself, which is nearly all of them, much faster than route
 * by route. What's left are blackholes and the probe routes, deleted in
 * chunks so memory stays bounded however many there are. Then the members,
 * no longer in any group, and any route still on them.
 */
int sync_flush(struct nl *nl, uint8_t proto)
{
	char buf[128] __attribute__((aligned(4)));
	struct flush_ctx fc = { .proto = proto };
	struct nlmsghdr *nlh;
	struct fib_rule_hdr *frh;
	size_t n_routes = 0;
	unsigned errors;
	int ret;

	fc.routes = malloc(FLUSH_CHUNK * sizeof(*fc.routes));
	if (!fc.routes) {
		fc.oom = true;
		ret = -ENOMEM;
		goto fail;
	}

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = RTM_GETRULE;
	frh = mnl_nlmsg_put_extra_header(nlh, sizeof(*frh));
	frh->family = AF_UNSPEC;
	ret = nl_dump(nl, nlh, flush_rule_cb, &fc);
	if (ret)
		goto fail;

	/* nothing to flush on kernels without nexthop objects */
	ret = nl_dump_nexthops(nl, flush_nh_cb, &fc);
	if (ret && ret != -EOPNOTSUPP)
		goto fail;

	nl_batch_begin(nl);
	for (size_t i = 0; i < fc.n_rules; i++)
		nl_rule(nl, NL_DEL, &fc.rules[i]);
	flush_nexthops(nl, &fc, true);
	errors = nl_batch_end(nl);

	ret = flush_routes(nl, &fc, &n_routes, &errors);
	if (ret)
		goto fail;

	nl_batch_begin(nl);
	flush_nexthops(nl, &fc, false);
	errors += nl_batch_end(nl);

	if (fc.n_rules || fc.n_nhs || n_routes)
		info("flush: removed %zu rules, %zu nexthops and the routes on them, "
		     "%zu other routes with proto %u%s", fc.n_rules, fc.n_nhs, n_routes, proto,
		     errors ? " (with errors)" : "");

	flush_free(&fc);
	return errors ? -EIO : 0;

fail:
	err("flush: dump failed: %s", fc.oom ? "out of memory" : strerror(-ret));
	flush_free(&fc);
	return ret;
}

/* --- nexthop id ownership --- */

struct nhid_ctx {
	const struct config *cfg;
	uint32_t id;		/* first foreign id found, 0 = none */
	uint8_t proto;
};

static int nhid_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nhid_ctx *nc = data;
	const struct nhmsg *nhm = mnl_nlmsg_get_payload(nlh);
	struct attrs t = {};
	uint32_t id;

	if (nc->id || nhm->nh_protocol == nc->cfg->rt_proto)
		return MNL_CB_OK;
	mnl_attr_parse(nlh, sizeof(*nhm), attrs_cb, &t);
	if (!t.tb[NHA_ID])
		return MNL_CB_OK;
	id = mnl_attr_get_u32(t.tb[NHA_ID]);
	if (id > nc->cfg->nexthop_id && id <= cfg_nhid_end(nc->cfg)) {
		nc->id = id;
		nc->proto = nhm->nh_protocol;
	}
	return MNL_CB_OK;
}

int sync_check_nhids(struct nl *nl, const struct config *cfg)
{
	struct nhid_ctx nc = { .cfg = cfg };
	int ret;

	ret = nl_dump_nexthops(nl, nhid_cb, &nc);
	if (ret == -EOPNOTSUPP) {
		if (!cfg->n_groups)
			return 0;
		err("kernel lacks nexthop objects (need >= 5.13)");
		return -1;
	}
	if (ret) {
		err("nexthop dump failed: %s", strerror(-ret));
		return -1;
	}
	if (nc.id) {
		err("nexthop id %u has proto %u, not %u: nexthop_id range %u..%llu "
		    "must be routebot's alone", nc.id, nc.proto, cfg->rt_proto,
		    cfg->nexthop_id + 1, (unsigned long long)cfg_nhid_end(cfg));
		return -1;
	}
	return 0;
}
