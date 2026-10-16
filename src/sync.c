#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <linux/fib_rules.h>
#include <linux/nexthop.h>
#include <linux/rtnetlink.h>

#include "kstate.h"
#include "log.h"
#include "sync.h"

static const int families[2] = { AF_INET, AF_INET6 };

/* the highest metric there is, v4 and v6: behind any other route */
#define METRIC_LAST UINT32_MAX

/* what the kernel makes of a v6 route without a metric */
#define METRIC_V6 1024

static const char *fam_name(int f)
{
	return f ? "v6" : "v4";
}

/* Make room for n elements of size bytes in *p (a pointer to a pointer). */
static int reserve(void *p, size_t *cap, size_t n, size_t size)
{
	void **pp = p, *np;
	size_t c = *cap ? *cap : 8;

	if (n <= *cap)
		return 0;
	while (c < n)
		c *= 2;
	np = realloc(*pp, c * size);
	if (!np)
		return -1;
	*pp = np;
	*cap = c;
	return 0;
}

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

/* Nexthop ids, few: linear. */
struct idset {
	uint32_t *ids;
	size_t n, cap;
};

static bool idset_has(const struct idset *s, uint32_t id)
{
	for (size_t i = 0; id && i < s->n; i++)
		if (s->ids[i] == id)
			return true;
	return false;
}

static int idset_add(struct idset *s, uint32_t id)
{
	if (idset_has(s, id))
		return 0;
	if (reserve(&s->ids, &s->cap, s->n + 1, sizeof(*s->ids)))
		return -1;
	s->ids[s->n++] = id;
	return 0;
}

/*
 * Everything one world renders to, except the prefix routes: those depend
 * on the config alone, each points at its group's nexthop for good.
 */
struct plan {
	struct nexthop_spec *members;	/* the blackholes, device nexthops */
	size_t n_members, cap_members;
	struct nexthop_spec *groups;	/* resilient groups, every group and family */
	size_t n_groups, cap_groups;
	struct route_spec *small;	/* group table defaults and the probe table */
	size_t n_small, cap_small;
	struct rule_spec *rules;
	size_t n_rules, cap_rules;
};

static void gen_members(const struct world *w, struct plan *p)
{
	const struct config *c = w->cfg;

	/* what a group holds while none of its members is usable */
	for (int f = 0; f < 2 && c->n_groups; f++)
		p->members[p->n_members++] = (struct nexthop_spec){
			.id = cfg_blackhole_nhid(c, f),
			.family = families[f],
			.proto = c->rt_proto,
			.blackhole = true,
		};

	for (size_t d = 0; d < c->n_devices; d++) {
		if (!dev_member(c, d, false))
			continue;
		for (int f = 0; f < 2; f++) {
			const struct ifrender *ir = &w->ifs[d].fam[f];
			struct nexthop_spec *n;

			if (!ir->usable)
				continue;
			n = &p->members[p->n_members++];
			memset(n, 0, sizeof(*n));
			n->id = cfg_member_nhid(c, d, f);
			n->family = families[f];
			n->proto = c->rt_proto;
			n->oif = ir->ifindex;
			n->has_gw = ir->has_gw;
			if (ir->has_gw)
				memcpy(n->gw, ir->gw, family_alen(families[f]));
		}
	}
}

/*
 * Every group exists, per family, with its usable members or else the
 * blackhole: its routes never change for its members' sake.
 */
static void gen_groups(const struct world *w, struct plan *p)
{
	const struct config *c = w->cfg;

	for (size_t g = 0; g < c->n_groups; g++) {
		const struct cfg_group *grp = &c->groups[g];

		for (int f = 0; f < 2; f++) {
			struct nexthop_spec *n = &p->groups[p->n_groups++];

			memset(n, 0, sizeof(*n));
			for (size_t m = 0; m < grp->n_members && n->n_grp < MAX_NH_GROUP; m++) {
				if (!world_member_usable(w, g, m, f))
					continue;
				n->grp[n->n_grp].id = cfg_member_nhid(c, grp->members[m].dev, f);
				n->grp[n->n_grp].weight = grp->members[m].weight;
				n->n_grp++;
			}
			if (!n->n_grp)
				n->grp[n->n_grp++] = (struct nh_grp_entry){ cfg_blackhole_nhid(c, f), 1 };

			n->id = cfg_group_nhid(c, g, f);
			n->family = families[f];	/* bookkeeping, sent as AF_UNSPEC */
			n->proto = c->rt_proto;
			n->buckets = grp->buckets;
			n->timer_idle = grp->timer_idle;
			n->timer_busy = grp->timer_busy;
		}
	}
}

/*
 * Every group's table holds a default route through the group, fwmark or
 * not: the group's witness. The kernel deletes it along with the group and
 * every route on it, so while it's there, so are the group's prefix routes.
 * Behind it, a blackhole: should the group go, marked traffic is dropped
 * rather than falling through to the next rule.
 */
static void gen_small(const struct world *w, struct plan *p)
{
	const struct config *c = w->cfg;

	for (size_t g = 0; g < c->n_groups; g++) {
		for (int f = 0; f < 2; f++) {
			p->small[p->n_small++] = (struct route_spec){
				.family = families[f],
				.type = RTN_UNICAST,
				.proto = c->rt_proto,
				.table = cfg_group_table(c, g),
				.nh_id = cfg_group_nhid(c, g, f),
			};
			p->small[p->n_small++] = (struct route_spec){
				.family = families[f],
				.type = RTN_BLACKHOLE,
				.proto = c->rt_proto,
				.table = cfg_group_table(c, g),
				.metric = METRIC_LAST,
			};
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
			memset(r, 0, sizeof(*r));
			r->family = families[f];
			r->type = RTN_UNICAST;
			r->table = cfg_probe_table(c);
			r->proto = c->rt_proto;
			r->metric = d + 1;
			r->oif = ir->ifindex;
			r->has_gw = ir->has_gw;
			if (ir->has_gw)
				memcpy(r->gw, ir->gw, family_alen(families[f]));
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
	free(p->small);
	free(p->rules);
	memset(p, 0, sizeof(*p));
}

/* Render w into p, in p's buffers: no allocation once they are big enough. */
static int plan_build(const struct world *w, struct plan *p)
{
	const struct config *c = w->cfg;
	size_t nm, ns, ng = c ? c->n_groups : 0;

	p->n_members = p->n_groups = p->n_small = p->n_rules = 0;
	if (!c)
		return 0;

	nm = ng ? 2 : 0;
	ns = 4 * ng;
	for (size_t d = 0; d < c->n_devices; d++) {
		nm += dev_member(c, d, false) ? 2 : 0;
		ns += dev_member(c, d, true) ? 2 : 0;
	}
	if (reserve(&p->members, &p->cap_members, nm, sizeof(*p->members)) ||
	    reserve(&p->groups, &p->cap_groups, 2 * ng, sizeof(*p->groups)) ||
	    reserve(&p->small, &p->cap_small, ns, sizeof(*p->small)) ||
	    reserve(&p->rules, &p->cap_rules, 2 * (ng + 2), sizeof(*p->rules)))
		return -1;

	gen_members(w, p);
	gen_groups(w, p);
	gen_small(w, p);
	gen_rules(c, p);
	return 0;
}

static const struct nexthop_spec *plan_nh(const struct plan *p, uint32_t id)
{
	for (size_t i = 0; i < p->n_members; i++)
		if (p->members[i].id == id)
			return &p->members[i];
	for (size_t i = 0; i < p->n_groups; i++)
		if (p->groups[i].id == id)
			return &p->groups[i];
	return NULL;
}

/* --- what's wanted against what the kernel holds --- */

static uint32_t metric_of(uint8_t family, uint32_t metric)
{
	return family == AF_INET6 && !metric ? METRIC_V6 : metric;
}

/* The same key: what a replace or a delete of a matches. */
static bool route_key_eq(const struct route_spec *a, const struct kroute *k)
{
	const struct route_spec *b = &k->r;

	return a->family == b->family && a->plen == b->plen && a->table == b->table &&
	       metric_of(a->family, a->metric) == metric_of(b->family, b->metric) &&
	       !k->tos && !k->src_len && !memcmp(a->dst, b->dst, family_alen(a->family));
}

/*
 * The same route. One on a nexthop is reported as a blackhole while its
 * group holds the blackhole nexthop: only the nexthop counts then.
 */
static bool route_eq(const struct route_spec *a, const struct kroute *k)
{
	const struct route_spec *b = &k->r;

	if (!route_key_eq(a, k) || a->proto != b->proto || a->nh_id != b->nh_id)
		return false;
	if (a->nh_id)
		return true;
	return a->type == b->type && !k->multipath && a->oif == b->oif &&
	       a->has_gw == b->has_gw &&
	       (!a->has_gw || !memcmp(a->gw, b->gw, family_alen(a->family)));
}

static bool rule_eq(const struct rule_spec *a, const struct rule_spec *b)
{
	return a->family == b->family && a->proto == b->proto && a->prio == b->prio &&
	       a->mark == b->mark && a->mask == b->mask && a->table == b->table;
}

/* Kernel nexthop k is wanted nexthop d. */
static bool nh_eq(const struct nexthop_spec *k, const struct nexthop_spec *d)
{
	if (k->proto != d->proto || k->blackhole != d->blackhole || k->n_grp != d->n_grp)
		return false;
	if (d->n_grp) {
		if (k->buckets != d->buckets || k->timer_idle != d->timer_idle ||
		    k->timer_busy != d->timer_busy)
			return false;
		for (size_t i = 0; i < d->n_grp; i++)
			if (k->grp[i].id != d->grp[i].id || k->grp[i].weight != d->grp[i].weight)
				return false;
		return true;
	}
	return k->family == d->family && k->oif == d->oif && k->has_gw == d->has_gw &&
	       (!d->has_gw || !memcmp(k->gw, d->gw, family_alen(d->family)));
}

/*
 * Can the kernel turn k into d with a replace? Not a group into a single
 * nexthop or back, not a group's bucket count (nor a group that isn't
 * resilient), not a family or a protocol.
 */
static bool nh_replaceable(const struct nexthop_spec *k, const struct nexthop_spec *d)
{
	if (!k->n_grp != !d->n_grp || k->proto != d->proto || k->blackhole != d->blackhole)
		return false;
	if (d->n_grp)
		return k->buckets && k->buckets == d->buckets;
	return k->family == d->family;
}

/*
 * Who an id stands for in c's layout: a group (by name) or a device (by
 * spec) in family f, or the blackhole of family f. An id of two configs is
 * the same logical object only if it stands for the same in both.
 */
struct owner {
	char kind;		/* 'b', 'd', 'g' */
	int f;
	const char *name;
};

static bool owner_of(const struct config *c, uint32_t id, struct owner *o)
{
	uint32_t off;
	size_t i;

	if (!c || id < c->nexthop_id)
		return false;
	off = id - c->nexthop_id;
	o->f = off & 1;
	if (off < 2) {
		o->kind = 'b';
		o->name = "";
		return c->n_groups;
	}
	if ((off - 2) % 4 < 2) {
		i = (off - 2) / 4;
		o->kind = 'd';
		o->name = i < c->n_devices ? c->devices[i].spec : NULL;
	} else {
		i = (off - 4) / 4;
		o->kind = 'g';
		o->name = i < c->n_groups ? c->groups[i].name : NULL;
	}
	return o->name;
}

/* 1: id has the same owner in a and b, 0: another one, -1: a doesn't say. */
static int same_owner(const struct config *a, const struct config *b, uint32_t id)
{
	struct owner oa, ob;

	if (!owner_of(a, id, &oa))
		return -1;
	return owner_of(b, id, &ob) && oa.kind == ob.kind && oa.f == ob.f &&
	       !strcmp(oa.name, ob.name);
}

/* --- the sync context --- */

struct sync {
	struct kstate k;
	struct plan want, prev;
	struct idset doomed;		/* kernel nexthops deleted and made anew */
	struct idset refused;		/* members the kernel won't take: left out */
	struct idset reset;		/* groups whose prefix routes are set again */
	uint32_t *tables;		/* the observed tables */
	size_t cap_tables;
	uint8_t *bits;			/* full reconcile: per prefix, 2 bits */
	size_t cap_bits;
};

struct sync *sync_new(void)
{
	return calloc(1, sizeof(struct sync));
}

void sync_free(struct sync *s)
{
	if (!s)
		return;
	kstate_free(&s->k);
	plan_free(&s->want);
	plan_free(&s->prev);
	free(s->doomed.ids);
	free(s->refused.ids);
	free(s->reset.ids);
	free(s->tables);
	free(s->bits);
	free(s);
}

/* One sync: what's wanted, what was, what the kernel holds. */
struct diff {
	struct sync *s;
	struct nl *nl;
	const struct config *pc, *wc;	/* prev's config (or NULL), want's */
	const struct kstate *k;
	const struct plan *pw, *pp;	/* want, prev rendered */
	uint8_t protos[2];		/* routebot's: want's rt_proto, prev's */
	size_t n_protos;
	size_t n_tables;		/* in s->tables */
	enum sync_mode mode;
	struct sync_stats *st;
};

static bool is_ours(const struct diff *d, uint8_t proto)
{
	for (size_t i = 0; i < d->n_protos; i++)
		if (d->protos[i] == proto)
			return true;
	return false;
}

static const struct nexthop_spec *k_nh(const struct diff *d, uint32_t id)
{
	for (size_t i = 0; i < d->k->n_nh; i++)
		if (d->k->nh[i].id == id)
			return &d->k->nh[i];
	return NULL;
}

static bool k_has_route(const struct diff *d, const struct route_spec *r)
{
	for (size_t i = 0; i < d->k->n_routes; i++)
		if (route_eq(r, &d->k->routes[i]))
			return true;
	return false;
}

static bool rule_in(const struct rule_spec *rs, size_t n, const struct rule_spec *r)
{
	for (size_t i = 0; i < n; i++)
		if (rule_eq(&rs[i], r))
			return true;
	return false;
}

/* Whether p has a small route eq() to k: route_eq() or route_key_eq(). */
static bool small_has(const struct plan *p, const struct kroute *k,
                      bool (*eq)(const struct route_spec *, const struct kroute *))
{
	for (size_t i = 0; i < p->n_small; i++)
		if (eq(&p->small[i], k))
			return true;
	return false;
}

static bool observed_table(const struct diff *d, uint32_t t)
{
	for (size_t i = 0; i < d->n_tables; i++)
		if (d->s->tables[i] == t)
			return true;
	return false;
}

/*
 * The probe table and every group table of c, not a prefix table (as
 * across a reload that moves table_id): never dumped on the way.
 */
static int add_tables(struct diff *d, const struct config *c)
{
	struct sync *s = d->s;

	for (size_t i = 0; c && i <= c->n_groups; i++) {
		uint32_t t = c->table_id + 1 + i;

		if (t == d->wc->table_id || (d->pc && t == d->pc->table_id) ||
		    observed_table(d, t))
			continue;
		if (reserve(&s->tables, &s->cap_tables, d->n_tables + 1, sizeof(*s->tables)))
			return -1;
		s->tables[d->n_tables++] = t;
	}
	return 0;
}

static uint32_t nhid_end(const struct config *c)
{
	return cfg_nhid_end(c) > UINT32_MAX ? UINT32_MAX : cfg_nhid_end(c);
}

/* Dump routebot's small objects, and nexthops in its id ranges. */
static int observe(struct diff *d)
{
	struct kscope sc = { .n_protos = d->n_protos };

	memcpy(sc.protos, d->protos, sizeof(sc.protos));
	sc.id_lo[sc.n_ranges] = cfg_nhid_start(d->wc);
	sc.id_hi[sc.n_ranges++] = nhid_end(d->wc);
	if (d->pc) {
		sc.id_lo[sc.n_ranges] = cfg_nhid_start(d->pc);
		sc.id_hi[sc.n_ranges++] = nhid_end(d->pc);
	}
	d->n_tables = 0;
	if (add_tables(d, d->wc) || add_tables(d, d->pc))
		return -ENOMEM;
	sc.tables = d->s->tables;
	sc.n_tables = d->n_tables;
	return kstate_observe(d->nl, &sc, &d->s->k);
}

/* A nexthop in want's id range that isn't routebot's: hands off, nothing can be done. */
static const struct nexthop_spec *foreign_nh(const struct diff *d)
{
	for (size_t i = 0; i < d->k->n_nh; i++) {
		const struct nexthop_spec *kn = &d->k->nh[i];

		if (!is_ours(d, kn->proto) && kn->id >= cfg_nhid_start(d->wc) &&
		    kn->id <= cfg_nhid_end(d->wc))
			return kn;
	}
	return NULL;
}

/*
 * Leave the refused members out of want: out of their groups (a group
 * left with none holds the blackhole), along with their probe routes,
 * which the kernel would refuse as well.
 */
static void plan_drop(struct plan *p, const struct config *c, const struct idset *refused)
{
	size_t out = 0;

	for (size_t i = 0; i < p->n_members; i++)
		if (!idset_has(refused, p->members[i].id))
			p->members[out++] = p->members[i];
	p->n_members = out;

	out = 0;
	for (size_t i = 0; i < p->n_small; i++) {
		const struct route_spec *r = &p->small[i];

		if (r->table != cfg_probe_table(c) ||
		    !idset_has(refused, cfg_member_nhid(c, r->metric - 1, r->family == AF_INET6)))
			p->small[out++] = *r;
	}
	p->n_small = out;

	for (size_t i = 0; i < p->n_groups; i++) {
		struct nexthop_spec *n = &p->groups[i];
		uint16_t w = 0;

		for (uint16_t j = 0; j < n->n_grp; j++)
			if (!idset_has(refused, n->grp[j].id))
				n->grp[w++] = n->grp[j];
		if (!w)
			n->grp[w++] = (struct nh_grp_entry){
				cfg_blackhole_nhid(c, n->family == AF_INET6), 1 };
		n->n_grp = w;
	}
}

/*
 * End a batch. A member nexthop the kernel refuses (its device has IPv6
 * disabled, a gateway isn't on-link) is a known outcome: it isn't there,
 * it's left out of the groups set after, and the next sync tries again.
 * Anything else leaves the kernel uncertain. Returns the uncertain ones.
 */
static unsigned batch_end(struct diff *d)
{
	struct nl *nl = d->nl;
	unsigned errors = nl_batch_end(nl), known = 0;

	d->st->errors += errors;
	for (unsigned i = 0; i < nl->n_refused; i++) {
		const struct nl_refused *r = &nl->refused[i];
		const struct nexthop_spec *n = plan_nh(d->pw, r->id);
		struct owner o;

		if (r->type == RTM_NEWNEXTHOP && r->error != ENOENT && n && !n->n_grp &&
		    !n->blackhole && owner_of(d->wc, r->id, &o)) {
			warn("%s: kernel refused its %s nexthop, left out", o.name, fam_name(o.f));
			if (!idset_add(&d->s->refused, r->id))
				known++;
		}
	}
	return errors - (known < errors ? known : errors);
}

/* --- prefix routes --- */

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

/* The nexthop of rule's group in family f. */
static uint32_t rule_nh(const struct config *c, uint16_t rule, int f)
{
	return cfg_group_nhid(c, c->rule_group[rule], f);
}

/* The nexthop of entry i of c's family f list. */
static uint32_t prefix_nh(const struct config *c, int f, size_t i)
{
	uint16_t rule;

	prefix_at(c, f, i, &rule);
	return rule_nh(c, rule, f);
}

/* The one place a prefix route is built: entry i of c's family f list. */
static void prefix_route(const struct config *c, int f, size_t i, struct route_spec *r)
{
	const uint8_t *addr;
	uint16_t rule;

	memset(r, 0, sizeof(*r));
	r->family = families[f];
	addr = prefix_at(c, f, i, &rule);
	r->plen = addr[f ? 16 : 4];
	memcpy(r->dst, addr, f ? 16 : 4);
	r->table = c->table_id;
	r->proto = c->rt_proto;
	r->type = RTN_UNICAST;
	r->nh_id = rule_nh(c, rule, f);
}

static void prefix_send(const struct diff *d, enum nl_op op, const struct config *c, int f,
                        size_t i)
{
	struct route_spec r;

	prefix_route(c, f, i, &r);
	nl_route(d->nl, op, &r);
	if (op == NL_DEL)
		d->st->route_del++;
	else
		d->st->route_set++;
}

/* Entry i of c's family f list, off its nexthop: a plain blackhole. */
static void prefix_detach(const struct diff *d, const struct config *c, int f, size_t i)
{
	struct route_spec r;

	prefix_route(c, f, i, &r);
	r.type = RTN_BLACKHOLE;
	r.nh_id = 0;
	nl_route(d->nl, NL_SET, &r);
	d->st->route_set++;
}

/* Index of (addr, plen) in c's family f list, -1 if not there. */
static long prefix_find(const struct config *c, int f, const uint8_t *addr, uint8_t plen)
{
	size_t alen = f ? 16 : 4, lo = 0, hi = prefixes_n(c, f);
	uint8_t key[17];
	uint16_t rule;

	memcpy(key, addr, alen);
	key[alen] = plen;
	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;
		int cmp = memcmp(prefix_at(c, f, mid, &rule), key, alen + 1);

		if (!cmp)
			return mid;
		if (cmp < 0)
			lo = mid + 1;
		else
			hi = mid;
	}
	return -1;
}

/*
 * Same table and tag means old and new routes share keys and can be
 * merge-walked; otherwise they are disjoint sets.
 */
static bool prefixes_comparable(const struct config *oc, const struct config *nc)
{
	return oc && nc && oc->table_id == nc->table_id && oc->rt_proto == nc->rt_proto;
}

/*
 * Old and new hold the very same family f list (the same config, or one
 * shared across a reload): same keys and rule indexes, nothing to merge or
 * delete. A rule may still map to another group.
 */
static bool prefixes_shared(const struct config *oc, const struct config *nc, int f)
{
	return prefixes_comparable(oc, nc) && prefixes_of(oc, f) == prefixes_of(nc, f) &&
	       prefixes_n(oc, f) == prefixes_n(nc, f) && oc->n_rules == nc->n_rules;
}

/* Whether any rule of c maps to a group in ids, in family f. */
static bool rules_on(const struct config *c, int f, const struct idset *ids)
{
	for (size_t r = 0; r < c->n_rules; r++)
		if (idset_has(ids, rule_nh(c, r, f)))
			return true;
	return false;
}

/*
 * Believed: prev's prefix routes on the doomed groups become plain
 * blackholes, so that nothing falls through to the next rule, nor goes
 * through another group, until they point at their group again.
 */
static void prefixes_detach(const struct diff *d)
{
	const struct config *pc = d->pc;

	for (int f = 0; pc && d->s->doomed.n && f < 2; f++) {
		if (!rules_on(pc, f, &d->s->doomed))
			continue;
		for (size_t i = 0; i < prefixes_n(pc, f); i++)
			if (idset_has(&d->s->doomed, prefix_nh(pc, f, i)))
				prefix_detach(d, pc, f, i);
	}
}

/*
 * A believed prefix route depends on nothing but its group's nexthop,
 * given comparable table and tag: it changed if that nexthop id did, or if
 * the group was (or will be) deleted, taking the route along.
 */
static bool prefix_changed(const struct diff *d, int f, uint16_t orule, uint16_t nrule)
{
	uint32_t nnh = rule_nh(d->wc, nrule, f);

	return rule_nh(d->pc, orule, f) != nnh || idset_has(&d->s->reset, nnh);
}

/* Shared lists: set what changed, after checking per rule whether anything did. */
static void prefixes_set_shared(const struct diff *d, int f)
{
	size_t r, n = prefixes_n(d->wc, f);
	uint16_t rule;

	for (r = 0; r < d->wc->n_rules; r++)
		if (prefix_changed(d, f, r, r))
			break;
	if (r == d->wc->n_rules)
		return;

	for (size_t i = n; i-- > 0;) {
		prefix_at(d->wc, f, i, &rule);
		if (prefix_changed(d, f, rule, rule))
			prefix_send(d, NL_SET, d->wc, f, i);
	}
}

/* Orders entry i of a and entry j of b, both family f, by (addr, plen). */
static int prefix_cmp(const struct config *a, size_t i, const struct config *b, size_t j, int f,
                      uint16_t *ra, uint16_t *rb)
{
	return memcmp(prefix_at(a, f, i, ra), prefix_at(b, f, j, rb), f ? 17 : 5);
}

/*
 * Believed: set every prefix route of want that prev hasn't, or not as it
 * is. Walked backwards, (addr, plen) descending: a prefix comes before any
 * that covers it, so traffic never meets a covering route of another group
 * first, as it would while the more specific one isn't set yet.
 */
static void prefixes_set(const struct diff *d)
{
	const struct config *oc = d->pc, *nc = d->wc;
	bool comparable = prefixes_comparable(oc, nc);

	for (int f = 0; f < 2; f++) {
		size_t i = comparable ? prefixes_n(oc, f) : 0, j = prefixes_n(nc, f);
		uint16_t ro = 0, rn = 0;

		if (prefixes_shared(oc, nc, f)) {
			prefixes_set_shared(d, f);
			continue;
		}

		while (j > 0) {
			int cmp = i > 0 ? prefix_cmp(oc, i - 1, nc, j - 1, f, &ro, &rn) : -1;

			if (cmp > 0) {
				i--;
				continue;
			}
			if (cmp < 0 || prefix_changed(d, f, ro, rn))
				prefix_send(d, NL_SET, nc, f, j - 1);
			i -= !cmp;
			j--;
		}
	}
}

/* Believed: delete every prefix route of prev that want hasn't. */
static void prefixes_del(const struct diff *d)
{
	const struct config *oc = d->pc, *nc = d->wc;
	bool comparable = prefixes_comparable(oc, nc);

	for (int f = 0; oc && f < 2; f++) {
		size_t no = prefixes_n(oc, f), nn = comparable ? prefixes_n(nc, f) : 0;
		size_t i = 0, j = 0;
		uint16_t ro, rn;

		if (prefixes_shared(oc, nc, f))
			continue;

		while (i < no) {
			int cmp = j < nn ? prefix_cmp(oc, i, nc, j, f, &ro, &rn) : -1;

			if (cmp < 0)
				prefix_send(d, NL_DEL, oc, f, i);
			i += cmp <= 0;
			j += cmp >= 0;
		}
	}
}

/* --- full reconcile: the prefix routes observed too --- */

/* Per prefix of want, v4 then v6: in place as wanted; to be detached first. */
#define BIT_OK		1
#define BIT_DETACH	2

static size_t bit_index(const struct config *c, int f, size_t i)
{
	return f ? c->n_p4 + i : i;
}

static void bit_set(uint8_t *bits, size_t i, unsigned b)
{
	bits[i / 4] |= b << (2 * (i % 4));
}

static unsigned bit_get(const uint8_t *bits, size_t i)
{
	return bits[i / 4] >> (2 * (i % 4)) & 3;
}

/* Is k the key of one of c's prefix routes? Its index in family *f then, else -1. */
static long wanted_prefix(const struct config *c, const struct kroute *k, int *f)
{
	const struct route_spec *r = &k->r;

	if (r->table != c->table_id || k->tos || k->src_len)
		return -1;
	*f = r->family == AF_INET6;
	if (metric_of(r->family, r->metric) != (*f ? METRIC_V6 : 0))
		return -1;
	return prefix_find(c, *f, r->dst, r->plen);
}

/*
 * A route of routebot's that want has no place for: not in an observed
 * table (their routes are diffed one by one), no key of want's small
 * routes or prefix routes.
 */
static bool route_unwanted(const struct diff *d, const struct kroute *k)
{
	int f;

	return !observed_table(d, k->r.table) && !small_has(d->pw, k, route_key_eq) &&
	       wanted_prefix(d->wc, k, &f) < 0;
}

/*
 * An unwanted route that must not be left as it is while the nexthops and
 * rules change: on a nexthop that goes, or in one of want's own tables
 * (left over from another role, under another rule).
 */
static bool unwanted_off(const struct diff *d, const struct kroute *k)
{
	uint32_t t = k->r.table;

	return idset_has(&d->s->doomed, k->r.nh_id) || t == d->wc->table_id ||
	       (t > d->wc->table_id && t - d->wc->table_id <= d->wc->n_groups + 1);
}

struct scan {
	const struct diff *d;
	size_t n_unwanted;		/* routes to delete */
	size_t n_unwanted_off;		/* ... of which to blackhole first */
};

static int scan_cb(const struct nlmsghdr *nlh, void *data)
{
	struct scan *sc = data;
	const struct diff *d = sc->d;
	struct kroute k;
	long i;
	int f;

	if (nl_parse_route(nlh, &k) || !is_ours(d, k.r.proto) || observed_table(d, k.r.table))
		return MNL_CB_OK;
	i = wanted_prefix(d->wc, &k, &f);
	if (i < 0) {
		if (small_has(d->pw, &k, route_key_eq))
			return MNL_CB_OK;
		sc->n_unwanted++;
		sc->n_unwanted_off += unwanted_off(d, &k);
	} else if (k.r.proto == d->wc->rt_proto && k.r.nh_id == prefix_nh(d->wc, f, i) &&
	           !idset_has(&d->s->doomed, k.r.nh_id)) {
		bit_set(d->s->bits, bit_index(d->wc, f, i), BIT_OK);
	} else {
		/*
		 * Wrong, whatever it is (another group's nexthop, another
		 * table's role, one that goes): off it first, set after
		 */
		bit_set(d->s->bits, bit_index(d->wc, f, i), BIT_DETACH);
	}
	return MNL_CB_OK;
}

/* Dump every route with routebot's protos, classify it, keep nothing but bits. */
static int scan_routes(const struct diff *d, struct scan *sc)
{
	const struct config *c = d->wc;
	size_t n = (c->n_p4 + c->n_p6) / 4 + 1;
	int ret;

	if (reserve(&d->s->bits, &d->s->cap_bits, n, 1))
		return -ENOMEM;
	memset(d->s->bits, 0, n);
	memset(sc, 0, sizeof(*sc));
	sc->d = d;
	for (size_t p = 0; p < d->n_protos; p++) {
		ret = nl_dump_routes(d->nl, AF_UNSPEC, 0, d->protos[p], scan_cb, sc);
		if (ret)
			return ret;
	}
	return 0;
}

/*
 * Requests for routes known by dumping alone: every route with proto that
 * pred() holds for (all, if NULL) gets op, queued right from the dump's callback (dumps
 * have their own socket: the batch goes out between two of its datagrams,
 * and the kernel's dump goes on from where it was, routes gone or not). A
 * request that succeeds makes pred() false (the route is gone, or a
 * blackhole off any nexthop); one more dump checks that, and catches what a
 * dump resumed after deletions may have skipped. Memory stays bounded,
 * time linear in the routes.
 */
struct sweep {
	struct nl *nl;
	uint8_t proto;
	enum nl_op op;
	bool (*pred)(const struct kroute *k, const void *data);
	const void *data;
	size_t n_sent;
};

static int sweep_cb(const struct nlmsghdr *nlh, void *data)
{
	struct sweep *sw = data;
	struct route_key key;
	struct kroute k;

	if (nl_parse_route(nlh, &k) || k.r.proto != sw->proto ||
	    (sw->pred && !sw->pred(&k, sw->data)))
		return MNL_CB_OK;
	kroute_key(&k, &key);
	nl_route_key(sw->nl, sw->op, &key, sw->proto);
	sw->n_sent++;
	return MNL_CB_OK;
}

#define SWEEP_PASSES 4

/* Counts what went and what's left; adds request errors to *errors. */
static int sweep_run(struct sweep *sw, size_t *n_done, size_t *n_left, unsigned *errors)
{
	struct nl *nl = sw->nl;
	int ret = 0;

	*n_done = *n_left = 0;
	for (int pass = 0; pass < SWEEP_PASSES; pass++) {
		size_t failed;

		sw->n_sent = 0;
		nl_batch_begin(nl);
		ret = nl_dump_routes(nl, AF_UNSPEC, 0, sw->proto, sweep_cb, sw);
		*errors += nl_batch_end(nl);
		if (ret)
			return ret;
		failed = nl->n_expected + nl->n_errors;
		failed = failed < sw->n_sent ? failed : sw->n_sent;
		*n_done += sw->n_sent - failed;
		*n_left = sw->n_sent;
		/* nothing left, or nothing more that can go */
		if (!sw->n_sent || failed == sw->n_sent) {
			*n_left = failed;
			break;
		}
	}
	return 0;
}

static bool pred_unwanted(const struct kroute *k, const void *data)
{
	return route_unwanted(data, k);
}

static bool pred_unwanted_off(const struct kroute *k, const void *data)
{
	const struct diff *d = data;

	return (k->r.type != RTN_BLACKHOLE || k->r.nh_id) && route_unwanted(d, k) &&
	       unwanted_off(d, k);
}

/* Sweep, with each of routebot's protos, the routes pred() holds for. */
static int sweep_protos(const struct diff *d, bool (*pred)(const struct kroute *, const void *),
                        enum nl_op op)
{
	for (size_t p = 0; p < d->n_protos; p++) {
		struct sweep sw = {
			.nl = d->nl, .proto = d->protos[p], .op = op, .pred = pred, .data = d,
		};
		size_t done, left;
		int ret = sweep_run(&sw, &done, &left, &d->st->errors);

		if (ret)
			return ret;
		if (op == NL_DEL)
			d->st->route_del += done;
		else
			d->st->route_set += done;
		if (left) {
			warn("reconcile: %zu routes with proto %u left, can't %s them", left,
			     d->protos[p], op == NL_DEL ? "delete" : "detach");
			d->st->errors++;
		}
	}
	return 0;
}

/* Observed: want's prefix routes on a doomed nexthop become plain blackholes. */
static void prefixes_full_detach(const struct diff *d)
{
	const struct config *c = d->wc;

	for (int f = 0; f < 2; f++)
		for (size_t i = 0; i < prefixes_n(c, f); i++)
			if (bit_get(d->s->bits, bit_index(c, f, i)) & BIT_DETACH)
				prefix_detach(d, c, f, i);
}

/* Observed: set every prefix route of want not in place. */
static void prefixes_full_set(const struct diff *d)
{
	const struct config *c = d->wc;

	/* backwards, as prefixes_set() */
	for (int f = 0; f < 2; f++)
		for (size_t i = prefixes_n(c, f); i-- > 0;) {
			if (bit_get(d->s->bits, bit_index(c, f, i)) & BIT_OK)
				d->st->kept++;
			else
				prefix_send(d, NL_SET, c, f, i);
		}
}

/* --- the small objects --- */

/*
 * Kernel nexthops to delete and make anew: those the kernel can't replace
 * into what want has at their id; those that stand for something else now
 * (another group or device: replaced in place, they'd send the routes
 * still on them through another group's uplinks); and, where prev doesn't
 * say whose they are, those that differ. Deleting a member drops it from
 * its groups, and a group left empty goes too: doomed as well.
 */
static int find_doomed(const struct diff *d)
{
	struct idset *doomed = &d->s->doomed;

	doomed->n = 0;
	for (size_t i = 0; i < d->k->n_nh; i++) {
		const struct nexthop_spec *kn = &d->k->nh[i];
		const struct nexthop_spec *dn = plan_nh(d->pw, kn->id);
		int same;

		if (!dn || !is_ours(d, kn->proto))
			continue;
		same = same_owner(d->pc, d->wc, kn->id);
		if ((!nh_replaceable(kn, dn) || !same || (same < 0 && !nh_eq(kn, dn))) &&
		    idset_add(doomed, kn->id))
			return -1;
	}

	for (size_t i = 0; i < d->k->n_nh; i++) {
		const struct nexthop_spec *kn = &d->k->nh[i];
		bool all = true;

		if (!kn->n_grp || !is_ours(d, kn->proto) || idset_has(doomed, kn->id))
			continue;
		for (size_t m = 0; m < kn->n_grp; m++)
			all = all && idset_has(doomed, kn->grp[m].id);
		if (all && idset_add(doomed, kn->id))
			return -1;
	}
	return 0;
}

/* Is want's witness of group g in family f there, on the group? */
static bool witness_ok(const struct diff *d, size_t g, int f)
{
	struct route_spec w = {
		.family = families[f],
		.type = RTN_UNICAST,
		.proto = d->wc->rt_proto,
		.table = cfg_group_table(d->wc, g),
		.nh_id = cfg_group_nhid(d->wc, g, f),
	};

	return k_nh(d, w.nh_id) && k_has_route(d, &w);
}

/*
 * Groups whose prefix routes the kernel may have taken (the group or its
 * witness is gone) or will take (doomed): their routes are set again.
 */
static int find_reset(const struct diff *d)
{
	struct idset *reset = &d->s->reset;

	reset->n = 0;
	for (size_t g = 0; g < d->wc->n_groups; g++)
		for (int f = 0; f < 2; f++) {
			uint32_t id = cfg_group_nhid(d->wc, g, f);

			if ((idset_has(&d->s->doomed, id) || !witness_ok(d, g, f)) &&
			    idset_add(reset, id))
				return -1;
		}
	return 0;
}

static void lost(const struct diff *d, const char *who, const char *what, int f)
{
	info("%s: kernel lost its %s %s, restoring", who, fam_name(f), what);
	d->st->lost++;
}

/* What prev had installed, want still has, and the kernel lost: said once, counted. */
static void log_lost(const struct diff *d)
{
	const struct plan *pp = d->pp, *pw = d->pw;
	const struct config *pc = d->pc, *wc = d->wc;
	struct owner o;

	if (!pc)
		return;
	/* members, then groups: group i of the plan is g = i / 2, f = i % 2 */
	for (size_t i = 0; i < pw->n_members + pw->n_groups; i++) {
		size_t g = i - pw->n_members;
		const struct nexthop_spec *n = g < pw->n_groups ? &pw->groups[g] : &pw->members[i];

		if (plan_nh(pp, n->id) && same_owner(pc, wc, n->id) == 1 && owner_of(wc, n->id, &o) &&
		    o.kind != 'b' && (g < pw->n_groups ? pc->table_id == wc->table_id &&
		                      !witness_ok(d, g / 2, o.f) : !k_nh(d, n->id)))
			lost(d, o.name, g < pw->n_groups ? "group" : "nexthop", o.f);
	}
	for (size_t i = 0; i < pw->n_small; i++) {
		struct kroute k = { .r = pw->small[i] };	/* as prev had it */
		size_t dev = k.r.metric - 1;

		k.r.proto = pc->rt_proto;
		if (k.r.table == cfg_probe_table(wc) && !k_has_route(d, &pw->small[i]) &&
		    dev < pc->n_devices && !strcmp(pc->devices[dev].spec, wc->devices[dev].spec) &&
		    small_has(pp, &k, route_eq))
			lost(d, wc->devices[dev].spec, "probe route", k.r.family == AF_INET6);
	}
	for (size_t i = 0; i < pw->n_rules; i++)
		if (!rule_in(d->k->rules, d->k->n_rules, &pw->rules[i]) &&
		    rule_in(pp->rules, pp->n_rules, &pw->rules[i])) {
			info("kernel lost the %s rule at %u, restoring",
			     fam_name(pw->rules[i].family == AF_INET6), pw->rules[i].prio);
			d->st->lost++;
		}
}

/* Delete the doomed: groups first, deleting members empties some. */
static void nexthops_del_doomed(const struct diff *d)
{
	for (int groups = 1; groups >= 0; groups--)
		for (size_t i = 0; i < d->k->n_nh; i++) {
			const struct nexthop_spec *kn = &d->k->nh[i];

			if (!!kn->n_grp == groups && idset_has(&d->s->doomed, kn->id)) {
				nl_nexthop(d->nl, NL_DEL, kn);
				d->st->nh_del++;
			}
		}
}

/* Does deleting the doomed take a member out of the kernel's group kn? */
static bool loses_member(const struct diff *d, const struct nexthop_spec *kn)
{
	for (size_t m = 0; m < kn->n_grp; m++)
		if (idset_has(&d->s->doomed, kn->grp[m].id))
			return true;
	return false;
}

/*
 * Set every nexthop of n the kernel doesn't hold as it is, or holds
 * doomed, or (a group) with a doomed member, which the delete dropped.
 */
static void nexthops_set(const struct diff *d, const struct nexthop_spec *n, size_t nn)
{
	for (size_t j = 0; j < nn; j++) {
		const struct nexthop_spec *kn = k_nh(d, n[j].id);

		if (kn && nh_eq(kn, &n[j]) && !idset_has(&d->s->doomed, n[j].id) &&
		    !loses_member(d, kn))
			continue;
		/*
		 * One the dump showed is only replaced: should the kernel have
		 * deleted it since, and the routes on it, that fails (and calls
		 * for a full reconcile) instead of creating it anew under a
		 * witness that would vouch for routes no longer there.
		 */
		nl_nexthop(d->nl, kn && !idset_has(&d->s->doomed, n[j].id) ? NL_REPLACE : NL_SET,
		           &n[j]);
		d->st->nh_set++;
	}
}

/* Delete routebot's nexthops that want hasn't: groups, or the rest. */
static void nexthops_del_extra(const struct diff *d, bool groups)
{
	for (size_t i = 0; i < d->k->n_nh; i++) {
		const struct nexthop_spec *kn = &d->k->nh[i];

		if (!!kn->n_grp != groups || !is_ours(d, kn->proto) || plan_nh(d->pw, kn->id) ||
		    idset_has(&d->s->doomed, kn->id))
			continue;
		nl_nexthop(d->nl, NL_DEL, kn);
		d->st->nh_del++;
	}
}

/*
 * Set want's small routes the kernel doesn't hold as they are: the
 * blackholes behind the group tables' defaults, or the rest. A doomed
 * group's witness goes with it.
 */
static void small_routes_set(const struct diff *d, bool blackholes)
{
	for (size_t j = 0; j < d->pw->n_small; j++) {
		const struct route_spec *r = &d->pw->small[j];

		if ((r->type == RTN_BLACKHOLE) != blackholes ||
		    (k_has_route(d, r) && !idset_has(&d->s->doomed, r->nh_id)))
			continue;
		nl_route(d->nl, NL_SET, r);
		d->st->route_set++;
	}
}

/*
 * Routebot's routes in the observed tables. A full reconcile trusts
 * nothing: there, any that isn't want's becomes a blackhole first (early),
 * before rules and nexthops change (it may be another role's, an old probe
 * route in what is now a group table, say). In the end, those want has no
 * key for are deleted, but those on a doomed nexthop, gone with it.
 */
static void small_routes_del(const struct diff *d, bool early)
{
	for (size_t i = 0; i < d->k->n_routes; i++) {
		const struct kroute *k = &d->k->routes[i];
		struct route_key key;

		if (!is_ours(d, k->r.proto))
			continue;
		if (early ? d->mode != SYNC_FULL || small_has(d->pw, k, route_eq) ||
		            (k->r.type == RTN_BLACKHOLE && !k->r.nh_id)
		          : small_has(d->pw, k, route_key_eq) ||
		            (d->mode != SYNC_FULL && idset_has(&d->s->doomed, k->r.nh_id)))
			continue;
		kroute_key(k, &key);
		nl_route_key(d->nl, early ? NL_SET : NL_DEL, &key, k->r.proto);
		if (early)
			d->st->route_set++;
		else
			d->st->route_del++;
	}
}

static void rules_add(const struct diff *d)
{
	for (size_t i = 0; i < d->pw->n_rules; i++)
		if (!rule_in(d->k->rules, d->k->n_rules, &d->pw->rules[i])) {
			nl_rule(d->nl, NL_SET, &d->pw->rules[i]);
			d->st->rule_add++;
		}
}

/*
 * Delete routebot's rules that want hasn't: those into want's CIDR table,
 * or the rest. A table never gets new content while an old rule of other
 * traffic still points there: old rules into the CIDR table go before it's
 * filled, the rest before the group and probe tables are. Yet they go only
 * once the CIDR table is filled, or listed traffic would meet it empty.
 */
static void rules_del(const struct diff *d, bool cidr)
{
	for (size_t i = 0; i < d->k->n_rules; i++) {
		const struct rule_spec *r = &d->k->rules[i];

		if (!is_ours(d, r->proto) || rule_in(d->pw->rules, d->pw->n_rules, r) ||
		    (r->table == d->wc->table_id) != cidr)
			continue;
		nl_rule(d->nl, NL_DEL, r);
		d->st->rule_del++;
	}
}

/* Set want's prefix routes the kernel hasn't as they are. */
static void prefixes_fill(const struct diff *d)
{
	if (d->mode == SYNC_FULL)
		prefixes_full_set(d);
	else
		prefixes_set(d);
}

/* Does a reload from pc to wc move routebot's tables, rules or ids? */
static bool layout_changes(const struct config *pc, const struct config *wc)
{
	return pc && (pc->table_id != wc->table_id || pc->rule_prio != wc->rule_prio ||
	              pc->nexthop_id != wc->nexthop_id || pc->rt_proto != wc->rt_proto);
}

/*
 * Before a layout change: every group of prev's the kernel holds becomes
 * its family's blackhole, in place. Whatever is on them, prefix routes and
 * group table defaults, drops traffic until the new layout is set, rather
 * than leaking it to main or another group's uplink.
 */
static unsigned groups_blackhole(struct diff *d)
{
	nl_batch_begin(d->nl);
	for (size_t i = 0; i < d->pp->n_members; i++)
		if (d->pp->members[i].blackhole) {
			nl_nexthop(d->nl, NL_SET, &d->pp->members[i]);
			d->st->nh_set++;
		}
	for (size_t i = 0; i < d->pp->n_groups; i++) {
		const struct nexthop_spec *g = &d->pp->groups[i];
		const struct nexthop_spec *kn = k_nh(d, g->id);
		struct nexthop_spec n;

		if (!kn || !kn->n_grp || !is_ours(d, kn->proto))
			continue;
		n = *kn;
		n.n_grp = 1;
		n.grp[0] = (struct nh_grp_entry){
			cfg_blackhole_nhid(d->pc, g->family == AF_INET6), 1 };
		nl_nexthop(d->nl, NL_REPLACE, &n);
		d->st->nh_set++;
	}
	return batch_end(d);
}

int sync_apply(struct sync *s, struct nl *nl, const struct world *prev,
               const struct world *want, enum sync_mode mode, struct sync_stats *st)
{
	struct diff d = {
		.s = s, .nl = nl, .pc = prev->cfg, .wc = want->cfg, .k = &s->k,
		.pw = &s->want, .pp = &s->prev, .st = st, .mode = mode,
	};
	const struct nexthop_spec *foreign;
	struct scan sc = {};
	unsigned uncertain = 0;
	int ret;

	memset(st, 0, sizeof(*st));
	s->refused.n = 0;
	d.protos[d.n_protos++] = want->cfg->rt_proto;
	if (d.pc && !is_ours(&d, d.pc->rt_proto))
		d.protos[d.n_protos++] = d.pc->rt_proto;
	/* nothing believed, or a layout change: all of it observed */
	if (!d.pc || layout_changes(d.pc, d.wc))
		d.mode = SYNC_FULL;

	if (plan_build(want, &s->want) || plan_build(prev, &s->prev)) {
		err("out of memory");
		st->errors++;
		return -1;
	}
	ret = observe(&d);
	if (!ret && layout_changes(d.pc, d.wc)) {
		uncertain += groups_blackhole(&d);
		ret = observe(&d);
	}
	if (ret) {
		err("sync: can't read the kernel's state: %s", strerror(-ret));
		st->errors++;
		return -1;
	}
	foreign = foreign_nh(&d);
	if (foreign) {
		err("nexthop id %u has proto %u, not %u: nexthop_id range %u..%llu must be "
		    "routebot's alone", foreign->id, foreign->proto, d.wc->rt_proto,
		    cfg_nhid_start(d.wc), (unsigned long long)cfg_nhid_end(d.wc));
		st->errors++;
		return -1;
	}
	if (find_doomed(&d) || find_reset(&d)) {
		err("out of memory");
		st->errors++;
		return -1;
	}
	log_lost(&d);

	if (d.mode == SYNC_FULL) {
		unsigned before = st->errors;

		ret = scan_routes(&d, &sc);
		/* nothing goes through a nexthop that goes, or a table that changes hands */
		if (!ret && sc.n_unwanted_off)
			ret = sweep_protos(&d, pred_unwanted_off, NL_SET);
		uncertain += st->errors - before;
		if (ret) {
			err("reconcile: %s", strerror(-ret));
			st->errors++;
			return -1;
		}
	}

	/*
	 * make before break: blackholes behind the group tables' defaults;
	 * routes off what goes; new rules; then nexthops bottom up (the
	 * members the kernel refuses left out of the groups), the CIDR table
	 * filled, the other tables once no old rule points there, and clean
	 * up top down.
	 */
	nl_batch_begin(nl);
	small_routes_set(&d, true);
	if (d.mode == SYNC_FULL)
		prefixes_full_detach(&d);
	else
		prefixes_detach(&d);
	small_routes_del(&d, true);
	nexthops_del_doomed(&d);
	rules_add(&d);
	rules_del(&d, true);
	nexthops_set(&d, s->want.members, s->want.n_members);
	uncertain += batch_end(&d);

	plan_drop(&s->want, d.wc, &s->refused);
	nl_batch_begin(nl);
	nexthops_set(&d, s->want.groups, s->want.n_groups);
	prefixes_fill(&d);
	rules_del(&d, false);
	small_routes_set(&d, false);
	small_routes_del(&d, false);
	if (d.mode == SYNC_FULL) {
		uncertain += batch_end(&d);
		info("reconcile: %zu prefix routes in place", st->kept);
		if (sc.n_unwanted) {
			unsigned before = st->errors;

			if (sweep_protos(&d, pred_unwanted, NL_DEL)) {
				err("reconcile: route dump failed");
				st->errors++;
			}
			uncertain += st->errors - before;
		}
		nl_batch_begin(nl);
	} else {
		prefixes_del(&d);
	}
	nexthops_del_extra(&d, true);
	nexthops_del_extra(&d, false);
	uncertain += batch_end(&d);

	return uncertain ? -1 : 0;
}

/* --- flush --- */

/* Delete k's nexthops that are groups, or that aren't. */
static void flush_nexthops(struct nl *nl, const struct kstate *k, bool groups)
{
	for (size_t i = 0; i < k->n_nh; i++)
		if (!!k->nh[i].n_grp == groups)
			nl_nexthop(nl, NL_DEL, &k->nh[i]);
}

/*
 * Rules first, then the groups: the kernel deletes every route on a deleted
 * nexthop by itself, which is nearly all of them, much faster than route
 * by route. The rest are swept. Then the members and blackholes, no longer
 * in any group, and any route still on them.
 */
int sync_flush(struct nl *nl, uint8_t proto)
{
	struct kscope sc = { .protos = { proto }, .n_protos = 1 };
	struct sweep sw = { .nl = nl, .proto = proto, .op = NL_DEL };
	struct kstate k = {};
	size_t n_routes = 0, n_left = 0, n_more = 0;
	unsigned errors;
	int ret = kstate_observe(nl, &sc, &k);

	if (ret)
		goto fail;
	nl_batch_begin(nl);
	for (size_t i = 0; i < k.n_rules; i++)
		nl_rule(nl, NL_DEL, &k.rules[i]);
	flush_nexthops(nl, &k, true);
	errors = nl_batch_end(nl);

	ret = sweep_run(&sw, &n_routes, &n_left, &errors);
	if (ret)
		goto fail;
	nl_batch_begin(nl);
	flush_nexthops(nl, &k, false);
	errors += nl_batch_end(nl);

	/* some may have been on the members */
	if (n_left && (ret = sweep_run(&sw, &n_more, &n_left, &errors)))
		goto fail;
	n_routes += n_more;
	if (n_left) {
		warn("flush: %zu routes with proto %u left, can't delete them", n_left, proto);
		errors++;
	}
	if (k.n_rules || k.n_nh || n_routes)
		info("flush: removed %zu rules, %zu nexthops and the routes on them, "
		     "%zu other routes with proto %u%s", k.n_rules, k.n_nh, n_routes, proto,
		     errors ? " (with errors)" : "");
	kstate_free(&k);
	return errors ? -EIO : 0;

fail:
	err("flush: dump failed: %s", strerror(-ret));
	kstate_free(&k);
	return ret;
}

/* --- nexthop id ownership --- */

struct nhid_ctx {
	const struct config *cfg;
	uint8_t protos[2];
	size_t n_protos;
	uint32_t id;		/* first foreign id found, 0 = none */
	uint8_t proto;
};

static int nhid_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nhid_ctx *nc = data;
	struct nexthop_spec n;

	/* a group too big to parse still has its id and proto */
	if (nc->id || (nl_parse_nexthop(nlh, &n) && !n.id))
		return MNL_CB_OK;
	for (size_t i = 0; i < nc->n_protos; i++)
		if (n.proto == nc->protos[i])
			return MNL_CB_OK;
	if (n.id >= cfg_nhid_start(nc->cfg) && n.id <= cfg_nhid_end(nc->cfg)) {
		nc->id = n.id;
		nc->proto = n.proto;
	}
	return MNL_CB_OK;
}

int sync_check_nhids(struct nl *nl, const struct config *cfg, const struct config *prev)
{
	struct nhid_ctx nc = { .cfg = cfg };
	int ret;

	nc.protos[nc.n_protos++] = cfg->rt_proto;
	if (prev)
		nc.protos[nc.n_protos++] = prev->rt_proto;

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
		    cfg_nhid_start(cfg), (unsigned long long)cfg_nhid_end(cfg));
		return -1;
	}
	return 0;
}
