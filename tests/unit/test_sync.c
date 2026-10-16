/*
 * sync_apply against a model of the kernel.
 *
 * mnl_socket_sendto is interposed (the executable's definition wins over
 * libmnl's), so every batch nl.c sends lands here instead of the kernel: it
 * is applied to a small model with the kernel's semantics (deleting a
 * nexthop deletes the routes on it and drops it from its groups, an emptied
 * group goes too; replace can't change a group's bucket count; routes need
 * their nexthop to exist).
 *
 * For every pair of worlds (old, new), named scenarios and random ones:
 *   - empty -> old installs exactly old's prefixes, rendered independently
 *   - old -> new leaves the model equal to empty -> new
 *   - no route set is a no-op replace, no request fails
 *   - the prefix route requests are exactly, in order, those of the
 *     straightforward diff: every new prefix that is new, or whose group
 *     nexthop changed or was re-created, v4 then v6, then every old prefix
 *     gone from new (all of them when table or tag changed)
 */
#include <arpa/inet.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/nexthop.h>
#include <linux/rtnetlink.h>
#include <linux/fib_rules.h>

#include "log.h"
#include "sync.h"

int log_level = L_WARN;

const char *__ubsan_default_options(void);
const char *__ubsan_default_options(void)
{
	return "halt_on_error=1:print_stacktrace=1";
}

void log_msg(int level, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "log %d: ", level);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
}

static unsigned fails;
static const char *scenario;

#define CHECK(cond, ...) do { \
	if (!(cond)) { \
		fails++; \
		fprintf(stderr, "FAIL %s:%d [%s]: ", __FILE__, __LINE__, scenario); \
		fprintf(stderr, __VA_ARGS__); \
		fputc('\n', stderr); \
	} \
} while (0)

/* --- the kernel model --- */

struct mroute {
	uint8_t family, plen, type, proto;
	uint32_t table, metric, nh_id;
	int oif;
	bool has_gw;
	uint8_t dst[16], gw[16];
};

struct mnh {
	uint32_t id;
	bool group;
	uint8_t family, proto;
	int oif;
	bool has_gw;
	uint8_t gw[16];
	uint16_t n, buckets;
	uint32_t ids[MAX_NH_GROUP];
	uint16_t weights[MAX_NH_GROUP];
	uint32_t idle, busy;
};

struct mrule {
	uint8_t family, proto;
	uint32_t prio, mark, mask, table;
};

#define MAXR 4096
#define MAXNH 256
#define MAXRU 64

struct kernel {
	struct mroute r[MAXR];
	size_t nr;
	struct mnh nh[MAXNH];
	size_t nnh;
	struct mrule ru[MAXRU];
	size_t nru;
};

/* What one apply did, as the kernel saw it. */
struct rec {
	uint8_t op;	/* 'S' set, 'D' delete */
	uint8_t family, plen, type, proto;
	uint32_t table, nh_id;
	uint8_t dst[16];
};

static struct kernel *K;	/* where requests go */
static struct rec recs[2 * MAXR];
static size_t nrecs;
static unsigned n_failed, n_noop_set, n_msgs;
static uint32_t nh_deleted[MAXNH], nh_recreated[MAXNH];
static size_t n_deleted, n_recreated;

static bool route_key_same(const struct mroute *a, const struct mroute *b)
{
	return a->family == b->family && a->plen == b->plen && a->table == b->table &&
	       a->metric == b->metric && !memcmp(a->dst, b->dst, 16);
}

static struct mnh *nh_get(struct kernel *k, uint32_t id)
{
	for (size_t i = 0; i < k->nnh; i++)
		if (k->nh[i].id == id)
			return &k->nh[i];
	return NULL;
}

static void routes_drop_nh(struct kernel *k, uint32_t id)
{
	size_t w = 0;

	for (size_t i = 0; i < k->nr; i++)
		if (k->r[i].nh_id != id)
			k->r[w++] = k->r[i];
	k->nr = w;
}

static void nh_remove(struct kernel *k, uint32_t id)
{
	struct mnh *n = nh_get(k, id);
	uint32_t emptied[MAXNH];
	size_t ne = 0;

	if (!n)
		return;
	*n = k->nh[--k->nnh];
	routes_drop_nh(k, id);
	for (size_t i = 0; i < k->nnh; i++) {
		struct mnh *g = &k->nh[i];
		uint16_t w = 0;

		if (!g->group)
			continue;
		for (uint16_t j = 0; j < g->n; j++)
			if (g->ids[j] != id) {
				g->ids[w] = g->ids[j];
				g->weights[w++] = g->weights[j];
			}
		g->n = w;
		if (!w)
			emptied[ne++] = g->id;
	}
	for (size_t i = 0; i < ne; i++)
		nh_remove(k, emptied[i]);
}

struct attrs {
	const struct nlattr *tb[64];
};

static int attrs_cb(const struct nlattr *a, void *data)
{
	struct attrs *t = data;

	if (mnl_attr_get_type(a) < 64)
		t->tb[mnl_attr_get_type(a)] = a;
	return MNL_CB_OK;
}

static uint32_t attr_u32(const struct attrs *t, int type, uint32_t def)
{
	return t->tb[type] ? mnl_attr_get_u32(t->tb[type]) : def;
}

static void apply_route(const struct nlmsghdr *nlh)
{
	const struct rtmsg *rtm = mnl_nlmsg_get_payload(nlh);
	struct attrs t = {};
	struct mroute r;
	struct rec *rc = &recs[nrecs++];
	size_t i;

	memset(&r, 0, sizeof(r));	/* compared with memcmp, padding included */
	mnl_attr_parse(nlh, sizeof(*rtm), attrs_cb, &t);
	r.family = rtm->rtm_family;
	r.plen = rtm->rtm_dst_len;
	r.proto = rtm->rtm_protocol;
	r.type = rtm->rtm_type;
	r.table = attr_u32(&t, RTA_TABLE, rtm->rtm_table);
	r.metric = attr_u32(&t, RTA_PRIORITY, 0);
	r.nh_id = attr_u32(&t, RTA_NH_ID, 0);
	r.oif = attr_u32(&t, RTA_OIF, 0);
	if (t.tb[RTA_DST])
		memcpy(r.dst, mnl_attr_get_payload(t.tb[RTA_DST]), mnl_attr_get_payload_len(t.tb[RTA_DST]));
	if (t.tb[RTA_GATEWAY]) {
		r.has_gw = true;
		memcpy(r.gw, mnl_attr_get_payload(t.tb[RTA_GATEWAY]),
		       mnl_attr_get_payload_len(t.tb[RTA_GATEWAY]));
	}

	memset(rc, 0, sizeof(*rc));
	rc->op = nlh->nlmsg_type == RTM_DELROUTE ? 'D' : 'S';
	rc->family = r.family;
	rc->plen = r.plen;
	rc->type = r.type;
	rc->proto = r.proto;
	rc->table = r.table;
	rc->nh_id = r.nh_id;
	memcpy(rc->dst, r.dst, 16);

	for (i = 0; i < K->nr; i++)
		if (route_key_same(&K->r[i], &r))
			break;

	if (nlh->nlmsg_type == RTM_DELROUTE) {
		/* the kernel matches the protocol when one is given; a miss is ESRCH */
		if (i < K->nr && (!r.proto || r.proto == K->r[i].proto))
			K->r[i] = K->r[--K->nr];
		return;
	}

	if (r.nh_id) {
		const struct mnh *n = nh_get(K, r.nh_id);

		if (!n || n->family != r.family) {
			n_failed++;
			fprintf(stderr, "route via missing/foreign nexthop %u\n", r.nh_id);
			return;
		}
	}
	if (i < K->nr) {
		if (!memcmp(&K->r[i], &r, sizeof(r))) {
			n_noop_set++;
			fprintf(stderr, "no-op replace: table %u plen %u nh %u type %u\n",
				r.table, r.plen, r.nh_id, r.type);
		}
		K->r[i] = r;
		return;
	}
	if (K->nr == MAXR) {
		n_failed++;
		return;
	}
	K->r[K->nr++] = r;
}

static void apply_nexthop(const struct nlmsghdr *nlh)
{
	const struct nhmsg *nhm = mnl_nlmsg_get_payload(nlh);
	struct attrs t = {};
	struct mnh n = {}, *o;

	mnl_attr_parse(nlh, sizeof(*nhm), attrs_cb, &t);
	n.id = attr_u32(&t, NHA_ID, 0);
	o = nh_get(K, n.id);

	if (nlh->nlmsg_type == RTM_DELNEXTHOP) {
		if (o) {
			nh_deleted[n_deleted++] = n.id;
			nh_remove(K, n.id);
		}
		return;
	}

	n.proto = nhm->nh_protocol;
	if (t.tb[NHA_GROUP]) {
		const struct nexthop_grp *g = mnl_attr_get_payload(t.tb[NHA_GROUP]);
		struct attrs rt = {};

		n.group = true;
		n.n = mnl_attr_get_payload_len(t.tb[NHA_GROUP]) / sizeof(*g);
		for (uint16_t i = 0; i < n.n; i++) {
			const struct mnh *m = nh_get(K, g[i].id);

			if (!m || m->group) {
				n_failed++;
				fprintf(stderr, "group %u: member %u missing\n", n.id, g[i].id);
				return;
			}
			n.family = m->family;
			n.ids[i] = g[i].id;
			n.weights[i] = g[i].weight;
		}
		if (t.tb[NHA_RES_GROUP])
			mnl_attr_parse_nested(t.tb[NHA_RES_GROUP], attrs_cb, &rt);
		n.buckets = rt.tb[NHA_RES_GROUP_BUCKETS] ?
			    mnl_attr_get_u16(rt.tb[NHA_RES_GROUP_BUCKETS]) : 0;
		n.idle = attr_u32(&rt, NHA_RES_GROUP_IDLE_TIMER, 0);
		n.busy = attr_u32(&rt, NHA_RES_GROUP_UNBALANCED_TIMER, 0);
	} else {
		n.family = nhm->nh_family;
		n.oif = attr_u32(&t, NHA_OIF, 0);
		if (t.tb[NHA_GATEWAY]) {
			n.has_gw = true;
			memcpy(n.gw, mnl_attr_get_payload(t.tb[NHA_GATEWAY]),
			       mnl_attr_get_payload_len(t.tb[NHA_GATEWAY]));
		}
	}

	if (o) {
		if (o->group != n.group || o->family != n.family ||
		    (n.group && o->buckets != n.buckets)) {
			n_failed++;
			fprintf(stderr, "nexthop %u: replace can't do that\n", n.id);
			return;
		}
		*o = n;
		return;
	}
	for (size_t i = 0; i < n_deleted; i++)
		if (nh_deleted[i] == n.id)
			nh_recreated[n_recreated++] = n.id;
	K->nh[K->nnh++] = n;
}

static void apply_rule(const struct nlmsghdr *nlh)
{
	const struct fib_rule_hdr *frh = mnl_nlmsg_get_payload(nlh);
	struct attrs t = {};
	struct mrule r;
	size_t i;

	memset(&r, 0, sizeof(r));
	mnl_attr_parse(nlh, sizeof(*frh), attrs_cb, &t);
	r.family = frh->family;
	r.proto = t.tb[FRA_PROTOCOL] ? mnl_attr_get_u8(t.tb[FRA_PROTOCOL]) : 0;
	r.prio = attr_u32(&t, FRA_PRIORITY, 0);
	r.mark = attr_u32(&t, FRA_FWMARK, 0);
	r.mask = attr_u32(&t, FRA_FWMASK, 0);
	r.table = attr_u32(&t, FRA_TABLE, frh->table);
	for (i = 0; i < K->nru; i++)
		if (!memcmp(&K->ru[i], &r, sizeof(r)))
			break;
	if (nlh->nlmsg_type == RTM_DELRULE) {
		if (i < K->nru)
			K->ru[i] = K->ru[--K->nru];
	} else if (i == K->nru) {
		K->ru[K->nru++] = r;
	}
}

ssize_t mnl_socket_sendto(const struct mnl_socket *s, const void *buf, size_t len)
{
	int left = len;

	(void)s;
	for (const struct nlmsghdr *nlh = buf; mnl_nlmsg_ok(nlh, left);
	     nlh = mnl_nlmsg_next(nlh, &left)) {
		n_msgs++;
		switch (nlh->nlmsg_type) {
		case RTM_NEWROUTE:
		case RTM_DELROUTE:
			apply_route(nlh);
			break;
		case RTM_NEWNEXTHOP:
		case RTM_DELNEXTHOP:
			apply_nexthop(nlh);
			break;
		case RTM_NEWRULE:
		case RTM_DELRULE:
			apply_rule(nlh);
			break;
		default:
			n_failed++;
		}
	}
	return len;
}

/* Canonical text of the model: sorted lines. */
static int cmp_str(const void *a, const void *b)
{
	return strcmp(*(char *const *)a, *(char *const *)b);
}

static char *kernel_text(const struct kernel *k)
{
	size_t n = k->nr + k->nnh + k->nru, len = 1;
	char **lines = calloc(n + 1, sizeof(*lines)), *out, *p;
	size_t l = 0;

	for (size_t i = 0; i < k->nr; i++) {
		const struct mroute *r = &k->r[i];
		char d[64], g[64];

		inet_ntop(r->family, r->dst, d, sizeof(d));
		inet_ntop(r->family, r->gw, g, sizeof(g));
		lines[l] = malloc(256);
		snprintf(lines[l++], 256, "route %u %s/%u t%u m%u type%u nh%u oif%d gw%s p%u",
			 r->family, d, r->plen, r->table, r->metric, r->type, r->nh_id, r->oif,
			 r->has_gw ? g : "-", r->proto);
	}
	for (size_t i = 0; i < k->nnh; i++) {
		const struct mnh *h = &k->nh[i];
		char *s = malloc(1024);
		int o = snprintf(s, 1024, "nh %u f%u p%u g%d oif%d gw%d:%02x%02x b%u i%u u%u",
				 h->id, h->family, h->proto, h->group, h->oif, h->has_gw,
				 h->gw[0], h->gw[3] ^ h->gw[15], h->buckets, h->idle, h->busy);

		for (uint16_t j = 0; j < h->n; j++)
			o += snprintf(s + o, 1024 - o, " %u/%u", h->ids[j], h->weights[j]);
		lines[l++] = s;
	}
	for (size_t i = 0; i < k->nru; i++) {
		const struct mrule *r = &k->ru[i];

		lines[l] = malloc(128);
		snprintf(lines[l++], 128, "rule f%u p%u prio%u %x/%x t%u", r->family, r->proto,
			 r->prio, r->mark, r->mask, r->table);
	}
	qsort(lines, l, sizeof(*lines), cmp_str);
	for (size_t i = 0; i < l; i++)
		len += strlen(lines[i]) + 1;
	p = out = malloc(len);
	for (size_t i = 0; i < l; i++) {
		p += sprintf(p, "%s\n", lines[i]);
		free(lines[i]);
	}
	*p = '\0';
	free(lines);
	return out;
}

/* --- worlds --- */

#define MAXD 6
#define MAXG 4
#define MAXM 4
#define MAXRULES 4
#define MAXP 64

struct tworld {
	struct config *cfg;	/* NULL = empty world */
	struct ifview ifs[MAXD];
	bool member_up[MAXG * MAXM];
	struct world w;
};

static struct nl nl;

static struct config *cfg_new(void)
{
	struct config *c = calloc(1, sizeof(*c));

	c->fwmask = 0xff000000;
	c->table_id = 100;
	c->rule_prio = 1000;
	c->rt_proto = 233;
	c->nexthop_id = 1000;
	c->probe_mark = 0xfe000000;
	c->devices = calloc(MAXD, sizeof(*c->devices));
	c->groups = calloc(MAXG, sizeof(*c->groups));
	c->rule_group = calloc(MAXRULES, sizeof(*c->rule_group));
	c->p4 = calloc(MAXP, sizeof(*c->p4));
	c->p6 = calloc(MAXP, sizeof(*c->p6));
	for (size_t g = 0; g < MAXG; g++)
		c->groups[g].members = calloc(MAXM, sizeof(struct cfg_member));
	return c;
}

static void cfg_add_group(struct config *c, uint32_t fwmark, uint16_t buckets)
{
	struct cfg_group *g = &c->groups[c->n_groups++];

	g->fwmark = fwmark;
	g->buckets = buckets;
	g->timer_idle = 120;
	g->timer_busy = 600;
}

static void cfg_add_member(struct config *c, size_t g, uint16_t dev, uint16_t weight)
{
	struct cfg_group *grp = &c->groups[g];

	grp->members[grp->n_members++] = (struct cfg_member){ dev, weight };
	if (dev >= c->n_devices)
		c->n_devices = dev + 1;
}

/* A copy sharing nothing, prefix lists included. */
static struct config *cfg_dup(const struct config *o)
{
	struct config *c = cfg_new();
	struct cfg_device *devs = c->devices;
	struct cfg_group *groups = c->groups;
	uint16_t *rg = c->rule_group;
	struct prefix4 *p4 = c->p4;
	struct prefix6 *p6 = c->p6;

	*c = *o;
	c->devices = devs;
	c->groups = groups;
	c->rule_group = rg;
	c->p4 = p4;
	c->p6 = p6;
	memcpy(devs, o->devices, MAXD * sizeof(*devs));
	for (size_t g = 0; g < MAXG; g++) {
		struct cfg_member *m = groups[g].members;

		groups[g] = o->groups[g];
		groups[g].members = m;
		memcpy(m, o->groups[g].members, MAXM * sizeof(*m));
	}
	memcpy(rg, o->rule_group, MAXRULES * sizeof(*rg));
	memcpy(p4, o->p4, MAXP * sizeof(*p4));
	memcpy(p6, o->p6, MAXP * sizeof(*p6));
	return c;
}

/* shared = p4/p6 belong to another config */
static void cfg_free(struct config *c, bool shared)
{
	if (!c)
		return;
	for (size_t g = 0; g < MAXG; g++)
		free(c->groups[g].members);
	free(c->groups);
	free(c->devices);
	free(c->rule_group);
	if (!shared) {
		free(c->p4);
		free(c->p6);
	}
	free(c);
}

static int cmp_p4(const void *a, const void *b)
{
	return memcmp(a, b, 5);
}

static int cmp_p6(const void *a, const void *b)
{
	return memcmp(a, b, 17);
}

/* key k of a fixed pool: v4 10.k.0.0/16 or /24, v6 2001:db8:k::/48 */
static void add_prefix(struct config *c, int f, unsigned k, uint16_t rule)
{
	if (rule >= c->n_rules)
		c->n_rules = rule + 1;
	if (!f) {
		struct prefix4 *p = &c->p4[c->n_p4++];

		*p = (struct prefix4){ { 10, k / 2, 0, 0 }, k % 2 ? 24 : 16, 0, rule };
	} else {
		struct prefix6 *p = &c->p6[c->n_p6++];

		memset(p, 0, sizeof(*p));
		p->addr[0] = 0x20;
		p->addr[1] = 0x01;
		p->addr[2] = 0x0d;
		p->addr[3] = 0xb8;
		p->addr[5] = k;
		p->plen = 48;
		p->rule = rule;
	}
}

static void sort_prefixes(struct config *c)
{
	qsort(c->p4, c->n_p4, sizeof(*c->p4), cmp_p4);
	qsort(c->p6, c->n_p6, sizeof(*c->p6), cmp_p6);
}

static void tw_init(struct tworld *t, struct config *c)
{
	memset(t, 0, sizeof(*t));
	t->cfg = c;
	for (size_t d = 0; d < MAXD; d++)
		for (int f = 0; f < 2; f++) {
			struct ifrender *r = &t->ifs[d].fam[f];

			r->usable = true;
			r->ifindex = d + 1;
			r->has_gw = !(d % 2);
			r->gw[0] = f ? 0xfe : 10;
			r->gw[f ? 15 : 3] = d + 1;	/* within the address, as the kernel sees it */
		}
	for (size_t i = 0; i < MAXG * MAXM; i++)
		t->member_up[i] = true;
}

static const struct world *tw_world(struct tworld *t)
{
	t->w = (struct world){ t->cfg, t->ifs, NULL, t->member_up };
	return &t->w;
}

/* --- the reference --- */

static uint32_t ref_group_nh(struct tworld *t, size_t g, int f)
{
	const struct config *c = t->cfg;
	const struct cfg_group *grp = &c->groups[g];

	for (size_t m = 0; m < grp->n_members && m < MAX_NH_GROUP; m++)
		if (t->ifs[grp->members[m].dev].fam[f].usable &&
		    t->member_up[cfg_member_index(c, g, m)])
			return cfg_group_nhid(c, g, f);
	return 0;
}

static size_t ref_n(const struct config *c, int f)
{
	return f ? c->n_p6 : c->n_p4;
}

static const uint8_t *ref_key(const struct config *c, int f, size_t i, uint16_t *rule)
{
	*rule = f ? c->p6[i].rule : c->p4[i].rule;
	return f ? c->p6[i].addr : c->p4[i].addr;
}

static bool ref_find(const struct config *c, int f, const uint8_t *key, uint16_t *rule)
{
	for (size_t i = 0; i < ref_n(c, f); i++)
		if (!memcmp(ref_key(c, f, i, rule), key, f ? 17 : 5))
			return true;
	return false;
}

static bool recreated(uint32_t id)
{
	for (size_t i = 0; id && i < n_recreated; i++)
		if (nh_recreated[i] == id)
			return true;
	return false;
}

static void ref_push(struct rec *out, size_t *n, char op, const struct config *c, int f,
                     const uint8_t *key, uint32_t nh)
{
	struct rec *r = &out[(*n)++];

	memset(r, 0, sizeof(*r));
	r->op = op;
	r->family = f ? AF_INET6 : AF_INET;
	memcpy(r->dst, key, f ? 16 : 4);
	r->plen = key[f ? 16 : 4];
	r->table = c->table_id;
	r->proto = c->rt_proto;
	if (op == 'S') {
		r->nh_id = nh;
		r->type = nh ? RTN_UNICAST : RTN_BLACKHOLE;
	}
}

/* The prefix requests of old -> new, given what was re-created. */
static size_t ref_diff(struct tworld *o, struct tworld *n, struct rec *out)
{
	const struct config *oc = o->cfg, *nc = n->cfg;
	bool comparable = oc && nc && oc->table_id == nc->table_id && oc->rt_proto == nc->rt_proto;
	size_t cnt = 0;
	uint16_t rule, orule;

	for (int f = 0; nc && f < 2; f++)
		for (size_t j = 0; j < ref_n(nc, f); j++) {
			const uint8_t *key = ref_key(nc, f, j, &rule);
			uint32_t nnh = ref_group_nh(n, nc->rule_group[rule], f);

			if (comparable && ref_find(oc, f, key, &orule) &&
			    ref_group_nh(o, oc->rule_group[orule], f) == nnh && !recreated(nnh))
				continue;
			ref_push(out, &cnt, 'S', nc, f, key, nnh);
		}
	for (int f = 0; oc && f < 2; f++)
		for (size_t i = 0; i < ref_n(oc, f); i++) {
			const uint8_t *key = ref_key(oc, f, i, &orule);

			if (comparable && ref_find(nc, f, key, &rule))
				continue;
			ref_push(out, &cnt, 'D', oc, f, key, 0);
		}
	return cnt;
}

static bool is_prefix_rec(const struct rec *r, const struct config *a, const struct config *b)
{
	/* group and probe tables hold default routes only; the pool has no /0 */
	return r->plen && ((a && r->table == a->table_id) || (b && r->table == b->table_id));
}

static void run(struct kernel *k, struct tworld *o, struct tworld *n, struct sync_stats *st)
{
	K = k;
	nrecs = 0;
	n_failed = n_noop_set = n_msgs = 0;
	n_deleted = n_recreated = 0;
	sync_apply(&nl, tw_world(o), tw_world(n), st);
}

struct result {
	unsigned set, del, msgs;	/* prefix route requests; all requests */
};

static struct kernel k1, k2;
static struct rec want[2 * MAXR];

/* All the checks for old -> new; returns what was sent. */
static struct result check_pair(const char *name, struct tworld *o, struct tworld *n)
{
	struct sync_stats st;
	struct result res = {};
	struct tworld empty;
	char *a, *b;
	size_t nw, got = 0;

	scenario = name;
	tw_init(&empty, NULL);

	/* empty -> new, the reference state */
	memset(&k2, 0, sizeof(k2));
	run(&k2, &empty, n, &st);
	CHECK(!n_failed && !st.errors, "fresh new: %u failed requests", n_failed);
	for (int f = 0; n->cfg && f < 2; f++)
		for (size_t i = 0; i < ref_n(n->cfg, f); i++) {
			uint16_t rule;
			const uint8_t *key = ref_key(n->cfg, f, i, &rule);
			uint32_t nh = ref_group_nh(n, n->cfg->rule_group[rule], f);
			bool found = false;

			for (size_t r = 0; r < k2.nr; r++)
				if (k2.r[r].table == n->cfg->table_id && k2.r[r].family == (f ? AF_INET6 : AF_INET) &&
				    !memcmp(k2.r[r].dst, key, f ? 16 : 4) && k2.r[r].plen == key[f ? 16 : 4]) {
					found = k2.r[r].nh_id == nh &&
						k2.r[r].type == (nh ? RTN_UNICAST : RTN_BLACKHOLE) &&
						k2.r[r].proto == n->cfg->rt_proto;
					break;
				}
			CHECK(found, "fresh new: prefix %zu of family %d not rendered right", i, f);
		}

	/* empty -> old, then old -> new */
	memset(&k1, 0, sizeof(k1));
	run(&k1, &empty, o, &st);
	CHECK(!n_failed && !st.errors, "fresh old: %u failed requests", n_failed);
	run(&k1, o, n, &st);
	CHECK(!n_failed && !st.errors, "old -> new: %u failed requests", n_failed);
	CHECK(!n_noop_set, "old -> new: %u no-op route replaces", n_noop_set);

	a = kernel_text(&k1);
	b = kernel_text(&k2);
	CHECK(!strcmp(a, b), "old -> new differs from a fresh new:\n--- got\n%s--- want\n%s", a, b);
	free(a);
	free(b);

	nw = ref_diff(o, n, want);
	for (size_t i = 0; i < nrecs; i++) {
		if (!is_prefix_rec(&recs[i], o->cfg, n->cfg))
			continue;
		CHECK(got < nw && !memcmp(&recs[i], &want[got], sizeof(recs[i])),
		      "prefix request %zu (%c table %u plen %u nh %u) is not the reference's",
		      got, recs[i].op, recs[i].table, recs[i].plen, recs[i].nh_id);
		if (recs[i].op == 'S')
			res.set++;
		else
			res.del++;
		got++;
	}
	CHECK(got == nw, "%zu prefix requests, the reference has %zu", got, nw);
	CHECK(res.set + res.del <= st.route_set + st.route_del, "stats undercount");
	res.msgs = n_msgs;
	return res;
}

/* --- named scenarios --- */

/*
 * Groups: 0 = devices 0, 1 (fwmark), 1 = device 2 (fwmark, probed),
 * 2 = device 3, no fwmark. Rules: 0 -> group 0, 1 -> group 1, 2 -> group 2.
 * Prefixes (v4 key, rule): 0..5 rule 0, 6..9 rule 1, 10..11 rule 2;
 * v6: 0..2 rule 0, 3 rule 1.
 */
static struct config *base_cfg(void)
{
	struct config *c = cfg_new();

	cfg_add_group(c, 0x01000000, 16);
	cfg_add_member(c, 0, 0, 1);
	cfg_add_member(c, 0, 1, 2);
	cfg_add_group(c, 0x02000000, 16);
	cfg_add_member(c, 1, 2, 1);
	c->groups[1].has_probe[0] = true;
	cfg_add_group(c, 0, 8);
	cfg_add_member(c, 2, 3, 1);
	c->rule_group[0] = 0;
	c->rule_group[1] = 1;
	c->rule_group[2] = 2;
	for (unsigned k = 0; k < 12; k++)
		add_prefix(c, 0, k, k < 6 ? 0 : k < 10 ? 1 : 2);
	for (unsigned k = 0; k < 4; k++)
		add_prefix(c, 1, k, k < 3 ? 0 : 1);
	c->n_rules = 3;
	sort_prefixes(c);
	return c;
}

#define EXPECT(r, s, d) CHECK((r).set == (s) && (r).del == (d), \
	"want %u set %u deleted, got %u, %u", (unsigned)(s), (unsigned)(d), (r).set, (r).del)

static void named(void)
{
	struct config *c = base_cfg(), *c2;
	struct tworld a, b, e;
	struct result r;

	tw_init(&a, c);
	tw_init(&b, c);
	tw_init(&e, NULL);

	r = check_pair("same config, nothing changed", &a, &b);
	EXPECT(r, 0, 0);
	CHECK(r.msgs == 0, "%u requests for nothing", r.msgs);

	b.ifs[1].fam[0].usable = false;
	r = check_pair("same config, a member leaves", &a, &b);
	EXPECT(r, 0, 0);
	CHECK(r.msgs == 2, "want group replace + member delete, got %u requests", r.msgs);

	b.ifs[0].fam[0].usable = false;
	r = check_pair("same config, v4 of group 0 blackholed", &a, &b);
	EXPECT(r, 6, 0);
	r = check_pair("same config, v4 of group 0 back", &b, &a);
	EXPECT(r, 6, 0);

	tw_init(&b, c);
	b.member_up[cfg_member_index(c, 1, 0)] = false;
	r = check_pair("same config, group 1 probed down", &a, &b);
	EXPECT(r, 5, 0);

	/* reload: group 0's buckets change, it is re-created with its routes */
	c2 = cfg_dup(c);
	c2->groups[0].buckets = 32;
	tw_init(&b, c2);
	r = check_pair("reload, buckets changed", &a, &b);
	EXPECT(r, 9, 0);
	cfg_free(c2, false);

	/* reload: rule 1 moves to group 0 */
	c2 = cfg_dup(c);
	c2->rule_group[1] = 0;
	tw_init(&b, c2);
	r = check_pair("reload, rule moved", &a, &b);
	EXPECT(r, 5, 0);
	cfg_free(c2, false);

	/* the same with the lists shared, as across a reload with unchanged lists */
	c2 = cfg_dup(c);
	free(c2->p4);
	free(c2->p6);
	c2->p4 = c->p4;
	c2->p6 = c->p6;
	c2->rule_group[1] = 0;
	tw_init(&b, c2);
	r = check_pair("reload, lists shared, rule moved", &a, &b);
	EXPECT(r, 5, 0);
	c2->rule_group[1] = 1;
	r = check_pair("reload, lists shared, nothing changed", &a, &b);
	EXPECT(r, 0, 0);
	cfg_free(c2, true);

	/* reload: another rule wins a duplicate (v4 key 7 goes from rule 1 to rule 0) */
	c2 = cfg_dup(c);
	for (size_t i = 0; i < c2->n_p4; i++)
		if (c2->p4[i].addr[1] == 3 && c2->p4[i].plen == 24)
			c2->p4[i].rule = 0;
	tw_init(&b, c2);
	r = check_pair("reload, another rule wins a duplicate", &a, &b);
	EXPECT(r, 1, 0);
	cfg_free(c2, false);

	/* reload: one prefix gone, one new */
	c2 = cfg_dup(c);
	c2->p4[0].addr[2] = 99;
	sort_prefixes(c2);
	tw_init(&b, c2);
	r = check_pair("reload, a prefix replaced", &a, &b);
	EXPECT(r, 1, 1);
	cfg_free(c2, false);

	/* reload: table or tag change, not comparable */
	c2 = cfg_dup(c);
	c2->table_id = 500;
	tw_init(&b, c2);
	r = check_pair("reload, table_id changed", &a, &b);
	EXPECT(r, 16, 16);
	c2->table_id = c->table_id;
	c2->rt_proto = 234;
	r = check_pair("reload, rt_proto changed", &a, &b);
	EXPECT(r, 16, 16);
	cfg_free(c2, false);

	r = check_pair("old world empty", &e, &a);
	EXPECT(r, 16, 0);
	r = check_pair("new world empty", &a, &e);
	EXPECT(r, 0, 16);
	r = check_pair("both empty", &e, &e);
	EXPECT(r, 0, 0);

	cfg_free(c, false);
}

/* --- random pairs --- */

static uint64_t rng = 0x9e3779b97f4a7c15ULL;

static unsigned rnd(unsigned n)
{
	rng ^= rng << 13;
	rng ^= rng >> 7;
	rng ^= rng << 17;
	return (rng >> 11) % n;
}

static struct config *random_cfg(void)
{
	struct config *c = cfg_new();
	unsigned ng = 1 + rnd(MAXG), nd = 1 + rnd(MAXD);
	bool used4[MAXP] = {}, used6[MAXP] = {};

	c->table_id = rnd(4) ? 100 : 5000;
	c->rt_proto = rnd(6) ? 233 : 234;
	c->nexthop_id = rnd(6) ? 1000 : 1004;
	for (unsigned g = 0; g < ng; g++) {
		unsigned nm = 1 + rnd(MAXM < nd ? MAXM : nd), first = rnd(nd);

		cfg_add_group(c, rnd(3) ? (g + 1) << 24 : 0, rnd(4) ? 16 : 32);
		c->groups[g].has_probe[0] = !rnd(4);
		c->groups[g].has_probe[1] = !rnd(4);
		for (unsigned m = 0; m < nm; m++)
			cfg_add_member(c, g, (first + m) % nd, 1 + rnd(3));
	}
	c->n_devices = nd;
	c->n_rules = 1 + rnd(MAXRULES);
	for (size_t r = 0; r < c->n_rules; r++)
		c->rule_group[r] = rnd(ng);
	for (unsigned i = 0, n = rnd(40); i < n; i++) {
		unsigned k = rnd(48);

		if (!used4[k]) {
			used4[k] = true;
			add_prefix(c, 0, k, rnd(c->n_rules));
		}
	}
	for (unsigned i = 0, n = rnd(20); i < n; i++) {
		unsigned k = rnd(24);

		if (!used6[k]) {
			used6[k] = true;
			add_prefix(c, 1, k, rnd(c->n_rules));
		}
	}
	sort_prefixes(c);
	return c;
}

static void random_state(struct tworld *t)
{
	for (size_t d = 0; d < MAXD; d++)
		for (int f = 0; f < 2; f++) {
			struct ifrender *r = &t->ifs[d].fam[f];

			r->usable = rnd(4);
			r->has_gw = rnd(2);
			r->ifindex = d + 1 + (rnd(8) ? 0 : 10);
			r->gw[f ? 15 : 3] = rnd(3);
		}
	for (size_t i = 0; i < MAXG * MAXM; i++)
		t->member_up[i] = rnd(5);
}

/* A reload's worth of change, keeping most of it. */
static struct config *mutate(const struct config *o)
{
	struct config *c = cfg_dup(o);

	switch (rnd(6)) {
	case 0:
		c->rule_group[rnd(c->n_rules)] = rnd(c->n_groups);
		break;
	case 1:
		if (c->n_p4)
			c->p4[rnd(c->n_p4)].rule = rnd(c->n_rules);
		break;
	case 2:
		c->groups[rnd(c->n_groups)].buckets ^= 48;
		break;
	case 3:
		if (c->n_p4) {
			size_t i = rnd(c->n_p4);

			c->p4[i] = c->p4[--c->n_p4];
		}
		add_prefix(c, rnd(2), rnd(24), rnd(c->n_rules));
		/* a duplicate key may result: drop it */
		sort_prefixes(c);
		for (size_t i = 1; i < c->n_p4; i++)
			if (!memcmp(&c->p4[i - 1], &c->p4[i], 5))
				memmove(&c->p4[i], &c->p4[i + 1], (--c->n_p4 - i) * sizeof(*c->p4));
		for (size_t i = 1; i < c->n_p6; i++)
			if (!memcmp(&c->p6[i - 1], &c->p6[i], 17))
				memmove(&c->p6[i], &c->p6[i + 1], (--c->n_p6 - i) * sizeof(*c->p6));
		break;
	case 4:
		c->table_id = c->table_id == 100 ? 5000 : 100;
		break;
	case 5:
		c->groups[rnd(c->n_groups)].fwmark ^= 0x80000000;
		break;
	}
	return c;
}

static void random_pairs(unsigned n)
{
	char name[64];

	for (unsigned i = 0; i < n; i++) {
		struct config *c = random_cfg(), *c2 = NULL;
		struct tworld a, b;
		bool shared = false;

		tw_init(&a, c);
		random_state(&a);
		switch (rnd(5)) {
		case 0:	/* an event: same config */
		case 1:
			tw_init(&b, c);
			break;
		case 2:	/* a reload with the lists shared */
			c2 = cfg_dup(c);
			free(c2->p4);
			free(c2->p6);
			c2->p4 = c->p4;
			c2->p6 = c->p6;
			shared = true;
			if (rnd(2))
				c2->rule_group[rnd(c2->n_rules)] = rnd(c2->n_groups);
			if (rnd(3))
				c2->groups[rnd(c2->n_groups)].buckets ^= 48;
			tw_init(&b, c2);
			break;
		case 3:	/* a reload */
			c2 = mutate(c);
			tw_init(&b, c2);
			break;
		default:	/* an unrelated config */
			c2 = random_cfg();
			tw_init(&b, c2);
			break;
		}
		random_state(&b);
		if (rnd(3))	/* mostly small changes */
			memcpy(b.ifs, a.ifs, sizeof(a.ifs));
		snprintf(name, sizeof(name), "random pair %u", i);
		check_pair(name, &a, &b);
		cfg_free(c2, shared);
		cfg_free(c, false);
		if (fails)
			break;
	}
}

int main(void)
{
	if (nl_open(&nl))
		return 2;
	named();
	if (!fails)
		random_pairs(3000);
	nl_close(&nl);
	if (fails) {
		fprintf(stderr, "test_sync: %u checks failed\n", fails);
		return 1;
	}
	printf("test_sync: ok\n");
	return 0;
}
