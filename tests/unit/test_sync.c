/*
 * sync_apply against a model of the kernel, which is the state it observes.
 *
 * nl.c talks to the model instead of the kernel: mnl_socket_sendto,
 * mnl_socket_recvfrom and recv are defined here, and an executable's
 * definition wins over the shared library's. Write batches are applied one
 * message at a time with the kernel's semantics, and errors are queued as
 * NLMSG_ERROR replies (requests go without NLM_F_ACK: only errors come
 * back). Dump requests are answered from the model in the kernel's format
 * (checked against a 6.18 kernel: attribute order, compat nexthop details,
 * v6 metric 1024 and cacheinfo, routes on a blackholed group reported as
 * RTN_BLACKHOLE with RTA_NH_ID, groups as AF_UNSPEC with their resilient
 * attributes nested, timers in USER_HZ, datagrams cut where the kernel
 * cuts them, NLMSG_DONE on its own after route dumps).
 *
 * Modelled: nexthops (a delete takes the routes on it, drops it from its
 * groups and deletes the groups it empties, with their routes; a blackhole
 * only alone in a group; replace can't change a group's buckets, nor a group
 * into a single nexthop or back, nor turn a nexthop v6 routes use into v4;
 * groups can't nest, members must exist), routes (keyed by family, table,
 * dst, tos, v6 source, metric, proto ignored; NLM_F_REPLACE replaces by key;
 * deletes match proto and type when given, metric 0 = the lowest; tables
 * exist once used; routes need their nexthop, of their own family), rules
 * (NLM_F_EXCL against an identical rule, proto included; deletes match what
 * they give, mark 0 matching any mark; ordered by priority then age), and
 * what the kernel does behind routebot's back (link flushes, the last v4
 * address going, nexthops deleted, foreign objects).
 *
 * Not modelled: devices (any ifindex is accepted; down devices, unreachable
 * gateways, carrier), v4 routes over v6 nexthops (refused here: routebot
 * never means them), duplicate routes under one key (v4 aliases, v6
 * siblings), non-resilient groups, notifications.
 *
 * Every step brings the model from one world to the next: named scenarios,
 * then random runs over random configs and worlds, the model perturbed in
 * between and in the middle of an apply. Checked for every step:
 *   - a fresh install of the world equals an independent rendering of it
 *   - the result equals the fresh install, foreign objects untouched
 *   - without a perturbation during the apply, it returns 0 and no request
 *     fails (expected ENOENT/ESRCH/EEXIST counted and reported); after a
 *     failure a full sync repairs it, after a race the next sync does
 *   - after every single message: every prefix of both worlds' same group
 *     resolves (rules, fwmark, longest prefix, metric, nexthop, members) to
 *     a blackhole or that group's devices, never to nothing or another
 *     group's device (a prefix of one world only may be absent, i.e. fall
 *     to main or a covering prefix); marked traffic of a group likewise; no
 *     prefix route routebot wants goes with a nexthop routebot deletes.
 *     What already failed before the apply isn't held against it, nor what
 *     breaks after a race hit (the rest of the batch was planned on a stale
 *     dump): that is counted and logged, and the next sync must repair it
 *   - nothing sent when nothing changed, no prefix route sent for member
 *     changes, no route sent by a full sync of an intact kernel
 */
#include <arpa/inet.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <linux/fib_rules.h>
#include <linux/nexthop.h>
#include <linux/rtnetlink.h>

#include "log.h"
#include "sync.h"

int log_level = L_WARN;

const char *__ubsan_default_options(void);
const char *__ubsan_default_options(void)
{
	return "halt_on_error=1:print_stacktrace=1";
}

/* --- reporting --- */

#define LOGBUF (64 * 1024)

static char logbuf[LOGBUF];	/* routebot's log during the current step */
static size_t loglen;
static char msglog[256 * 1024];	/* the requests of the current step */
static size_t msglen;

static void buf_add(char *buf, size_t *len, size_t cap, const char *fmt, va_list ap)
{
	int n;

	if (*len + 2 >= cap)
		return;
	n = vsnprintf(buf + *len, cap - *len, fmt, ap);
	if (n < 0)
		return;
	*len += (size_t)n < cap - *len ? (size_t)n : cap - *len - 1;
}

void log_msg(int level, const char *fmt, ...)
{
	va_list ap;
	char line[16];

	if (level > log_level)
		return;
	snprintf(line, sizeof(line), "  log %d: ", level);
	va_start(ap, fmt);
	if (loglen + sizeof(line) < LOGBUF) {
		memcpy(logbuf + loglen, line, strlen(line));
		loglen += strlen(line);
	}
	buf_add(logbuf, &loglen, LOGBUF, fmt, ap);
	va_end(ap);
	if (loglen + 1 < LOGBUF)
		logbuf[loglen++] = '\n';
	logbuf[loglen] = '\0';
}

static void mlog(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void mlog(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	buf_add(msglog, &msglen, sizeof(msglog), fmt, ap);
	va_end(ap);
}

static unsigned fails, step_fails, reports;
static char scenario[96];
static unsigned step_no;
static uint64_t seed;
static const char *step_what = "";

static unsigned max_reports = 6;	/* TEST_SYNC_REPORTS */
#define MAX_REPORTS max_reports

static void fail(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void fail(const char *fmt, ...)
{
	va_list ap;

	fails++;
	if (!step_fails++) {
		reports++;
		if (reports > MAX_REPORTS)
			fprintf(stderr, "FAIL [%s] step %u (seed %#llx): %s (details skipped)\n",
			        scenario, step_no, (unsigned long long)seed, step_what);
		else
			fprintf(stderr, "\nFAIL [%s] step %u (seed %#llx): %s\n", scenario, step_no,
			        (unsigned long long)seed, step_what);
	}
	if (reports > MAX_REPORTS || step_fails > 12)
		return;
	fprintf(stderr, "  - ");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

#define CHECK(cond, ...) do { if (!(cond)) fail(__VA_ARGS__); } while (0)

static uint64_t rng;

static unsigned rnd(unsigned n)
{
	rng ^= rng << 13;
	rng ^= rng >> 7;
	rng ^= rng << 17;
	return (rng >> 11) % n;
}

static bool chance(unsigned pct)
{
	return rnd(100) < pct;
}

/* --- the kernel model --- */

#define MAXR 4096
#define NBUCKET 1024
#define MAXNH 512
#define MAXRU 128
#define MAXT 64

#define PROTO_A 233	/* the rt_protos configs use */
#define PROTO_B 234
#define PROTO_FOREIGN 4	/* RTPROT_STATIC */

static bool ours(uint8_t proto)
{
	return proto == PROTO_A || proto == PROTO_B;
}

struct mroute {
	bool used;
	uint8_t family, dst_len, src_len, tos, type, proto, scope;
	bool has_gw;
	uint32_t table, metric, nh_id;
	int oif;
	uint8_t dst[16], src[16], gw[16];
	int next;		/* hash chain or free list, slot + 1 */
};

struct mnh {
	uint32_t id;
	bool group, blackhole;
	uint8_t family, proto;
	int oif;
	bool has_gw;
	uint8_t gw[16];
	uint16_t n, buckets;
	uint32_t ids[MAX_NH_GROUP];
	uint16_t weights[MAX_NH_GROUP];	/* 1..256 */
	uint32_t idle, busy;		/* clock_t, as sent */
};

struct mrule {
	uint8_t family, proto;
	uint32_t prio, mark, mask, table;
};

/* rule lists in dump order: v4, ipmr, ip6mr, v6 */
static const uint8_t rule_fams[4] = { AF_INET, RTNL_FAMILY_IPMR, RTNL_FAMILY_IP6MR, AF_INET6 };

struct kernel {
	struct mroute r[MAXR];
	int bucket[NBUCKET];	/* slot + 1 */
	int free_head;		/* slot + 1 */
	size_t n_routes;
	unsigned plens[2][129];
	struct mnh nh[MAXNH];	/* by id */
	size_t nnh;
	struct mrule ru[4][MAXRU];
	size_t nru[4];
	uint32_t tables[2][MAXT];
	size_t ntables[2];
};

static int fi(int family)
{
	return family == AF_INET6;
}

static size_t alen_of(int family)
{
	return family == AF_INET6 ? 16 : 4;
}

static void k_init(struct kernel *k)
{
	memset(k, 0, sizeof(*k));
	for (int i = 0; i < MAXR; i++)
		k->r[i].next = i + 2 <= MAXR ? i + 2 : 0;
	k->free_head = 1;
	for (int f = 0; f < 2; f++) {
		k->tables[f][k->ntables[f]++] = RT_TABLE_MAIN;
		k->tables[f][k->ntables[f]++] = RT_TABLE_LOCAL;
	}
	/* the kernel's own rules, as a fresh netns dumps them */
	k->ru[0][k->nru[0]++] = (struct mrule){ AF_INET, RTPROT_KERNEL, 0, 0, 0, RT_TABLE_LOCAL };
	k->ru[0][k->nru[0]++] = (struct mrule){ AF_INET, RTPROT_KERNEL, 32766, 0, 0, RT_TABLE_MAIN };
	k->ru[0][k->nru[0]++] = (struct mrule){ AF_INET, RTPROT_KERNEL, 32767, 0, 0, RT_TABLE_DEFAULT };
	k->ru[1][k->nru[1]++] = (struct mrule){ RTNL_FAMILY_IPMR, RTPROT_KERNEL, 32767, 0, 0,
	                                        RT_TABLE_DEFAULT };
	k->ru[2][k->nru[2]++] = (struct mrule){ RTNL_FAMILY_IP6MR, RTPROT_KERNEL, 32767, 0, 0,
	                                        RT_TABLE_MAIN };
	k->ru[3][k->nru[3]++] = (struct mrule){ AF_INET6, RTPROT_KERNEL, 0, 0, 0, RT_TABLE_LOCAL };
	k->ru[3][k->nru[3]++] = (struct mrule){ AF_INET6, RTPROT_KERNEL, 32766, 0, 0, RT_TABLE_MAIN };
}

static bool table_exists(const struct kernel *k, int family, uint32_t t)
{
	for (size_t i = 0; i < k->ntables[fi(family)]; i++)
		if (k->tables[fi(family)][i] == t)
			return true;
	return false;
}

static void table_add(struct kernel *k, int family, uint32_t t)
{
	if (!table_exists(k, family, t) && k->ntables[fi(family)] < MAXT)
		k->tables[fi(family)][k->ntables[fi(family)]++] = t;
}

static unsigned rhash(int family, uint32_t table, uint8_t plen, const uint8_t *dst)
{
	uint32_t h = 2166136261u ^ family ^ (table * 31) ^ (plen * 131u);

	for (size_t i = 0; i < alen_of(family); i++)
		h = (h ^ dst[i]) * 16777619u;
	return h % NBUCKET;
}

static bool rkey_eq(const struct mroute *a, const struct mroute *b)
{
	return a->family == b->family && a->table == b->table && a->dst_len == b->dst_len &&
	       !memcmp(a->dst, b->dst, 16) && a->tos == b->tos && a->src_len == b->src_len &&
	       !memcmp(a->src, b->src, 16) && a->metric == b->metric;
}

static int r_find(const struct kernel *k, const struct mroute *key)
{
	for (int s = k->bucket[rhash(key->family, key->table, key->dst_len, key->dst)]; s;
	     s = k->r[s - 1].next)
		if (rkey_eq(&k->r[s - 1], key))
			return s - 1;
	return -1;
}

static bool r_insert(struct kernel *k, const struct mroute *r)
{
	unsigned b = rhash(r->family, r->table, r->dst_len, r->dst);
	int s = k->free_head;

	if (!s)
		return false;
	k->free_head = k->r[s - 1].next;
	k->r[s - 1] = *r;
	k->r[s - 1].used = true;
	k->r[s - 1].next = k->bucket[b];
	k->bucket[b] = s;
	k->n_routes++;
	k->plens[fi(r->family)][r->dst_len]++;
	return true;
}

static void r_remove(struct kernel *k, int slot)
{
	struct mroute *r = &k->r[slot];
	int *p = &k->bucket[rhash(r->family, r->table, r->dst_len, r->dst)];

	while (*p != slot + 1)
		p = &k->r[*p - 1].next;
	*p = r->next;
	k->plens[fi(r->family)][r->dst_len]--;
	k->n_routes--;
	memset(r, 0, sizeof(*r));
	r->next = k->free_head;
	k->free_head = slot + 1;
}

static struct mnh *nh_get(struct kernel *k, uint32_t id)
{
	size_t lo = 0, hi = k->nnh;

	while (lo < hi) {
		size_t mid = (lo + hi) / 2;

		if (k->nh[mid].id == id)
			return &k->nh[mid];
		if (k->nh[mid].id < id)
			lo = mid + 1;
		else
			hi = mid;
	}
	return NULL;
}

static bool nh_insert(struct kernel *k, const struct mnh *n)
{
	size_t i = k->nnh;

	if (k->nnh == MAXNH)
		return false;
	while (i && k->nh[i - 1].id > n->id) {
		k->nh[i] = k->nh[i - 1];
		i--;
	}
	k->nh[i] = *n;
	k->nnh++;
	return true;
}

/* Who is deleting: routebot (during an apply) or the kernel on its own. */
enum cause { BY_KERNEL, BY_ROUTEBOT };

static void note_route_gone(const struct mroute *r, enum cause c);

static void routes_drop_nh(struct kernel *k, uint32_t id, enum cause c)
{
	for (int i = 0; i < MAXR; i++)
		if (k->r[i].used && k->r[i].nh_id == id) {
			note_route_gone(&k->r[i], c);
			r_remove(k, i);
		}
}

/* Delete a nexthop as the kernel does: routes on it, then the groups it empties. */
static void nh_remove(struct kernel *k, uint32_t id, enum cause c)
{
	struct mnh *n = nh_get(k, id);
	uint32_t emptied[MAXNH];
	size_t ne = 0;

	if (!n)
		return;
	memmove(n, n + 1, (k->nh + --k->nnh - n) * sizeof(*n));
	routes_drop_nh(k, id, c);
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
		if (w != g->n && !w)
			emptied[ne++] = g->id;
		g->n = w;
	}
	for (size_t i = 0; i < ne; i++)
		nh_remove(k, emptied[i], c);
}

/* A link goes down (or flaps): its nexthops go, and the plain routes on it. */
static void link_flush(struct kernel *k, int ifindex)
{
	for (size_t i = 0; i < k->nnh;) {
		if (!k->nh[i].group && !k->nh[i].blackhole && k->nh[i].oif == ifindex) {
			nh_remove(k, k->nh[i].id, BY_KERNEL);
			i = 0;
			continue;
		}
		i++;
	}
	for (int i = 0; i < MAXR; i++)
		if (k->r[i].used && !k->r[i].nh_id && k->r[i].type == RTN_UNICAST &&
		    k->r[i].oif == ifindex) {
			note_route_gone(&k->r[i], BY_KERNEL);
			r_remove(k, i);
		}
}

/* The last v4 address of ifindex goes: plain v4 routes on it, nothing else. */
static void addr4_flush(struct kernel *k, int ifindex)
{
	for (int i = 0; i < MAXR; i++)
		if (k->r[i].used && k->r[i].family == AF_INET && !k->r[i].nh_id &&
		    k->r[i].type == RTN_UNICAST && k->r[i].oif == ifindex)
			r_remove(k, i);
}

/* The single nexthops behind id: itself, or a group's members. */
static size_t nh_paths(struct kernel *k, const struct mnh *n, const struct mnh **out)
{
	size_t c = 0;

	if (!n->group) {
		out[c++] = n;
		return c;
	}
	for (uint16_t j = 0; j < n->n; j++) {
		const struct mnh *m = nh_get(k, n->ids[j]);

		if (m)
			out[c++] = m;
	}
	return c;
}

static bool nh_is_blackhole(struct kernel *k, const struct mnh *n)
{
	const struct mnh *p[MAX_NH_GROUP];
	size_t c = nh_paths(k, n, p);

	return c == 1 && p[0]->blackhole;
}

/* The type a dump reports: the kernel looks through the nexthop. */
static uint8_t route_type(struct kernel *k, const struct mroute *r)
{
	const struct mnh *n;

	if (!r->nh_id || !(n = nh_get(k, r->nh_id)))
		return r->type;
	return nh_is_blackhole(k, n) ? RTN_BLACKHOLE : r->type;
}

/* Is nexthop id used by a v6 route, directly or through a group? */
static bool nh_used_by_v6(struct kernel *k, uint32_t id)
{
	for (int i = 0; i < MAXR; i++) {
		const struct mroute *r = &k->r[i];
		const struct mnh *n;

		if (!r->used || r->family != AF_INET6 || !r->nh_id)
			continue;
		if (r->nh_id == id)
			return true;
		n = nh_get(k, r->nh_id);
		for (uint16_t j = 0; n && n->group && j < n->n; j++)
			if (n->ids[j] == id)
				return true;
	}
	return false;
}

/* --- requests: what the kernel does with them --- */

struct attrs {
	const struct nlattr *tb[64];
	bool other;
};

static int attrs_cb(const struct nlattr *a, void *data)
{
	struct attrs *t = data;

	if (mnl_attr_get_type(a) < 64)
		t->tb[mnl_attr_get_type(a)] = a;
	else
		t->other = true;
	return MNL_CB_OK;
}

static bool attr_u32(const struct attrs *t, int type, uint32_t *v)
{
	if (!t->tb[type])
		return false;
	*v = mnl_attr_get_u32(t->tb[type]);
	return true;
}

static struct kernel *K;	/* where requests go */
static const char *why;		/* why the last request failed */

/*
 * What the devices make the kernel refuse, by family and ifindex: member
 * nexthops (IPv6 disabled, a pinned gateway not on-link) and plain routes
 * through them (the probe routes). A device starts refusing as it comes
 * back from a flap: it never holds what it refuses.
 */
static uint64_t refuse[2];
static struct sync *S;		/* the sync under test */
static bool refused;		/* the last request failed for that */

static bool refusing(int family, int oif, const uint64_t *mask)
{
	return oif > 0 && oif < 64 && (mask[family == AF_INET6] >> oif & 1);
}

#define REFUSE(err, msg) do { why = (msg); return (err); } while (0)

/* Only these attributes, each of the right size. */
static bool attrs_only(const struct attrs *t, const int *ok, size_t n)
{
	if (t->other)
		return false;
	for (int i = 0; i < 64; i++) {
		bool found = false;

		if (!t->tb[i])
			continue;
		for (size_t j = 0; j < n; j++)
			found = found || ok[j] == i;
		if (!found)
			return false;
	}
	return true;
}

static void test_bug(const char *what);

static int apply_route(const struct nlmsghdr *nlh)
{
	static const int ok[] = { RTA_TABLE, RTA_DST, RTA_SRC, RTA_PRIORITY, RTA_NH_ID, RTA_OIF,
	                          RTA_GATEWAY };
	const struct rtmsg *rtm = mnl_nlmsg_get_payload(nlh);
	struct attrs t = {};
	struct mroute r = {};
	size_t alen;
	uint32_t v;
	int slot;

	if (mnl_attr_parse(nlh, sizeof(*rtm), attrs_cb, &t) < 0)
		REFUSE(EINVAL, "malformed");
	if (!attrs_only(&t, ok, sizeof(ok) / sizeof(ok[0]))) {
		test_bug("route request with an attribute the model doesn't know");
		REFUSE(EOPNOTSUPP, "unknown attribute");
	}
	if (rtm->rtm_family != AF_INET && rtm->rtm_family != AF_INET6)
		REFUSE(EAFNOSUPPORT, "family");
	alen = alen_of(rtm->rtm_family);
	r.family = rtm->rtm_family;
	r.dst_len = rtm->rtm_dst_len;
	r.src_len = rtm->rtm_src_len;
	r.tos = rtm->rtm_tos;
	r.proto = rtm->rtm_protocol;
	r.type = rtm->rtm_type;
	r.scope = r.family == AF_INET ? rtm->rtm_scope : RT_SCOPE_UNIVERSE;
	r.table = rtm->rtm_table;
	attr_u32(&t, RTA_TABLE, &r.table);
	attr_u32(&t, RTA_PRIORITY, &r.metric);
	attr_u32(&t, RTA_NH_ID, &r.nh_id);
	if (attr_u32(&t, RTA_OIF, &v))
		r.oif = v;
	if (!r.table) {
		test_bug("route request without a table");
		REFUSE(EINVAL, "no table");
	}
	if (r.dst_len > alen * 8 || r.src_len > alen * 8 || (r.tos && r.family != AF_INET) ||
	    (r.src_len && r.family != AF_INET6))
		REFUSE(EINVAL, "bad header");
	if (t.tb[RTA_DST]) {
		if (mnl_attr_get_payload_len(t.tb[RTA_DST]) != alen)
			REFUSE(EINVAL, "RTA_DST size");
		memcpy(r.dst, mnl_attr_get_payload(t.tb[RTA_DST]), alen);
	}
	if (t.tb[RTA_SRC]) {
		if (mnl_attr_get_payload_len(t.tb[RTA_SRC]) != alen)
			REFUSE(EINVAL, "RTA_SRC size");
		memcpy(r.src, mnl_attr_get_payload(t.tb[RTA_SRC]), alen);
	}
	if (t.tb[RTA_GATEWAY]) {
		if (mnl_attr_get_payload_len(t.tb[RTA_GATEWAY]) != alen)
			REFUSE(EINVAL, "RTA_GATEWAY size");
		r.has_gw = true;
		memcpy(r.gw, mnl_attr_get_payload(t.tb[RTA_GATEWAY]), alen);
	}
	for (size_t i = 0; i < alen * 8; i++) {
		bool bit = r.dst[i / 8] & (0x80 >> (i % 8));

		if (i >= r.dst_len && bit)
			REFUSE(EINVAL, "invalid prefix for given prefix length");
	}
	if (r.family == AF_INET6 && !r.metric)
		r.metric = 1024;

	if (nlh->nlmsg_type == RTM_DELROUTE) {
		int best = -1;

		if (t.tb[RTA_OIF] || t.tb[RTA_GATEWAY] || t.tb[RTA_NH_ID]) {
			test_bug("route delete with nexthop details");
			REFUSE(EOPNOTSUPP, "unmodelled delete");
		}
		if (!table_exists(K, r.family, r.table))
			REFUSE(ESRCH, "FIB table does not exist");
		if (r.family == AF_INET6 && !t.tb[RTA_PRIORITY])
			r.metric = 0;
		for (int i = 0; i < MAXR; i++) {
			const struct mroute *o = &K->r[i];

			if (!o->used || o->family != r.family || o->table != r.table ||
			    o->dst_len != r.dst_len || memcmp(o->dst, r.dst, 16) || o->tos != r.tos ||
			    o->src_len != r.src_len || memcmp(o->src, r.src, 16) ||
			    (r.metric && o->metric != r.metric) || (r.proto && o->proto != r.proto) ||
			    (r.type && o->type != r.type))
				continue;
			if (best < 0 || o->metric < K->r[best].metric)
				best = i;
		}
		if (best < 0)
			REFUSE(ESRCH, "no such route");
		r_remove(K, best);
		return 0;
	}

	if (r.family == AF_INET)
		table_add(K, AF_INET, r.table);
	if (r.type == RTN_UNICAST) {
		if (!r.nh_id == !r.oif)
			REFUSE(EINVAL, "unicast route needs a nexthop id or a device, not both");
		if (r.nh_id) {
			struct mnh *n = nh_get(K, r.nh_id);
			const struct mnh *p[MAX_NH_GROUP];
			size_t c;

			if (r.has_gw)
				REFUSE(EINVAL, "nexthop id and gateway");
			if (!n)
				REFUSE(EINVAL, "Nexthop id does not exist");
			if (r.src_len)
				REFUSE(EINVAL, "Nexthops can not be used with source routing");
			c = nh_paths(K, n, p);
			for (size_t i = 0; i < c; i++)
				if (p[i]->family != r.family)
					REFUSE(EINVAL, r.family == AF_INET6 ?
					       "IPv6 routes can not use an IPv4 nexthop" :
					       "model: v4 route over a v6 nexthop");
		}
		if (!r.nh_id && refusing(r.family, r.oif, refuse)) {
			refused = true;
			REFUSE(r.family == AF_INET6 ? EACCES : ENETUNREACH,
			       "model: the device refuses routes");
		}
	} else if (r.type == RTN_BLACKHOLE) {
		if (r.nh_id || r.oif || r.has_gw)
			REFUSE(EINVAL, "blackhole with a nexthop");
	} else {
		test_bug("route type the model doesn't know");
		REFUSE(EOPNOTSUPP, "route type");
	}

	slot = r_find(K, &r);
	if (slot >= 0) {
		if (!(nlh->nlmsg_flags & NLM_F_REPLACE)) {
			if (nlh->nlmsg_flags & NLM_F_EXCL)
				REFUSE(EEXIST, "route exists");
			test_bug("route add over an existing key without NLM_F_REPLACE");
			REFUSE(EOPNOTSUPP, "duplicate route");
		}
		r.used = true;
		r.next = K->r[slot].next;
		K->r[slot] = r;
	} else {
		if (!(nlh->nlmsg_flags & NLM_F_CREATE))
			REFUSE(ENOENT, "no route to replace");
		if (!r_insert(K, &r)) {
			test_bug("model out of route slots");
			REFUSE(ENOBUFS, "full");
		}
	}
	table_add(K, r.family, r.table);
	return 0;
}

static int apply_nexthop(const struct nlmsghdr *nlh)
{
	static const int ok[] = { NHA_ID, NHA_GROUP, NHA_GROUP_TYPE, NHA_BLACKHOLE, NHA_OIF,
	                          NHA_GATEWAY, NHA_RES_GROUP };
	const struct nhmsg *nhm = mnl_nlmsg_get_payload(nlh);
	struct attrs t = {};
	struct mnh n = {}, *o;

	if (mnl_attr_parse(nlh, sizeof(*nhm), attrs_cb, &t) < 0)
		REFUSE(EINVAL, "malformed");
	if (!attrs_only(&t, ok, sizeof(ok) / sizeof(ok[0]))) {
		test_bug("nexthop request with an attribute the model doesn't know");
		REFUSE(EOPNOTSUPP, "unknown attribute");
	}
	if (!attr_u32(&t, NHA_ID, &n.id) || !n.id) {
		test_bug("nexthop request without an id");
		REFUSE(EINVAL, "no id");
	}
	o = nh_get(K, n.id);

	if (nlh->nlmsg_type == RTM_DELNEXTHOP) {
		if (nhm->nh_family || nhm->nh_protocol || nhm->nh_scope || nhm->resvd ||
		    nhm->nh_flags)
			REFUSE(EINVAL, "Invalid values in header for nexthop get/del request");
		if (!o)
			REFUSE(ENOENT, "no such nexthop");
		nh_remove(K, n.id, BY_ROUTEBOT);
		return 0;
	}

	n.proto = nhm->nh_protocol;
	if (t.tb[NHA_GROUP]) {
		const struct nexthop_grp *g = mnl_attr_get_payload(t.tb[NHA_GROUP]);
		size_t len = mnl_attr_get_payload_len(t.tb[NHA_GROUP]);
		struct attrs rt = {};
		uint16_t type = t.tb[NHA_GROUP_TYPE] ? mnl_attr_get_u16(t.tb[NHA_GROUP_TYPE]) : 0;

		if (nhm->nh_family != AF_UNSPEC)
			REFUSE(EINVAL, "Invalid family for group");
		if (t.tb[NHA_BLACKHOLE] || t.tb[NHA_OIF] || t.tb[NHA_GATEWAY])
			REFUSE(EINVAL, "No other attributes can be set in nexthop groups");
		if (type != NEXTHOP_GRP_TYPE_RES) {
			test_bug("non-resilient group");
			REFUSE(EOPNOTSUPP, "group type");
		}
		if (!len || len % sizeof(*g) || len / sizeof(*g) > MAX_NH_GROUP)
			REFUSE(EINVAL, "Invalid length for nexthop group attribute");
		n.group = true;
		n.n = len / sizeof(*g);
		for (uint16_t i = 0; i < n.n; i++) {
			const struct mnh *m = nh_get(K, g[i].id);

			if (g[i].resvd2)
				REFUSE(EINVAL, "Reserved fields in nexthop_grp must be 0");
			if (!m)
				REFUSE(EINVAL, "Invalid nexthop id");
			if (m->group)
				REFUSE(EINVAL, "Multipath group can not be a nexthop within a group");
			if (m->blackhole && n.n > 1)
				REFUSE(EINVAL, "Blackhole nexthop can not be used in a group with more than 1 path");
			for (uint16_t j = 0; j < i; j++)
				if (n.ids[j] == g[i].id)
					REFUSE(EINVAL, "Duplicate nexthop id in group");
			n.ids[i] = g[i].id;
			n.weights[i] = (g[i].weight | g[i].weight_high << 8) + 1;
		}
		if (t.tb[NHA_RES_GROUP] &&
		    mnl_attr_parse_nested(t.tb[NHA_RES_GROUP], attrs_cb, &rt) < 0)
			REFUSE(EINVAL, "malformed NHA_RES_GROUP");
		if (rt.tb[NHA_RES_GROUP_BUCKETS])
			n.buckets = mnl_attr_get_u16(rt.tb[NHA_RES_GROUP_BUCKETS]);
		else if (o && o->group)
			n.buckets = o->buckets;
		else
			REFUSE(EINVAL, "Number of buckets not specified for nexthop group insertion");
		if (!n.buckets)
			REFUSE(EINVAL, "Number of buckets must be greater than zero");
		n.idle = o && o->group ? o->idle : 120 * 100;
		n.busy = o && o->group ? o->busy : 0;
		attr_u32(&rt, NHA_RES_GROUP_IDLE_TIMER, &n.idle);
		attr_u32(&rt, NHA_RES_GROUP_UNBALANCED_TIMER, &n.busy);
		if (o) {
			if (!o->group)
				REFUSE(EINVAL, "Can not replace a nexthop with a nexthop group");
			if (o->buckets != n.buckets)
				REFUSE(EINVAL, "Can not change number of buckets of a resilient nexthop group");
			for (uint16_t i = 0; i < n.n; i++)
				if (nh_get(K, n.ids[i])->family != AF_INET6 && nh_used_by_v6(K, n.id))
					REFUSE(EINVAL, "IPv6 routes can not use an IPv4 nexthop");
		}
	} else {
		n.family = nhm->nh_family;
		if (n.family != AF_INET && n.family != AF_INET6)
			REFUSE(EINVAL, "Invalid address family");
		if (t.tb[NHA_GROUP_TYPE] || t.tb[NHA_RES_GROUP])
			REFUSE(EINVAL, "group attributes without a group");
		if (t.tb[NHA_BLACKHOLE]) {
			if (t.tb[NHA_OIF] || t.tb[NHA_GATEWAY])
				REFUSE(EINVAL, "Blackhole attribute can not be used with gateway or oif");
			n.blackhole = true;
		} else {
			uint32_t oif = 0;

			if (!attr_u32(&t, NHA_OIF, &oif) || !oif)
				REFUSE(EINVAL, "Device attribute required for non-blackhole and non-fdb nexthops");
			n.oif = oif;
			if (t.tb[NHA_GATEWAY]) {
				if (mnl_attr_get_payload_len(t.tb[NHA_GATEWAY]) != alen_of(n.family))
					REFUSE(EINVAL, "Invalid gateway address");
				n.has_gw = true;
				memcpy(n.gw, mnl_attr_get_payload(t.tb[NHA_GATEWAY]), alen_of(n.family));
			}
			if (refusing(n.family, n.oif, refuse)) {
				refused = true;
				REFUSE(n.family == AF_INET6 ? EINVAL : ENETUNREACH,
				       "model: the device refuses nexthops");
			}
		}
		if (o) {
			if (o->group)
				REFUSE(EINVAL, "Can not replace a nexthop group with a nexthop");
			if (n.blackhole)
				for (size_t i = 0; i < K->nnh; i++) {
					const struct mnh *g = &K->nh[i];

					for (uint16_t j = 0; g->group && g->n > 1 && j < g->n; j++)
						if (g->ids[j] == n.id)
							REFUSE(EINVAL, "Blackhole nexthop can not be a member of a group with more than one path");
				}
			if (n.family == AF_INET && o->family == AF_INET6 && nh_used_by_v6(K, n.id))
				REFUSE(EINVAL, "IPv6 routes can not use an IPv4 nexthop");
		}
	}

	if (o) {
		if (!(nlh->nlmsg_flags & NLM_F_REPLACE))
			REFUSE(EEXIST, "Nexthop id already exists");
		*o = n;
		return 0;
	}
	if (!(nlh->nlmsg_flags & NLM_F_CREATE))
		REFUSE(ENOENT, "Nexthop not found");
	if (!nh_insert(K, &n)) {
		test_bug("model out of nexthop slots");
		REFUSE(ENOBUFS, "full");
	}
	return 0;
}

static int rule_list(int family)
{
	return family == AF_INET6 ? 3 : 0;
}

static bool rule_insert(struct kernel *k, const struct mrule *r)
{
	int l = rule_list(r->family);
	size_t i = k->nru[l];

	if (i == MAXRU)
		return false;
	/* after every rule of the same or a lower priority */
	while (i && k->ru[l][i - 1].prio > r->prio) {
		k->ru[l][i] = k->ru[l][i - 1];
		i--;
	}
	k->ru[l][i] = *r;
	k->nru[l]++;
	return true;
}

static void rule_remove(struct kernel *k, int l, size_t i)
{
	memmove(&k->ru[l][i], &k->ru[l][i + 1], (--k->nru[l] - i) * sizeof(k->ru[l][0]));
}

static int apply_rule(const struct nlmsghdr *nlh)
{
	static const int ok[] = { FRA_PRIORITY, FRA_FWMARK, FRA_FWMASK, FRA_TABLE, FRA_PROTOCOL };
	const struct fib_rule_hdr *frh = mnl_nlmsg_get_payload(nlh);
	struct attrs t = {};
	struct mrule r = {};
	bool has_mark, has_mask;
	int l;

	if (mnl_attr_parse(nlh, sizeof(*frh), attrs_cb, &t) < 0)
		REFUSE(EINVAL, "malformed");
	if (!attrs_only(&t, ok, sizeof(ok) / sizeof(ok[0])) || frh->dst_len || frh->src_len ||
	    frh->tos || frh->flags || frh->action != FR_ACT_TO_TBL) {
		test_bug("rule request the model doesn't know");
		REFUSE(EOPNOTSUPP, "unmodelled rule");
	}
	if (frh->family != AF_INET && frh->family != AF_INET6)
		REFUSE(EAFNOSUPPORT, "family");
	l = rule_list(frh->family);
	r.family = frh->family;
	r.proto = t.tb[FRA_PROTOCOL] ? mnl_attr_get_u8(t.tb[FRA_PROTOCOL]) : 0;
	r.table = frh->table;
	attr_u32(&t, FRA_PRIORITY, &r.prio);
	attr_u32(&t, FRA_TABLE, &r.table);
	has_mark = attr_u32(&t, FRA_FWMARK, &r.mark);
	has_mask = attr_u32(&t, FRA_FWMASK, &r.mask);
	if (has_mark && !has_mask)
		r.mask = UINT32_MAX;

	if (nlh->nlmsg_type == RTM_DELRULE) {
		for (size_t i = 0; i < K->nru[l]; i++) {
			const struct mrule *o = &K->ru[l][i];

			if ((r.prio && o->prio != r.prio) || (r.table && o->table != r.table) ||
			    (r.mark && o->mark != r.mark) || (r.mask && o->mask != r.mask) ||
			    (r.proto && o->proto != r.proto))
				continue;
			rule_remove(K, l, i);
			return 0;
		}
		REFUSE(ENOENT, "no such rule");
	}

	if (!t.tb[FRA_PRIORITY]) {
		test_bug("rule without a priority");
		REFUSE(EOPNOTSUPP, "no priority");
	}
	if (!r.table)
		REFUSE(EINVAL, "no table");
	if (nlh->nlmsg_flags & NLM_F_EXCL)
		for (size_t i = 0; i < K->nru[l]; i++)
			if (!memcmp(&K->ru[l][i], &r, sizeof(r)))
				REFUSE(EEXIST, "rule exists");
	if (!rule_insert(K, &r)) {
		test_bug("model out of rule slots");
		REFUSE(ENOBUFS, "full");
	}
	return 0;
}

/* --- dumps: the model as the kernel reports it --- */

#define SKB_GOOD 3776		/* SKB_WITH_OVERHEAD(4096): before the socket learns */
#define SKB_BIG 32448		/* SKB_WITH_OVERHEAD(32768): the most it learns */

/*
 * The sockets' receive queues: the dump socket's dump replies, the request
 * socket's error replies.
 */
struct dgram {
	size_t len;
	char *buf;
};

#define QMAX 8192

struct rq {
	struct dgram d[QMAX];
	size_t head, tail;
};

static struct rq dumpq, errq;
static size_t learned;		/* what the kernel learned of the dump socket's buffer */
static struct nl nl;

static void q_push(struct rq *q, const void *buf, size_t len)
{
	struct dgram *d = &q->d[q->tail % QMAX];

	if (q->tail - q->head == QMAX) {
		test_bug("receive queue overflow");
		return;
	}
	d->buf = malloc(len);
	memcpy(d->buf, buf, len);
	d->len = len;
	q->tail++;
}

static size_t q_len(const struct rq *q)
{
	return q->tail - q->head;
}

/*
 * A dump in progress. The kernel makes a dump's first datagram when asked,
 * and each next one as the reader takes the one before, from where it got
 * to: what changed in between shows (a route dump resumes by key: v4 at the
 * leaf it stopped in, skipping as many aliases of it as it had dumped, so
 * one deleted there makes it skip one; v6 like its tree walker, exactly
 * after the last one; nexthops after the last id; rules by position).
 */
static struct {
	bool active, done, first, route;
	uint16_t type, flags;
	uint32_t seq, pid;
	uint8_t family, proto;
	uint32_t table;
	int phase;			/* routes: 0 = v4, 1 = v6, 2 = through */
	bool begun4, begun6, begun_nh;
	uint32_t t4;
	uint8_t key4[4];
	unsigned skip4;
	struct mroute last6;
	uint32_t last_id;
	int rl;
	size_t ri;
} ds;

static void q_clear(void)
{
	while (dumpq.head != dumpq.tail)
		free(dumpq.d[dumpq.head++ % QMAX].buf);
	while (errq.head != errq.tail)
		free(errq.d[errq.head++ % QMAX].buf);
	ds.active = false;
}

struct dumpb {
	char buf[SKB_BIG + 64] __attribute__((aligned(4)));
	size_t len, limit;
};

static struct dumpb db;

static void db_begin(void)
{
	db.len = 0;
	/* a dump's first datagram is sized by what the socket learned so far */
	db.limit = !ds.first ? SKB_BIG : learned > SKB_GOOD ? learned : SKB_GOOD;
}

static void db_push(void)
{
	if (db.len)
		q_push(&dumpq, db.buf, db.len);
	db.len = 0;
	ds.first = false;
}

static struct nlmsghdr *db_msg(char *tmp, uint16_t type)
{
	struct nlmsghdr *nlh = mnl_nlmsg_put_header(tmp);

	nlh->nlmsg_type = type;
	nlh->nlmsg_flags = NLM_F_MULTI | ds.flags;
	nlh->nlmsg_seq = ds.seq;
	nlh->nlmsg_pid = ds.pid;
	return nlh;
}

/* Into the datagram, if it fits (always into an empty one). */
static bool db_try(const struct nlmsghdr *nlh)
{
	if (db.len && db.len + nlh->nlmsg_len > db.limit)
		return false;
	memcpy(db.buf + db.len, nlh, nlh->nlmsg_len);
	db.len += NLMSG_ALIGN(nlh->nlmsg_len);
	return true;
}

/* NLMSG_DONE carrying error (0 or -errno), with an extended ack message. */
static bool db_done(int error, const char *msg)
{
	char tmp[256] __attribute__((aligned(4)));
	struct nlmsghdr *nlh = db_msg(tmp, NLMSG_DONE);

	if (msg)
		nlh->nlmsg_flags |= NLM_F_ACK_TLVS;
	memcpy(mnl_nlmsg_put_extra_header(nlh, sizeof(int)), &error, sizeof(int));
	if (msg)
		mnl_attr_put_strz(nlh, NLMSGERR_ATTR_MSG, msg);
	return db_try(nlh);
}

static uint8_t table_compat(uint32_t t)
{
	return t < 256 ? t : RT_TABLE_COMPAT;
}

static bool enc_nexthop(const struct mnh *n)
{
	char tmp[1024] __attribute__((aligned(4)));
	struct nlmsghdr *nlh = db_msg(tmp, RTM_NEWNEXTHOP);
	struct nhmsg *nhm = mnl_nlmsg_put_extra_header(nlh, sizeof(*nhm));

	nhm->nh_protocol = n->proto;
	mnl_attr_put_u32(nlh, NHA_ID, n->id);
	if (n->group) {
		struct nexthop_grp g[MAX_NH_GROUP] = {};
		struct nlattr *nest;

		for (uint16_t i = 0; i < n->n; i++) {
			g[i].id = n->ids[i];
			g[i].weight = (n->weights[i] - 1) & 0xff;
			g[i].weight_high = (n->weights[i] - 1) >> 8;
		}
		mnl_attr_put_u16(nlh, NHA_GROUP_TYPE, NEXTHOP_GRP_TYPE_RES);
		mnl_attr_put(nlh, NHA_GROUP, n->n * sizeof(g[0]), g);
		nest = mnl_attr_nest_start(nlh, NHA_RES_GROUP);
		mnl_attr_put_u16(nlh, NHA_RES_GROUP_BUCKETS, n->buckets);
		mnl_attr_put_u32(nlh, NHA_RES_GROUP_IDLE_TIMER, n->idle);
		mnl_attr_put_u32(nlh, NHA_RES_GROUP_UNBALANCED_TIMER, n->busy);
		mnl_attr_put_u64(nlh, NHA_RES_GROUP_UNBALANCED_TIME, 0);
		mnl_attr_nest_end(nlh, nest);
		mnl_attr_put_u32(nlh, NHA_OP_FLAGS, 1u << 31);
	} else if (n->blackhole) {
		nhm->nh_family = n->family;
		mnl_attr_put(nlh, NHA_BLACKHOLE, 0, NULL);
	} else {
		nhm->nh_family = n->family;
		nhm->nh_scope = n->family == AF_INET && !n->has_gw ? RT_SCOPE_HOST : RT_SCOPE_LINK;
		mnl_attr_put_u32(nlh, NHA_OIF, n->oif);
		if (n->has_gw)
			mnl_attr_put(nlh, NHA_GATEWAY, alen_of(n->family), n->gw);
	}
	return db_try(nlh);
}

static bool enc_rule(const struct mrule *r)
{
	char tmp[256] __attribute__((aligned(4)));
	struct nlmsghdr *nlh = db_msg(tmp, RTM_NEWRULE);
	struct fib_rule_hdr *frh = mnl_nlmsg_put_extra_header(nlh, sizeof(*frh));

	frh->family = r->family;
	frh->table = table_compat(r->table);
	frh->action = FR_ACT_TO_TBL;
	mnl_attr_put_u32(nlh, FRA_TABLE, r->table);
	mnl_attr_put_u32(nlh, FRA_SUPPRESS_PREFIXLEN, UINT32_MAX);
	mnl_attr_put_u8(nlh, FRA_PROTOCOL, r->proto);
	if (r->prio)
		mnl_attr_put_u32(nlh, FRA_PRIORITY, r->prio);
	if (r->mark)
		mnl_attr_put_u32(nlh, FRA_FWMARK, r->mark);
	if (r->mark || r->mask)
		mnl_attr_put_u32(nlh, FRA_FWMASK, r->mask);
	return db_try(nlh);
}

/* One path of a route: a single nexthop's device and gateway (lo for a blackhole). */
static void enc_path(struct nlmsghdr *nlh, const struct mnh *n)
{
	if (n->blackhole) {
		mnl_attr_put_u32(nlh, RTA_OIF, 1);
		return;
	}
	if (n->has_gw)
		mnl_attr_put(nlh, RTA_GATEWAY, alen_of(n->family), n->gw);
	mnl_attr_put_u32(nlh, RTA_OIF, n->oif);
}

static void enc_multipath(struct nlmsghdr *nlh, const struct mnh *g)
{
	struct nlattr *mp = mnl_attr_nest_start(nlh, RTA_MULTIPATH);

	/* not a nested attribute to the kernel: no NLA_F_NESTED */
	mp->nla_type = RTA_MULTIPATH;
	for (uint16_t i = 0; i < g->n; i++) {
		const struct mnh *m = nh_get(K, g->ids[i]);
		struct rtnexthop *rtnh = mnl_nlmsg_get_payload_tail(nlh);

		nlh->nlmsg_len += RTNH_ALIGN(sizeof(*rtnh));
		memset(rtnh, 0, sizeof(*rtnh));
		rtnh->rtnh_hops = g->weights[i] - 1;
		rtnh->rtnh_ifindex = m->blackhole ? 1 : m->oif;
		if (m->has_gw)
			mnl_attr_put(nlh, RTA_GATEWAY, alen_of(m->family), m->gw);
		rtnh->rtnh_len = (char *)mnl_nlmsg_get_payload_tail(nlh) - (char *)rtnh;
	}
	mnl_attr_nest_end(nlh, mp);
}

static bool enc_route(const struct mroute *r)
{
	char tmp[2048] __attribute__((aligned(4)));
	struct nlmsghdr *nlh = db_msg(tmp, RTM_NEWROUTE);
	struct rtmsg *rtm = mnl_nlmsg_put_extra_header(nlh, sizeof(*rtm));
	size_t alen = alen_of(r->family);
	const struct mnh *n = r->nh_id ? nh_get(K, r->nh_id) : NULL;

	rtm->rtm_family = r->family;
	rtm->rtm_dst_len = r->dst_len;
	rtm->rtm_src_len = r->src_len;
	rtm->rtm_tos = r->tos;
	rtm->rtm_table = table_compat(r->table);
	rtm->rtm_protocol = r->proto;
	rtm->rtm_scope = r->scope;
	rtm->rtm_type = route_type(K, r);
	mnl_attr_put_u32(nlh, RTA_TABLE, r->table);
	if (r->dst_len)
		mnl_attr_put(nlh, RTA_DST, alen, r->dst);

	if (r->family == AF_INET) {
		if (r->metric)
			mnl_attr_put_u32(nlh, RTA_PRIORITY, r->metric);
		if (n) {
			const struct mnh *p[MAX_NH_GROUP];
			size_t c = nh_paths(K, n, p);

			mnl_attr_put_u32(nlh, RTA_NH_ID, n->id);
			if (c == 1)
				enc_path(nlh, p[0]);
			else
				enc_multipath(nlh, n);
		} else if (r->type == RTN_UNICAST) {
			if (r->has_gw)
				mnl_attr_put(nlh, RTA_GATEWAY, alen, r->gw);
			mnl_attr_put_u32(nlh, RTA_OIF, r->oif);
		}
	} else {
		struct rta_cacheinfo ci = {};

		if (r->src_len)
			mnl_attr_put(nlh, RTA_SRC, alen, r->src);
		mnl_attr_put_u32(nlh, RTA_PRIORITY, r->metric);
		if (n) {
			mnl_attr_put_u32(nlh, RTA_NH_ID, n->id);
			if (n->group)
				enc_multipath(nlh, n);
			else
				enc_path(nlh, n);
		} else if (r->type == RTN_BLACKHOLE) {
			mnl_attr_put_u32(nlh, RTA_OIF, 1);
		} else {
			if (r->has_gw)
				mnl_attr_put(nlh, RTA_GATEWAY, alen, r->gw);
			mnl_attr_put_u32(nlh, RTA_OIF, r->oif);
		}
		mnl_attr_put(nlh, RTA_CACHEINFO, sizeof(ci), &ci);
		mnl_attr_put_u8(nlh, RTA_PREF, 0);
	}
	return db_try(nlh);
}

/* The order of a route dump: tables, then v4 leaves (aliases longest first), v6 by prefix. */
static int cmp_route(const struct mroute *x, const struct mroute *y)
{
	int c;

	if (x->family != y->family)
		return x->family - y->family;
	if (x->table != y->table)
		return x->table < y->table ? -1 : 1;
	if ((c = memcmp(x->dst, y->dst, 16)))
		return c;
	if (x->dst_len != y->dst_len)	/* v4: the longer first, as the trie walks */
		return x->family == AF_INET ? y->dst_len - x->dst_len : x->dst_len - y->dst_len;
	if (x->tos != y->tos)
		return y->tos - x->tos;
	if (x->src_len != y->src_len || memcmp(x->src, y->src, 16))
		return x->src_len != y->src_len ? x->src_len - y->src_len : memcmp(x->src, y->src, 16);
	return x->metric < y->metric ? -1 : x->metric > y->metric;
}

static int cmp_route_slots(const void *a, const void *b)
{
	return cmp_route(&K->r[*(const int *)a], &K->r[*(const int *)b]);
}

static unsigned n_dumps;

/* A v4 leaf: table, then the address. */
static int cmp_leaf(uint32_t t, const uint8_t *key, uint32_t t2, const uint8_t *key2)
{
	if (t != t2)
		return t < t2 ? -1 : 1;
	return memcmp(key, key2, 4);
}

/* One family's routes of the dump's table, in dump order. */
static size_t route_slots(int family, int *slots)
{
	size_t n = 0;

	for (int i = 0; i < MAXR; i++)
		if (K->r[i].used && K->r[i].family == family && (!ds.table || K->r[i].table == ds.table))
			slots[n++] = i;
	qsort(slots, n, sizeof(slots[0]), cmp_route_slots);
	return n;
}

static bool proto_ok(const struct mroute *r)
{
	return !ds.proto || r->proto == ds.proto;
}

/* Fill the datagram from the cursor: true if it filled up before the dump's end. */
static bool produce_routes(void)
{
	static int slots[MAXR];

	if (ds.phase == 0 && (!ds.family || ds.family == AF_INET)) {
		size_t n = route_slots(AF_INET, slots), i = 0;
		bool first = true;

		/* the first leaf at or after the cursor's, skipping as many as were dumped of it */
		while (ds.begun4 && i < n &&
		       cmp_leaf(K->r[slots[i]].table, K->r[slots[i]].dst, ds.t4, ds.key4) < 0)
			i++;
		while (i < n) {
			const struct mroute *l = &K->r[slots[i]];
			size_t j = i;
			unsigned a = 0;

			for (; j < n && !cmp_leaf(K->r[slots[j]].table, K->r[slots[j]].dst, l->table,
			                          l->dst); j++, a++) {
				const struct mroute *r = &K->r[slots[j]];

				if ((first && ds.begun4 && a < ds.skip4) || !proto_ok(r))
					continue;
				if (!enc_route(r)) {
					ds.begun4 = true;
					ds.t4 = l->table;
					memcpy(ds.key4, l->dst, 4);
					ds.skip4 = a;
					return true;
				}
			}
			first = false;
			i = j;
		}
	}
	if (ds.phase == 0)
		ds.phase = 1;
	if (ds.phase == 1 && (!ds.family || ds.family == AF_INET6)) {
		size_t n = route_slots(AF_INET6, slots);

		for (size_t i = 0; i < n; i++) {
			const struct mroute *r = &K->r[slots[i]];

			if ((ds.begun6 && cmp_route(r, &ds.last6) <= 0) || !proto_ok(r))
				continue;
			if (!enc_route(r))
				return true;
			ds.begun6 = true;
			ds.last6 = *r;
		}
	}
	ds.phase = 2;
	return false;
}

static bool produce_nexthops(void)
{
	for (size_t i = 0; i < K->nnh; i++) {
		if (ds.begun_nh && K->nh[i].id <= ds.last_id)
			continue;
		if (!enc_nexthop(&K->nh[i]))
			return true;
		ds.begun_nh = true;
		ds.last_id = K->nh[i].id;
	}
	return false;
}

static bool produce_rules(void)
{
	for (; ds.rl < 4; ds.rl++, ds.ri = 0) {
		if (ds.family && ds.family != rule_fams[ds.rl])
			continue;
		for (; ds.ri < K->nru[ds.rl]; ds.ri++)
			if (!enc_rule(&K->ru[ds.rl][ds.ri]))
				return true;
	}
	return false;
}

/* The next datagram of the running dump. */
static void produce(void)
{
	db_begin();
	if (!ds.done) {
		bool more = ds.type == RTM_GETNEXTHOP ? produce_nexthops() :
		            ds.type == RTM_GETRULE ? produce_rules() : produce_routes();

		if (more) {
			db_push();
			return;
		}
		ds.done = true;
		/* a route dump's NLMSG_DONE comes on its own */
		if (ds.route && db.len) {
			db_push();
			return;
		}
	}
	if (!db_done(0, NULL)) {
		db_push();
		return;
	}
	db_push();
	ds.active = false;
}

/* A dump that ends before it starts: an error in NLMSG_DONE. */
static void dump_fail(int error, const char *msg)
{
	db_begin();
	db_done(error, msg);
	db_push();
	ds.active = false;
}

static void dump(const struct nlmsghdr *req)
{
	n_dumps++;
	if (ds.active || q_len(&dumpq))
		test_bug("a dump asked for while another is unread");
	memset(&ds, 0, sizeof(ds));
	ds.active = ds.first = true;
	ds.type = req->nlmsg_type;
	ds.seq = req->nlmsg_seq;
	ds.pid = mnl_socket_get_portid(nl.dump);
	switch (req->nlmsg_type) {
	case RTM_GETNEXTHOP: {
		const struct nhmsg *nhm = mnl_nlmsg_get_payload(req);

		if (req->nlmsg_len != NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*nhm)) || nhm->nh_family ||
		    nhm->nh_scope || nhm->nh_protocol || nhm->resvd || nhm->nh_flags) {
			test_bug("nexthop dump request the model doesn't know");
			dump_fail(-EINVAL, "model: unmodelled dump request");
			return;
		}
		break;
	}
	case RTM_GETRULE: {
		const struct fib_rule_hdr *frh = mnl_nlmsg_get_payload(req);

		ds.family = frh->family;
		break;
	}
	case RTM_GETROUTE: {
		static const int ok[] = { RTA_TABLE };
		const struct rtmsg *rtm = mnl_nlmsg_get_payload(req);
		struct attrs t = {};

		ds.route = true;
		if (mnl_attr_parse(req, sizeof(*rtm), attrs_cb, &t) < 0 ||
		    !attrs_only(&t, ok, 1) || rtm->rtm_dst_len || rtm->rtm_src_len || rtm->rtm_tos ||
		    rtm->rtm_scope || rtm->rtm_type || rtm->rtm_flags ||
		    (rtm->rtm_family != AF_UNSPEC && rtm->rtm_family != AF_INET &&
		     rtm->rtm_family != AF_INET6)) {
			test_bug("route dump request the model doesn't know");
			dump_fail(-EINVAL, "model: unmodelled dump request");
			return;
		}
		ds.family = rtm->rtm_family;
		ds.proto = rtm->rtm_protocol;
		ds.table = rtm->rtm_table;
		attr_u32(&t, RTA_TABLE, &ds.table);
		ds.flags = ds.table || ds.proto ? NLM_F_DUMP_FILTERED : 0;
		if (ds.table && ds.family && !table_exists(K, ds.family, ds.table)) {
			dump_fail(-ENOENT, ds.family == AF_INET ? "ipv4: FIB table does not exist" :
			                   "ipv6: FIB table does not exist");
			return;
		}
		break;
	}
	default:
		test_bug("dump of something the model doesn't know");
		dump_fail(-EOPNOTSUPP, NULL);
		return;
	}
	produce();
}

/* --- the interposed socket calls --- */

/* What one apply did, as the kernel saw it. */
struct acct {
	unsigned msgs, route_msgs, prefix_msgs, prefix_set, prefix_del, nh_msgs, rule_msgs;
	unsigned unexpected;		/* failed requests nl.c doesn't expect */
	unsigned expected;		/* ENOENT/ESRCH deletes, EEXIST rule adds */
	unsigned leaks;
	unsigned refused;		/* of the unexpected: what the devices refused */
};

static struct acct acc;
static bool checking;		/* invariants are checked after every message */
static struct {
	unsigned expected_by_type[4];	/* route del, rule del, rule add, nexthop del */
	unsigned unexpected;
	unsigned steps, applies, msgs, races, races_hit, followups, full_retries;
	unsigned perturbs;
	unsigned mid_dump;		/* requests sent while a dump was running */
	unsigned race_violations;	/* traffic checks broken after a race hit */
} totals;

/*
 * Once a race hit, the rest of the batch was planned on a stale dump: what
 * breaks then is the race's doing as much as sync's. Counted and logged,
 * not failed; the follow-up sync must still repair everything.
 */
static bool after_race;

static void violation(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void violation(const char *fmt, ...)
{
	char buf[512];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if (after_race) {
		totals.race_violations++;
		mlog("  !! after the race: %s\n", buf);
		return;
	}
	fail("%s", buf);
}

static void after_message(const struct nlmsghdr *nlh);
static void before_message(void);

static void queue_error(const struct nlmsghdr *req, int error, const char *msg)
{
	char tmp[4096] __attribute__((aligned(4)));
	struct nlmsghdr *nlh = mnl_nlmsg_put_header(tmp);
	struct nlmsgerr *e;

	nlh->nlmsg_type = NLMSG_ERROR;
	nlh->nlmsg_flags = NLM_F_ACK_TLVS;
	nlh->nlmsg_seq = req->nlmsg_seq;
	nlh->nlmsg_pid = mnl_socket_get_portid(nl.req);
	e = mnl_nlmsg_put_extra_header(nlh, sizeof(*e) - sizeof(e->msg) + req->nlmsg_len);
	e->error = -error;
	memcpy(&e->msg, req, req->nlmsg_len);
	mnl_attr_put_strz(nlh, NLMSGERR_ATTR_MSG, msg);
	q_push(&errq, nlh, nlh->nlmsg_len);
}

/* nl.c's view of which errors are routine */
static int expected_kind(uint16_t type, int error)
{
	switch (type) {
	case RTM_DELROUTE:
		return error == ESRCH || error == ENOENT ? 0 : -1;
	case RTM_DELRULE:
		return error == ENOENT ? 1 : -1;
	case RTM_NEWRULE:
		return error == EEXIST ? 2 : -1;
	case RTM_DELNEXTHOP:
		return error == ENOENT ? 3 : -1;
	}
	return -1;
}

static void describe(const struct nlmsghdr *nlh, char *buf, size_t len);

ssize_t mnl_socket_sendto(const struct mnl_socket *s, const void *buf, size_t len)
{
	int left = len;

	if (s == nl.dump) {
		const struct nlmsghdr *nlh = buf;

		if (len != nlh->nlmsg_len ||
		    (nlh->nlmsg_type != RTM_GETROUTE && nlh->nlmsg_type != RTM_GETRULE &&
		     nlh->nlmsg_type != RTM_GETNEXTHOP) ||
		    (nlh->nlmsg_flags & NLM_F_DUMP) != NLM_F_DUMP)
			test_bug("on the dump socket, something else than one dump request");
		if (checking)
			mlog("    dump %u\n", nlh->nlmsg_type);
		dump(nlh);
		return len;
	}
	if (s != nl.req) {
		test_bug("send on another socket");
		errno = EINVAL;
		return -1;
	}
	for (const struct nlmsghdr *nlh = buf; mnl_nlmsg_ok(nlh, left);
	     nlh = mnl_nlmsg_next(nlh, &left)) {
		char d[160];
		int err = 0, kind;

		if (nlh->nlmsg_type == RTM_GETROUTE || nlh->nlmsg_type == RTM_GETRULE ||
		    nlh->nlmsg_type == RTM_GETNEXTHOP) {
			test_bug("a dump on the request socket");
			continue;
		}
		if (nlh->nlmsg_flags & NLM_F_ACK)
			test_bug("request with NLM_F_ACK");
		totals.mid_dump += ds.active;
		before_message();
		why = "";
		refused = false;
		switch (nlh->nlmsg_type) {
		case RTM_NEWROUTE:
		case RTM_DELROUTE:
			err = apply_route(nlh);
			break;
		case RTM_NEWNEXTHOP:
		case RTM_DELNEXTHOP:
			err = apply_nexthop(nlh);
			break;
		case RTM_NEWRULE:
		case RTM_DELRULE:
			err = apply_rule(nlh);
			break;
		default:
			test_bug("request of an unknown type");
			err = EOPNOTSUPP;
		}
		describe(nlh, d, sizeof(d));
		if (checking && err)
			mlog("  #%u %s -> %s (%s)\n", acc.msgs, d, strerror(err), why);
		else if (checking)
			mlog("  #%u %s\n", acc.msgs, d);
		if (err) {
			char m[160];

			kind = expected_kind(nlh->nlmsg_type, err);
			if (kind >= 0) {
				acc.expected++;
				totals.expected_by_type[kind]++;
			} else {
				acc.unexpected++;
				acc.refused += refused;
			}
			snprintf(m, sizeof(m), "model: %s", why);
			queue_error(nlh, err, m);
		}
		after_message(nlh);
	}
	return len;
}

ssize_t mnl_socket_recvfrom(const struct mnl_socket *s, void *buf, size_t size)
{
	struct dgram *d;
	size_t n;

	if (s != nl.dump || !q_len(&dumpq)) {
		test_bug(s != nl.dump ? "recvfrom on another socket than the dump socket" :
		         "recv on an empty queue: would block forever");
		errno = EIO;
		return -1;
	}
	learned = size < SKB_BIG ? (size > learned ? size : learned) : SKB_BIG;
	d = &dumpq.d[dumpq.head++ % QMAX];
	n = d->len;
	if (n > size) {
		test_bug("datagram larger than the receive buffer");
		free(d->buf);
		errno = ENOSPC;
		return -1;
	}
	memcpy(buf, d->buf, n);
	free(d->buf);
	/* the kernel makes the next datagram as this one is taken */
	if (ds.active && !q_len(&dumpq))
		produce();
	return n;
}

ssize_t recv(int fd, void *buf, size_t len, int flags)
{
	struct dgram *d;

	if (nl.dump && fd == mnl_socket_get_fd(nl.dump))
		test_bug("recv on the dump socket");
	if (!nl.req || fd != mnl_socket_get_fd(nl.req))
		return syscall(SYS_recvfrom, fd, buf, len, flags, NULL, NULL);
	if (!q_len(&errq)) {
		if (!(flags & MSG_DONTWAIT))
			test_bug("blocking recv on an empty queue");
		errno = EAGAIN;
		return -1;
	}
	d = &errq.d[errq.head++ % QMAX];
	memcpy(buf, d->buf, d->len < len ? d->len : len);
	free(d->buf);
	return d->len < len ? d->len : len;
}

/* --- text --- */

static void addr_fmt(int family, const uint8_t *a, char *buf)
{
	inet_ntop(family, a, buf, INET6_ADDRSTRLEN);
}

static void route_text(struct kernel *k, const struct mroute *r, bool observed, char *buf,
                       size_t len)
{
	char d[INET6_ADDRSTRLEN], s[INET6_ADDRSTRLEN], g[INET6_ADDRSTRLEN];
	int o;

	addr_fmt(r->family, r->dst, d);
	addr_fmt(r->family, r->src, s);
	addr_fmt(r->family, r->gw, g);
	o = snprintf(buf, len, "route v%c t%u %s/%u", r->family == AF_INET ? '4' : '6', r->table,
	             d, r->dst_len);
	if (r->tos)
		o += snprintf(buf + o, len - o, " tos %u", r->tos);
	if (r->src_len)
		o += snprintf(buf + o, len - o, " from %s/%u", s, r->src_len);
	o += snprintf(buf + o, len - o, " metric %u proto %u", r->metric, r->proto);
	if (!observed && r->family == AF_INET)
		o += snprintf(buf + o, len - o, " scope %u", r->scope);
	if (observed)	/* the type as reported, which the caller put in */
		o += snprintf(buf + o, len - o, " type %u", r->type);
	else if (r->type == RTN_BLACKHOLE)
		o += snprintf(buf + o, len - o, " blackhole");
	if (r->nh_id)
		snprintf(buf + o, len - o, " nhid %u", r->nh_id);
	else if (r->type == RTN_UNICAST)
		snprintf(buf + o, len - o, " dev %d via %s", r->oif, r->has_gw ? g : "-");
}

static void nh_text(const struct mnh *n, bool secs, char *buf, size_t len)
{
	char g[INET6_ADDRSTRLEN];
	int o = snprintf(buf, len, "nh %u proto %u", n->id, n->proto);

	if (n->group) {
		o += snprintf(buf + o, len - o, " group buckets %u idle %u busy %u:", n->buckets,
		              secs ? n->idle / 100 : n->idle, secs ? n->busy / 100 : n->busy);
		for (uint16_t j = 0; j < n->n; j++)
			o += snprintf(buf + o, len - o, " %u,%u", n->ids[j], n->weights[j]);
	} else if (n->blackhole) {
		snprintf(buf + o, len - o, " v%c blackhole", n->family == AF_INET ? '4' : '6');
	} else {
		addr_fmt(n->family, n->gw, g);
		snprintf(buf + o, len - o, " v%c dev %d via %s", n->family == AF_INET ? '4' : '6',
		         n->oif, n->has_gw ? g : "-");
	}
}

static void rule_text(const struct mrule *r, char *buf, size_t len)
{
	snprintf(buf, len, "rule f%u proto %u prio %u mark %#x/%#x table %u", r->family, r->proto,
	         r->prio, r->mark, r->mask, r->table);
}

struct lines {
	char **l;
	size_t n, cap;
};

static void lines_add(struct lines *ls, const char *s)
{
	if (ls->n == ls->cap) {
		ls->cap = ls->cap ? 2 * ls->cap : 64;
		ls->l = realloc(ls->l, ls->cap * sizeof(*ls->l));
	}
	ls->l[ls->n++] = strdup(s);
}

static int cmp_str(const void *a, const void *b)
{
	return strcmp(*(char *const *)a, *(char *const *)b);
}

static char *lines_join(struct lines *ls)
{
	size_t len = 1;
	char *out, *p;

	if (ls->n)
		qsort(ls->l, ls->n, sizeof(*ls->l), cmp_str);
	for (size_t i = 0; i < ls->n; i++)
		len += strlen(ls->l[i]) + 1;
	p = out = malloc(len);
	for (size_t i = 0; i < ls->n; i++) {
		p += sprintf(p, "%s\n", ls->l[i]);
		free(ls->l[i]);
	}
	*p = '\0';
	free(ls->l);
	memset(ls, 0, sizeof(*ls));
	return out;
}

enum which { OURS, FOREIGN };

/* The model as sorted lines: routebot's objects, or everybody else's. */
static char *kernel_text(struct kernel *k, enum which w)
{
	struct lines ls = {};
	char buf[512];

	for (int i = 0; i < MAXR; i++)
		if (k->r[i].used && ours(k->r[i].proto) == (w == OURS)) {
			route_text(k, &k->r[i], false, buf, sizeof(buf));
			lines_add(&ls, buf);
		}
	for (size_t i = 0; i < k->nnh; i++)
		if (ours(k->nh[i].proto) == (w == OURS)) {
			nh_text(&k->nh[i], false, buf, sizeof(buf));
			lines_add(&ls, buf);
		}
	for (int l = 0; l < 4; l++)
		for (size_t i = 0; i < k->nru[l]; i++)
			if (ours(k->ru[l][i].proto) == (w == OURS)) {
				rule_text(&k->ru[l][i], buf, sizeof(buf));
				lines_add(&ls, buf);
			}
	return lines_join(&ls);
}

/* Lines only in a ("+"), only in b ("-"). Both sorted. */
static void print_diff(const char *a, const char *b)
{
	unsigned shown = 0;

	while ((*a || *b) && shown < 40) {
		const char *ea = strchr(a, '\n'), *eb = strchr(b, '\n');
		int c;

		if (!*a)
			c = 1;
		else if (!*b)
			c = -1;
		else {
			size_t la = ea - a, lb = eb - b;

			c = strncmp(a, b, la < lb ? la : lb);
			if (!c)
				c = la == lb ? 0 : la < lb ? -1 : 1;
		}
		if (c < 0) {
			fprintf(stderr, "      + %.*s\n", (int)(ea - a), a);
			a = ea + 1;
			shown++;
		} else if (c > 0) {
			fprintf(stderr, "      - %.*s\n", (int)(eb - b), b);
			b = eb + 1;
			shown++;
		} else {
			a = ea + 1;
			b = eb + 1;
		}
	}
	if (shown == 40)
		fprintf(stderr, "      ...\n");
}

/* Compare two texts; on a difference, fail with what and the diff (+ got, - want). */
static bool same_text(const char *got, const char *want, const char *what)
{
	if (!strcmp(got, want))
		return true;
	fail("%s (+ got, - want):", what);
	if (reports <= MAX_REPORTS && step_fails <= 12)
		print_diff(got, want);
	return false;
}

static void describe(const struct nlmsghdr *nlh, char *buf, size_t len)
{
	struct attrs t = {};
	char a[INET6_ADDRSTRLEN];

	switch (nlh->nlmsg_type) {
	case RTM_NEWROUTE:
	case RTM_DELROUTE: {
		const struct rtmsg *rtm = mnl_nlmsg_get_payload(nlh);
		uint8_t dst[16] = {};
		uint32_t table = rtm->rtm_table, metric = 0, nh = 0;

		mnl_attr_parse(nlh, sizeof(*rtm), attrs_cb, &t);
		if (t.tb[RTA_DST])
			memcpy(dst, mnl_attr_get_payload(t.tb[RTA_DST]),
			       mnl_attr_get_payload_len(t.tb[RTA_DST]) <= 16 ?
			       mnl_attr_get_payload_len(t.tb[RTA_DST]) : 16);
		attr_u32(&t, RTA_TABLE, &table);
		attr_u32(&t, RTA_PRIORITY, &metric);
		attr_u32(&t, RTA_NH_ID, &nh);
		addr_fmt(rtm->rtm_family, dst, a);
		snprintf(buf, len, "%s %s%s/%u tos %u table %u metric %u proto %u nhid %u",
		         nlh->nlmsg_type == RTM_NEWROUTE ? "route set" : "route del",
		         rtm->rtm_type == RTN_BLACKHOLE ? "blackhole " : "", a, rtm->rtm_dst_len,
		         rtm->rtm_tos, table, metric, rtm->rtm_protocol, nh);
		break;
	}
	case RTM_NEWNEXTHOP:
	case RTM_DELNEXTHOP: {
		const struct nhmsg *nhm = mnl_nlmsg_get_payload(nlh);
		uint32_t id = 0;
		int o;

		mnl_attr_parse(nlh, sizeof(*nhm), attrs_cb, &t);
		attr_u32(&t, NHA_ID, &id);
		o = snprintf(buf, len, "%s %u proto %u", nlh->nlmsg_type == RTM_NEWNEXTHOP ?
		             "nexthop set" : "nexthop del", id, nhm->nh_protocol);
		if (t.tb[NHA_GROUP]) {
			const struct nexthop_grp *g = mnl_attr_get_payload(t.tb[NHA_GROUP]);

			o += snprintf(buf + o, len - o, " group");
			for (size_t i = 0; i < mnl_attr_get_payload_len(t.tb[NHA_GROUP]) / sizeof(*g) &&
			     o < (int)len - 16; i++)
				o += snprintf(buf + o, len - o, " %u", g[i].id);
		} else if (t.tb[NHA_BLACKHOLE]) {
			snprintf(buf + o, len - o, " blackhole");
		} else if (t.tb[NHA_OIF]) {
			snprintf(buf + o, len - o, " dev %u", mnl_attr_get_u32(t.tb[NHA_OIF]));
		}
		break;
	}
	case RTM_NEWRULE:
	case RTM_DELRULE: {
		const struct fib_rule_hdr *frh = mnl_nlmsg_get_payload(nlh);
		uint32_t prio = 0, mark = 0, table = frh->table;

		mnl_attr_parse(nlh, sizeof(*frh), attrs_cb, &t);
		attr_u32(&t, FRA_PRIORITY, &prio);
		attr_u32(&t, FRA_FWMARK, &mark);
		attr_u32(&t, FRA_TABLE, &table);
		snprintf(buf, len, "%s f%u prio %u mark %#x table %u proto %u",
		         nlh->nlmsg_type == RTM_NEWRULE ? "rule add" : "rule del", frh->family, prio,
		         mark, table, t.tb[FRA_PROTOCOL] ? mnl_attr_get_u8(t.tb[FRA_PROTOCOL]) : 0);
		break;
	}
	default:
		snprintf(buf, len, "type %u", nlh->nlmsg_type);
	}
}

/* --- configs and worlds --- */

#define MAXD 24
#define MAXG 4
#define MAXM 8		/* random groups stay under 5 */
#define MAXRULES 4
#define MAXP 64		/* random lists stay under 60 */
#define NSPEC 24	/* device specs "dev0".., random configs use 8 */
#define NNAME 8		/* group names "a".. */
#define NPOOL4 48
#define NPOOL6 24

static char spec_buf[NSPEC][8];
static const char *spec_names[NSPEC];
static const char *const group_names[NNAME] = { "a", "b", "c", "d", "e", "f", "g", "h" };

/* A config as written: groups name their members by spec. */
struct tgroup {
	uint8_t name;
	uint32_t fwmark;
	uint8_t n;
	uint8_t spec[MAXM];
	uint16_t weight[MAXM];
	bool probe[2];
	uint16_t buckets;
	uint32_t idle, busy;
};

struct tsrc {
	uint32_t table_id, rule_prio, nexthop_id;
	uint8_t proto;
	uint8_t ng;
	struct tgroup g[MAXG];
	uint8_t nrules;
	uint8_t rule_group[MAXRULES];
	uint16_t np;
	struct { uint8_t f; uint16_t key; uint8_t rule; } p[MAXP];
};

/* The config built from it, as config_load would. */
struct tcfg {
	struct tsrc src;
	struct config c;
	struct cfg_device devs[MAXD];
	uint8_t dev_spec[MAXD];
	struct cfg_group groups[MAXG];
	struct cfg_member members[MAXG][MAXM];
	uint16_t rg[MAXRULES];
	struct prefix4 p4[MAXP];
	struct prefix6 p6[MAXP];
	bool borrowed;		/* c.p4/p6 are another config's */
};

static void pool_prefix(int f, unsigned key, uint8_t *addr, uint8_t *plen)
{
	memset(addr, 0, 16);
	if (!f) {
		addr[0] = 10 + key / 512;
		addr[1] = key / 2 % 256;
		*plen = key % 2 ? 24 : 16;
	} else {
		addr[0] = 0x20;
		addr[1] = 0x01;
		addr[2] = 0x0d;
		addr[3] = 0xb8;
		addr[4] = key >> 8;
		addr[5] = key;
		*plen = 48;
	}
}

static int cmp_p4(const void *a, const void *b)
{
	int c = memcmp(a, b, 5);

	return c ? c : (int)((const struct prefix4 *)a)->rule - ((const struct prefix4 *)b)->rule;
}

static int cmp_p6(const void *a, const void *b)
{
	int c = memcmp(a, b, 17);

	return c ? c : (int)((const struct prefix6 *)a)->rule - ((const struct prefix6 *)b)->rule;
}

static struct tcfg *tcfg_build(const struct tsrc *s)
{
	struct tcfg *t = calloc(1, sizeof(*t));
	struct config *c = &t->c;

	t->src = *s;
	c->fwmask = 0xff000000;
	c->table_id = s->table_id;
	c->rule_prio = s->rule_prio;
	c->gw_table = RT_TABLE_MAIN;
	c->rt_proto = s->proto;
	c->nexthop_id = s->nexthop_id;
	c->probe_mark = 0xfe000000;
	c->devices = t->devs;
	c->groups = t->groups;
	c->rule_group = t->rg;
	c->p4 = t->p4;
	c->p6 = t->p6;

	/* devices in order of first appearance */
	for (size_t g = 0; g < s->ng; g++) {
		const struct tgroup *tg = &s->g[g];
		struct cfg_group *cg = &t->groups[g];

		cg->name = (char *)group_names[tg->name];
		cg->fwmark = tg->fwmark;
		cg->members = t->members[g];
		cg->n_members = tg->n;
		cg->has_probe[0] = tg->probe[0];
		cg->has_probe[1] = tg->probe[1];
		if (tg->probe[0])
			cg->probe[0][0] = 10, cg->probe[0][3] = 1;
		if (tg->probe[1])
			cg->probe[1][0] = 0xfd, cg->probe[1][15] = 1;
		cg->probe_timer_ms = 1000;
		cg->probe_count = 3;
		cg->buckets = tg->buckets;
		cg->timer_idle = tg->idle;
		cg->timer_busy = tg->busy;
		for (size_t m = 0; m < tg->n; m++) {
			size_t d;

			for (d = 0; d < c->n_devices; d++)
				if (t->dev_spec[d] == tg->spec[m])
					break;
			if (d == c->n_devices) {
				t->dev_spec[d] = tg->spec[m];
				t->devs[d].spec = (char *)spec_names[tg->spec[m]];
				c->n_devices++;
			}
			t->members[g][m] = (struct cfg_member){ d, tg->weight[m] };
		}
	}
	c->n_groups = s->ng;
	c->n_rules = s->nrules;
	for (size_t r = 0; r < s->nrules; r++)
		t->rg[r] = s->rule_group[r];

	/* sorted by (addr, plen), the lowest rule winning a duplicate */
	for (size_t i = 0; i < s->np; i++) {
		uint8_t addr[16], plen;

		pool_prefix(s->p[i].f, s->p[i].key, addr, &plen);
		if (!s->p[i].f) {
			struct prefix4 *p = &t->p4[c->n_p4++];

			memcpy(p->addr, addr, 4);
			p->plen = plen;
			p->rule = s->p[i].rule;
		} else {
			struct prefix6 *p = &t->p6[c->n_p6++];

			memcpy(p->addr, addr, 16);
			p->plen = plen;
			p->rule = s->p[i].rule;
		}
	}
	qsort(t->p4, c->n_p4, sizeof(*t->p4), cmp_p4);
	qsort(t->p6, c->n_p6, sizeof(*t->p6), cmp_p6);
	for (size_t i = 1; i < c->n_p4; i++)
		if (!memcmp(&t->p4[i - 1], &t->p4[i], 5)) {
			memmove(&t->p4[i], &t->p4[i + 1], (c->n_p4 - i - 1) * sizeof(*t->p4));
			c->n_p4--;
			i--;
		}
	for (size_t i = 1; i < c->n_p6; i++)
		if (!memcmp(&t->p6[i - 1], &t->p6[i], 17)) {
			memmove(&t->p6[i], &t->p6[i + 1], (c->n_p6 - i - 1) * sizeof(*t->p6));
			c->n_p6--;
			i--;
		}
	return t;
}

/* The same lists as o, the very arrays: as across a reload that kept them. */
static void tcfg_borrow(struct tcfg *t, const struct tcfg *o)
{
	if (t->c.n_p4 != o->c.n_p4 || t->c.n_p6 != o->c.n_p6 ||
	    memcmp(t->p4, o->c.p4, t->c.n_p4 * sizeof(*t->p4)) ||
	    memcmp(t->p6, o->c.p6, t->c.n_p6 * sizeof(*t->p6)))
		return;
	t->c.p4 = o->c.p4;
	t->c.p6 = o->c.p6;
	t->borrowed = true;
}

/* o goes away: whoever borrowed its lists gets its own copy. */
static void tcfg_release(struct tcfg *o, struct tcfg *other)
{
	if (!o)
		return;
	if (other && other != o && other->borrowed && other->c.p4 == o->c.p4) {
		memcpy(other->p4, o->c.p4, o->c.n_p4 * sizeof(*other->p4));
		memcpy(other->p6, o->c.p6, o->c.n_p6 * sizeof(*other->p6));
		other->c.p4 = other->p4;
		other->c.p6 = other->p6;
		other->borrowed = false;
	}
	free(o);
}

/* The live state, by device spec and group name. */
struct env {
	struct ifrender spec[NSPEC][2];
	bool up[NNAME][NSPEC];	/* probe verdicts */
};

struct tworld {
	struct tcfg *tc;	/* NULL = nothing installed */
	struct env env;
	struct ifview ifs[MAXD];
	bool member_up[MAXG * MAXM];
	struct world w;
};

static void tw_make(struct tworld *t, struct tcfg *tc, const struct env *e)
{
	memset(t, 0, sizeof(*t));
	t->tc = tc;
	t->env = *e;
	if (tc) {
		const struct config *c = &tc->c;

		for (size_t d = 0; d < c->n_devices; d++) {
			for (int f = 0; f < 2; f++)
				t->ifs[d].fam[f] = e->spec[tc->dev_spec[d]][f];
		}
		for (size_t g = 0; g < c->n_groups; g++)
			for (size_t m = 0; m < c->groups[g].n_members; m++)
				t->member_up[cfg_member_index(c, g, m)] =
					e->up[tc->src.g[g].name][tc->dev_spec[c->groups[g].members[m].dev]];
	}
	t->w = (struct world){ tc ? &tc->c : NULL, t->ifs, t->member_up };
}

static const struct world *tw_world(struct tworld *t)
{
	t->w = (struct world){ t->tc ? &t->tc->c : NULL, t->ifs, t->member_up };
	return &t->w;
}

static void env_default(struct env *e)
{
	memset(e, 0, sizeof(*e));
	for (int s = 0; s < NSPEC; s++)
		for (int f = 0; f < 2; f++) {
			struct ifrender *r = &e->spec[s][f];

			r->usable = true;
			r->ifindex = s + 2;
			r->has_gw = !(s % 2);
			if (!f) {
				r->gw[0] = 10;
				r->gw[2] = s;
				r->gw[3] = 254;
			} else {
				r->gw[0] = 0xfe;
				r->gw[1] = 0x80;
				r->gw[15] = s + 1;
			}
		}
	for (int n = 0; n < NNAME; n++)
		for (int s = 0; s < NSPEC; s++)
			e->up[n][s] = true;
}

static const struct tgroup *src_group(const struct tsrc *s, uint8_t name)
{
	for (size_t g = 0; g < s->ng; g++)
		if (s->g[g].name == name)
			return &s->g[g];
	return NULL;
}

/* Devices of group name in world t, family f, as ifindex bits. */
static uint64_t group_devs1(const struct tworld *t, const struct env *e, uint8_t name, int f)
{
	uint64_t bits = 0;
	const struct tgroup *g;

	if (!t->tc || !(g = src_group(&t->tc->src, name)))
		return 0;
	for (size_t m = 0; m < g->n; m++) {
		const struct ifrender *r = &e->spec[g->spec[m]][f];

		if (r->usable && r->ifindex < 64)
			bits |= 1ull << r->ifindex;
	}
	return bits;
}

/*
 * Devices of group name, family f, as ifindex bits: its members in either
 * world, each where it is in either world (a device keeps its membership
 * while its link changes).
 */
static uint64_t group_devs(const struct tworld *p, const struct tworld *w, uint8_t name, int f)
{
	return group_devs1(p, &p->env, name, f) | group_devs1(p, &w->env, name, f) |
	       group_devs1(w, &p->env, name, f) | group_devs1(w, &w->env, name, f);
}

/* The group name prefix (f, addr, plen) has in t, or -1. */
static int prefix_group(const struct tworld *t, int f, const uint8_t *addr, uint8_t plen)
{
	const struct config *c;

	if (!t->tc)
		return -1;
	c = &t->tc->c;
	{
		uint8_t key[17];
		size_t alen = f ? 16 : 4, lo = 0, hi = f ? c->n_p6 : c->n_p4;

		memcpy(key, addr, alen);
		key[alen] = plen;
		while (lo < hi) {
			size_t mid = (lo + hi) / 2;
			const uint8_t *e = f ? c->p6[mid].addr : c->p4[mid].addr;
			int cmp = memcmp(e, key, alen + 1);

			if (!cmp)
				return t->tc->src.g[c->rule_group[f ? c->p6[mid].rule :
				                                      c->p4[mid].rule]].name;
			if (cmp < 0)
				lo = mid + 1;
			else
				hi = mid;
		}
	}
	return -1;
}

static void world_text(const struct tworld *t, const char *label)
{
	const struct tsrc *s;

	if (!t->tc) {
		fprintf(stderr, "    %s: nothing\n", label);
		return;
	}
	s = &t->tc->src;
	fprintf(stderr, "    %s: table %u prio %u nhid %u proto %u, %u+%zu prefixes\n", label,
	        s->table_id, s->rule_prio, s->nexthop_id, s->proto, (unsigned)t->tc->c.n_p4,
	        t->tc->c.n_p6);
	for (size_t g = 0; g < s->ng; g++) {
		const struct tgroup *tg = &s->g[g];

		fprintf(stderr, "      group %s fwmark %#x buckets %u timers %u/%u probe %d%d:",
		        group_names[tg->name], tg->fwmark, tg->buckets, tg->idle, tg->busy,
		        tg->probe[0], tg->probe[1]);
		for (size_t m = 0; m < tg->n; m++) {
			const struct ifrender *r = t->env.spec[tg->spec[m]];

			fprintf(stderr, " %s,%u[if%d%s%s %s%s%s]", spec_names[tg->spec[m]],
			        tg->weight[m], r[0].ifindex, r[0].usable ? " v4" : "",
			        r[0].has_gw ? "gw" : "", r[1].usable ? "v6" : "", r[1].has_gw ? "gw" : "",
			        t->env.up[tg->name][tg->spec[m]] ? "" : " down");
		}
		fputc('\n', stderr);
	}
	fprintf(stderr, "      rules:");
	for (size_t r = 0; r < s->nrules; r++)
		fprintf(stderr, " %zu->%s", r, group_names[s->g[s->rule_group[r]].name]);
	fputc('\n', stderr);
}

/* --- the reference: what a world renders to, independently of sync.c --- */

static void ref_route(struct kernel *k, int f, uint32_t table, const uint8_t *dst, uint8_t plen,
                      uint32_t metric, uint8_t type, uint8_t proto, uint32_t nh, int oif,
                      bool has_gw, const uint8_t *gw)
{
	struct mroute r = {};

	r.family = f ? AF_INET6 : AF_INET;
	r.table = table;
	if (dst)
		memcpy(r.dst, dst, alen_of(r.family));
	r.dst_len = plen;
	r.metric = metric ? metric : f ? 1024 : 0;
	r.type = type;
	r.proto = proto;
	r.nh_id = nh;
	r.oif = oif;
	r.has_gw = has_gw;
	if (has_gw)
		memcpy(r.gw, gw, alen_of(r.family));
	r.scope = !f && type == RTN_UNICAST && !nh && !has_gw ? RT_SCOPE_LINK : RT_SCOPE_UNIVERSE;
	r_insert(k, &r);
	table_add(k, r.family, table);
}

static bool dev_in_group(const struct config *c, size_t d, bool probed)
{
	for (size_t g = 0; g < c->n_groups; g++) {
		if (probed && !c->groups[g].has_probe[0] && !c->groups[g].has_probe[1])
			continue;
		for (size_t m = 0; m < c->groups[g].n_members; m++)
			if (c->groups[g].members[m].dev == d)
				return true;
	}
	return false;
}

static struct kernel FS;	/* the foreign objects, as they must stay */

/* Is member nexthop d/f of c one the kernel won't take? */
static bool member_refused(const struct ifrender *r, int f)
{
	return refusing(f ? AF_INET6 : AF_INET, r->ifindex, refuse);
}

static void reference(struct tworld *t, struct kernel *k)
{
	const struct config *c;
	bool probe = false;

	k_init(k);
	if (!t->tc)
		return;
	c = &t->tc->c;
	for (size_t g = 0; g < c->n_groups; g++)
		probe = probe || c->groups[g].has_probe[0] || c->groups[g].has_probe[1];

	for (int f = 0; f < 2; f++) {
		int family = f ? AF_INET6 : AF_INET;

		if (c->n_groups)
			nh_insert(k, &(struct mnh){ .id = cfg_blackhole_nhid(c, f), .family = family,
			                            .proto = c->rt_proto, .blackhole = true });
		for (size_t d = 0; d < c->n_devices; d++) {
			const struct ifrender *r = &t->ifs[d].fam[f];
			struct mnh n = { .id = cfg_member_nhid(c, d, f), .family = family,
			                 .proto = c->rt_proto, .oif = r->ifindex, .has_gw = r->has_gw };

			if (!r->usable || !dev_in_group(c, d, false))
				continue;
			if (r->has_gw)
				memcpy(n.gw, r->gw, alen_of(family));
			if (member_refused(r, f))
				continue;
			nh_insert(k, &n);
			if (probe && dev_in_group(c, d, true))
				ref_route(k, f, cfg_probe_table(c), NULL, 0, d + 1, RTN_UNICAST,
				          c->rt_proto, 0, r->ifindex, r->has_gw, r->gw);
		}
		for (size_t g = 0; g < c->n_groups; g++) {
			const struct cfg_group *grp = &c->groups[g];
			struct mnh n = { .id = cfg_group_nhid(c, g, f), .group = true,
			                 .proto = c->rt_proto, .buckets = grp->buckets,
			                 .idle = grp->timer_idle * 100, .busy = grp->timer_busy * 100 };

			for (size_t m = 0; m < grp->n_members; m++)
				if (t->ifs[grp->members[m].dev].fam[f].usable &&
				    t->member_up[cfg_member_index(c, g, m)] &&
				    !member_refused(&t->ifs[grp->members[m].dev].fam[f], f)) {
					n.ids[n.n] = cfg_member_nhid(c, grp->members[m].dev, f);
					n.weights[n.n++] = grp->members[m].weight;
				}
			if (!n.n) {
				n.ids[n.n] = cfg_blackhole_nhid(c, f);
				n.weights[n.n++] = 1;
			}
			nh_insert(k, &n);
			/* the witness, and the blackhole behind it */
			ref_route(k, f, cfg_group_table(c, g), NULL, 0, 0, RTN_UNICAST, c->rt_proto,
			          n.id, 0, false, NULL);
			ref_route(k, f, cfg_group_table(c, g), NULL, 0, UINT32_MAX, RTN_BLACKHOLE,
			          c->rt_proto, 0, 0, false, NULL);
			if (grp->fwmark)
				rule_insert(k, &(struct mrule){ family, c->rt_proto, cfg_group_prio(c, g),
				                                grp->fwmark, c->fwmask,
				                                cfg_group_table(c, g) });
		}
		if (probe)
			rule_insert(k, &(struct mrule){ family, c->rt_proto, cfg_probe_prio(c),
			                                c->probe_mark, c->fwmask, cfg_probe_table(c) });
		rule_insert(k, &(struct mrule){ family, c->rt_proto, c->rule_prio, 0, c->fwmask,
		                                c->table_id });
	}
	for (size_t i = 0; i < c->n_p4; i++)
		ref_route(k, 0, c->table_id, c->p4[i].addr, c->p4[i].plen, 0, RTN_UNICAST,
		          c->rt_proto, cfg_group_nhid(c, c->rule_group[c->p4[i].rule], 0), 0, false,
		          NULL);
	for (size_t i = 0; i < c->n_p6; i++)
		ref_route(k, 1, c->table_id, c->p6[i].addr, c->p6[i].plen, 0, RTN_UNICAST,
		          c->rt_proto, cfg_group_nhid(c, c->rule_group[c->p6[i].rule], 1), 0, false,
		          NULL);
}

/* --- traffic: where a packet goes through the model's rules and tables --- */

enum res { R_NOTHING, R_BLACKHOLE, R_DEVS };

struct verdict {
	enum res res;
	uint64_t devs;
	uint32_t table, nh;	/* where it was decided */
	int plen;		/* by a route of this prefix length, -1 = none */
};

static const struct mroute *table_lookup(struct kernel *k, int family, uint32_t table,
                                         const uint8_t *addr)
{
	size_t alen = alen_of(family);

	for (int plen = alen * 8; plen >= 0; plen--) {
		uint8_t m[16] = {};
		const struct mroute *best = NULL;

		if (!k->plens[fi(family)][plen])
			continue;
		for (int i = 0; i < plen; i++)
			m[i / 8] |= addr[i / 8] & (0x80 >> (i % 8));
		for (int s = k->bucket[rhash(family, table, plen, m)]; s; s = k->r[s - 1].next) {
			const struct mroute *r = &k->r[s - 1];

			if (r->family == family && r->table == table && r->dst_len == plen &&
			    !memcmp(r->dst, m, 16) && !r->tos && !r->src_len &&
			    (!best || r->metric < best->metric))
				best = r;
		}
		if (best)
			return best;
	}
	return NULL;
}

/* Where route r of table sends traffic. */
static struct verdict route_verdict(struct kernel *k, const struct mroute *r, uint32_t table)
{
	struct verdict v = { R_DEVS, 0, table, r->nh_id, r->dst_len };

	if (r->type == RTN_BLACKHOLE)
		return (struct verdict){ R_BLACKHOLE, 0, table, 0, r->dst_len };
	if (r->nh_id) {
		const struct mnh *n = nh_get(k, r->nh_id), *p[MAX_NH_GROUP];
		size_t c = n ? nh_paths(k, n, p) : 0;

		if (c == 1 && p[0]->blackhole)
			return (struct verdict){ R_BLACKHOLE, 0, table, r->nh_id, r->dst_len };
		for (size_t j = 0; j < c; j++)
			v.devs |= p[j]->oif < 64 ? 1ull << p[j]->oif : 1ull << 63;
	} else {
		v.devs = r->oif < 64 ? 1ull << r->oif : 1ull << 63;
	}
	return v;
}

static struct verdict resolve(struct kernel *k, int family, const uint8_t *addr, uint32_t mark)
{
	int l = rule_list(family);

	for (size_t i = 0; i < k->nru[l]; i++) {
		const struct mrule *ru = &k->ru[l][i];
		const struct mroute *r;

		if ((mark ^ ru->mark) & ru->mask)
			continue;
		if (ru->table == RT_TABLE_MAIN)
			return (struct verdict){ R_NOTHING, 0, ru->table, 0, -1 };
		if ((r = table_lookup(k, family, ru->table, addr)))
			return route_verdict(k, r, ru->table);
	}
	return (struct verdict){ R_NOTHING, 0, 0, 0, -1 };
}

/* What has to keep flowing during an apply. */
struct target {
	int family;
	uint8_t addr[16];	/* the probe address */
	uint8_t net[16], plen;	/* the prefix it stands for (mark targets: 0/0) */
	uint32_t mark;
	uint64_t allowed;
	bool absent_ok, active, dirty;
	uint32_t tables[2];	/* where its routes live in prev and want */
	char desc[96];
};

#define MAXTARGETS 4096

static struct target targets[MAXTARGETS];
static size_t n_targets;
static struct tworld *inv_prev, *inv_want;	/* the worlds the invariants speak of */

static bool target_ok(struct kernel *k, const struct target *t, struct verdict *v)
{
	*v = resolve(k, t->family, t->addr, t->mark);
	/* decided by a covering prefix's route: this one is absent */
	if (t->absent_ok && v->res != R_NOTHING && v->plen < t->plen)
		return true;
	switch (v->res) {
	case R_BLACKHOLE:
		return true;
	case R_NOTHING:
		return t->absent_ok;
	case R_DEVS:
		return !(v->devs & ~t->allowed);
	}
	return false;
}

static void verdict_fmt(const struct verdict *v, char *buf, size_t len)
{
	int o;

	if (v->res == R_NOTHING) {
		snprintf(buf, len, "nothing (falls through to main)");
		return;
	}
	if (v->res == R_BLACKHOLE) {
		snprintf(buf, len, "blackhole (table %u nhid %u)", v->table, v->nh);
		return;
	}
	o = snprintf(buf, len, "devices");
	for (int i = 0; i < 64; i++)
		if (v->devs & 1ull << i)
			o += snprintf(buf + o, len - o, " %d", i);
	snprintf(buf + o, len - o, " (table %u nhid %u)", v->table, v->nh);
}

static void targets_build(struct tworld *p, struct tworld *w)
{
	unsigned top[2] = { NPOOL4, NPOOL6 };

	/* the pool, as far as either world draws from it */
	for (int i = 0; i < 2; i++) {
		const struct tworld *t = i ? w : p;

		for (size_t j = 0; t->tc && j < t->tc->src.np; j++)
			if (t->tc->src.p[j].key >= top[t->tc->src.p[j].f])
				top[t->tc->src.p[j].f] = t->tc->src.p[j].key + 1;
	}
	n_targets = 0;
	for (int f = 0; f < 2; f++)
		for (unsigned key = 0; key < top[f] && n_targets < MAXTARGETS - 16; key++) {
			uint8_t addr[16], plen;
			int gp, gw;
			struct target *t;
			char a[INET6_ADDRSTRLEN];

			pool_prefix(f, key, addr, &plen);
			gp = prefix_group(p, f, addr, plen);
			gw = prefix_group(w, f, addr, plen);
			if (gp < 0 && gw < 0)
				continue;
			t = &targets[n_targets++];
			memset(t, 0, sizeof(*t));
			t->family = f ? AF_INET6 : AF_INET;
			memcpy(t->net, addr, 16);
			t->plen = plen;
			memcpy(t->addr, addr, 16);
			for (int i = plen; i < (f ? 128 : 32); i++)
				t->addr[i / 8] |= 0x80 >> (i % 8);
			/* a route stays on its group while that group changes: both groups, both worlds */
			t->allowed = (gp >= 0 ? group_devs(p, w, gp, f) : 0) |
			             (gw >= 0 ? group_devs(p, w, gw, f) : 0);
			t->absent_ok = gp < 0 || gw < 0;
			t->tables[0] = p->tc ? p->tc->c.table_id : 0;
			t->tables[1] = w->tc ? w->tc->c.table_id : 0;
			addr_fmt(t->family, addr, a);
			snprintf(t->desc, sizeof(t->desc), "prefix %s/%u (group %s -> %s)", a, plen,
			         gp >= 0 ? group_names[gp] : "-", gw >= 0 ? group_names[gw] : "-");
		}
	for (size_t g = 0; p->tc && w->tc && g < p->tc->src.ng; g++) {
		const struct tgroup *a = &p->tc->src.g[g], *b = src_group(&w->tc->src, a->name);

		if (!b || !a->fwmark || a->fwmark != b->fwmark)
			continue;
		for (int f = 0; f < 2; f++) {
			struct target *t = &targets[n_targets++];

			memset(t, 0, sizeof(*t));
			t->family = f ? AF_INET6 : AF_INET;
			if (!f) {
				t->addr[0] = 198, t->addr[1] = 51, t->addr[2] = 100, t->addr[3] = 1;
			} else {
				t->addr[0] = 0x20, t->addr[1] = 0x01, t->addr[2] = 0x0d;
				t->addr[3] = 0xb8, t->addr[4] = 0xff, t->addr[5] = 0xfe, t->addr[15] = 1;
			}
			t->mark = a->fwmark;
			t->tables[0] = cfg_group_table(&p->tc->c, g);
			t->tables[1] = cfg_group_table(&w->tc->c, b - w->tc->src.g);
			t->allowed = group_devs(p, w, a->name, f);
			snprintf(t->desc, sizeof(t->desc), "v%c traffic marked %#x (group %s)",
			         f ? '6' : '4', a->fwmark, group_names[a->name]);
		}
	}
}

/* Targets that hold now are checked from now on; the others can't be blamed on sync. */
static void targets_baseline(void)
{
	struct verdict v;

	for (size_t i = 0; i < n_targets; i++) {
		struct target *t = &targets[i];

		/* a prefix whose own route is missing already is the kernel's doing */
		t->active = target_ok(K, t, &v) && !(v.res != R_NOTHING && v.plen < t->plen);
		/*
		 * So is a route of its own that already goes astray, hidden for
		 * now (its rule is missing, another route comes first): a sync
		 * that puts the rule back merely shows it.
		 */
		for (int j = 0; j < 2 && t->active; j++) {
			const struct mroute *r = t->tables[j] ?
				table_lookup(K, t->family, t->tables[j], t->addr) : NULL;
			struct verdict rv;

			if (!r || r->dst_len < t->plen)
				continue;
			rv = route_verdict(K, r, t->tables[j]);
			t->active = rv.res != R_DEVS || !(rv.devs & ~t->allowed);
		}
	}
}

static unsigned msg_index;

static void targets_check(const struct nlmsghdr *nlh, bool all)
{
	for (size_t i = 0; i < n_targets; i++) {
		struct target *t = &targets[i];
		struct verdict v;
		char buf[160];

		if (!t->active || !(all || t->dirty))
			continue;
		t->dirty = false;
		if (target_ok(K, t, &v))
			continue;
		verdict_fmt(&v, buf, sizeof(buf));
		{
			char d[160];

			describe(nlh, d, sizeof(d));
			violation("after request #%u (%s): %s goes to %s", msg_index, d, t->desc, buf);
		}
		t->active = false;
	}
}

/* Which targets a route request can affect: those it covers. */
static void targets_mark(const struct nlmsghdr *nlh)
{
	const struct rtmsg *rtm = mnl_nlmsg_get_payload(nlh);
	struct attrs t = {};
	uint8_t dst[16] = {};

	mnl_attr_parse(nlh, sizeof(*rtm), attrs_cb, &t);
	if (t.tb[RTA_DST] && mnl_attr_get_payload_len(t.tb[RTA_DST]) <= 16)
		memcpy(dst, mnl_attr_get_payload(t.tb[RTA_DST]), mnl_attr_get_payload_len(t.tb[RTA_DST]));
	for (size_t i = 0; i < n_targets; i++) {
		struct target *tg = &targets[i];
		bool in = tg->family == rtm->rtm_family;

		for (int b = 0; in && b < rtm->rtm_dst_len && b < 128; b++)
			in = !((tg->addr[b / 8] ^ dst[b / 8]) & (0x80 >> (b % 8)));
		tg->dirty = tg->dirty || in;
	}
}

/* --- perturbations: the kernel and others, behind routebot's back --- */

enum pkind {
	P_LINK,		/* a link flaps */
	P_ADDR4,	/* a link's last v4 address goes */
	P_GROUP,	/* someone deletes a group */
	P_WITNESS,	/* someone deletes a group's default route */
	P_RULE,		/* someone deletes a rule of ours */
	P_CORRUPT,	/* someone changes a nexthop of ours */
	P_FOREIGN,	/* someone adds things of their own */
	P_LEFTOVER,	/* objects with our proto that sync observes */
	P_REFUSE,	/* a link flaps and comes back refusing nexthops and routes */
	P_UNREFUSE,	/* ... and takes them again */
	P_N_ANYTIME,
	P_LEFTOVER_FULL = P_N_ANYTIME,	/* prefix routes only a full sync sees */
	P_N,
	/* before a step only, never drawn at random from the above */
	P_GROUP_A = P_N,	/* group a's v4 nexthop (1004 in the named base) deleted */
};

static const char *const pkind_names[] = { "link flap", "last v4 address gone",
	"group deleted", "witness deleted", "rule deleted", "nexthop changed", "foreign objects",
	"leftovers", "refusal", "refusal lifted", "leftover prefix routes", "group a deleted" };

static uint32_t next_foreign_id = 10, next_leftover_id = 3000;

/* sync may then count errors, and retry what it can't have on every sync */
static bool refusals(void)
{
	return refuse[0] || refuse[1];
}

/* A device for a nexthop of family that someone else creates: one that takes it. */
static int taking_oif(int family)
{
	for (int tries = 0; tries < 32; tries++) {
		int oif = 2 + rnd(8);

		if (!refusing(family, oif, refuse))
			return oif;
	}
	return 50;
}

/* Ifindexes our nexthops and plain routes use. */
static int pick_ifindex(struct kernel *k)
{
	int cand[MAXNH + MAXR], n = 0;

	for (size_t i = 0; i < k->nnh; i++)
		if (ours(k->nh[i].proto) && !k->nh[i].group && !k->nh[i].blackhole)
			cand[n++] = k->nh[i].oif;
	for (int i = 0; i < MAXR; i++)
		if (k->r[i].used && ours(k->r[i].proto) && !k->r[i].nh_id && k->r[i].oif)
			cand[n++] = k->r[i].oif;
	return n ? cand[rnd(n)] : 2 + (int)rnd(8);
}

static uint32_t small_table(const struct tworld *t)
{
	const struct config *c = &t->tc->c;

	return rnd(c->n_groups + 1) ? cfg_group_table(c, rnd(c->n_groups)) : cfg_probe_table(c);
}

static void foreign_add(struct kernel *k, const struct tworld *t)
{
	uint8_t dst[16] = {};
	struct mroute r = {};

	switch (rnd(3)) {
	case 0: {
		struct mnh n = { .id = next_foreign_id++, .proto = PROTO_FOREIGN };

		if (next_foreign_id > 99)
			next_foreign_id = 10;
		if (nh_get(k, n.id))
			return;
		n.family = rnd(2) ? AF_INET6 : AF_INET;
		if (rnd(2))
			n.blackhole = true;
		else
			n.oif = 50;
		nh_insert(k, &n);
		nh_insert(&FS, &n);
		return;
	}
	case 1:
		r.family = rnd(2) ? AF_INET6 : AF_INET;
		r.proto = PROTO_FOREIGN;
		r.table = !t->tc || rnd(3) == 0 ? 7000 : rnd(2) ? t->tc->c.table_id : small_table(t);
		if (r.family == AF_INET) {
			dst[0] = 192, dst[1] = 0, dst[2] = 2, dst[3] = rnd(4) * 64;
			r.dst_len = 26;
		} else {
			dst[0] = 0x20, dst[1] = 0x01, dst[2] = 0x0d, dst[3] = 0xb8;
			dst[4] = dst[5] = 0xff, dst[7] = rnd(4);
			r.dst_len = 64;
			r.metric = 1024;
		}
		memcpy(r.dst, dst, 16);
		if (rnd(2)) {
			r.type = RTN_BLACKHOLE;
		} else {
			r.type = RTN_UNICAST;
			r.oif = 50;
			r.scope = r.family == AF_INET ? RT_SCOPE_LINK : 0;
		}
		if (r_find(k, &r) >= 0)
			return;
		r_insert(k, &r);
		table_add(k, r.family, r.table);
		r_insert(&FS, &r);
		return;
	default: {
		struct mrule ru = { rnd(2) ? AF_INET6 : AF_INET, PROTO_FOREIGN, rnd(2) ? 5 : 40000,
		                    0x1234, 0xffff, 250 };

		rule_insert(k, &ru);
		rule_insert(&FS, &ru);
		return;
	}
	}
}

/* Objects with our proto that only a crash under another config would leave. */
static void leftover_add(struct kernel *k, const struct tworld *t, bool full)
{
	uint8_t proto = t->tc->c.rt_proto;
	struct mroute r = {};
	unsigned key;

	if (!full)
		switch (rnd(3)) {
		case 0: {
			struct mnh n = { .id = next_leftover_id++, .proto = proto };

			n.family = rnd(2) ? AF_INET6 : AF_INET;
			if (rnd(3) == 0) {
				n.blackhole = true;
			} else {
				n.oif = taking_oif(n.family);
			}
			nh_insert(k, &n);
			if (!n.blackhole && rnd(2)) {
				struct mnh g = { .id = next_leftover_id++, .group = true, .proto = proto,
				                 .n = 1, .buckets = 8 };

				g.ids[0] = n.id;
				g.weights[0] = 1;
				nh_insert(k, &g);
			}
			return;
		}
		case 1: {
			struct mrule ru = { rnd(2) ? AF_INET6 : AF_INET, proto, 900 + rnd(300),
			                    0x7f000000, 0xff000000, rnd(2) ? small_table(t) : 6000 };

			rule_insert(k, &ru);
			return;
		}
		default:
			r.family = rnd(2) ? AF_INET6 : AF_INET;
			r.table = small_table(t);
			r.proto = proto;
			r.type = RTN_BLACKHOLE;
			if (rnd(2)) {
				/* a default behind ours, or a prefix: neither changes where traffic goes */
				r.metric = 7;
			} else {
				pool_prefix(fi(r.family), rnd(r.family == AF_INET ? NPOOL4 : NPOOL6), r.dst,
				            &r.dst_len);
				r.metric = r.family == AF_INET6 ? 1024 : 0;
			}
			if (r_find(k, &r) < 0) {
				r_insert(k, &r);
				table_add(k, r.family, r.table);
			}
			return;
		}

	/* prefix routes in our tables or others: only a full sync sees them */
	r.family = rnd(2) ? AF_INET6 : AF_INET;
	key = rnd(r.family == AF_INET ? NPOOL4 : NPOOL6);
	pool_prefix(fi(r.family), key, r.dst, &r.dst_len);
	r.proto = proto;
	r.table = rnd(3) ? t->tc->c.table_id : rnd(2) ? 7777 : t->tc->c.table_id == 100 ? 5000 : 100;
	r.metric = r.family == AF_INET6 ? 1024 : 0;
	switch (rnd(4)) {
	case 0:
		if (r.family == AF_INET)
			r.tos = 0x10;
		else {
			r.src_len = 64;
			memcpy(r.src, r.dst, 16);
			r.src[6] = 0x99;
		}
		break;
	case 1:
		r.metric = 5;
		break;
	}
	if (rnd(2)) {
		r.type = RTN_BLACKHOLE;
	} else {
		/* on one of our nexthops, any: maybe the wrong group's */
		size_t i = rnd(k->nnh ? k->nnh : 1);

		r.type = RTN_BLACKHOLE;
		if (k->nnh && ours(k->nh[i].proto) && !r.src_len) {
			struct mnh *n = &k->nh[i];
			const struct mnh *p[MAX_NH_GROUP];
			size_t c = nh_paths(k, n, p);
			bool fam_ok = c > 0;

			for (size_t j = 0; j < c; j++)
				fam_ok = fam_ok && p[j]->family == r.family;
			if (fam_ok) {
				r.type = RTN_UNICAST;
				r.nh_id = n->id;
			}
		}
	}
	if (r_find(k, &r) < 0) {
		r_insert(k, &r);
		table_add(k, r.family, r.table);
	}
}

/* One perturbation of kind p; returns whether it did anything. */
static bool perturb(struct kernel *k, enum pkind p, const struct tworld *t)
{
	char buf[256];
	size_t n = 0;

	totals.perturbs++;
	switch (p) {
	case P_LINK: {
		int ifi = pick_ifindex(k);

		link_flush(k, ifi);
		mlog("  ** link %d flapped\n", ifi);
		return true;
	}
	case P_ADDR4: {
		int ifi = pick_ifindex(k);

		addr4_flush(k, ifi);
		mlog("  ** link %d lost its last v4 address\n", ifi);
		return true;
	}
	case P_GROUP:
	case P_CORRUPT: {
		uint32_t ids[MAXNH];

		for (size_t i = 0; i < k->nnh; i++)
			if (ours(k->nh[i].proto) && (p == P_CORRUPT || k->nh[i].group))
				ids[n++] = k->nh[i].id;
		if (!n)
			return false;
		if (p == P_GROUP) {
			uint32_t id = ids[rnd(n)];

			nh_remove(k, id, BY_KERNEL);
			mlog("  ** nexthop %u deleted\n", id);
			return true;
		} else {
			struct mnh *o = nh_get(k, ids[rnd(n)]);

			if (o->group) {
				/* deleted and created anew, other buckets: its routes went */
				struct mnh g = *o;

				nh_remove(k, g.id, BY_KERNEL);
				g.buckets *= 2;
				for (uint16_t j = 0; j < g.n; j++)
					if (!nh_get(k, g.ids[j]))
						return true;
				nh_insert(k, &g);
				mlog("  ** group %u re-created with %u buckets\n", g.id, g.buckets);
			} else if (o->blackhole) {
				uint32_t id = o->id;

				nh_remove(k, id, BY_KERNEL);
				mlog("  ** blackhole %u deleted\n", id);
			} else {
				o->oif = taking_oif(o->family);
				o->has_gw = false;
				memset(o->gw, 0, 16);
				mlog("  ** nexthop %u: now dev %d\n", o->id, o->oif);
			}
			return true;
		}
	}
	case P_WITNESS:
	case P_RULE:
		if (!t->tc)
			return false;
		if (p == P_WITNESS) {
			int slots[64];

			for (int i = 0; i < MAXR && n < 64; i++) {
				const struct mroute *r = &k->r[i];

				if (r->used && ours(r->proto) && !r->dst_len && r->nh_id &&
				    r->table >= cfg_group_table(&t->tc->c, 0) &&
				    r->table < cfg_group_table(&t->tc->c, t->tc->c.n_groups))
					slots[n++] = i;
			}
			if (!n)
				return false;
			n = slots[rnd(n)];
			route_text(k, &k->r[n], false, buf, sizeof(buf));
			mlog("  ** %s deleted\n", buf);
			r_remove(k, n);
		} else {
			int l = rnd(2) ? 3 : 0;
			size_t idx[MAXRU];

			for (size_t i = 0; i < k->nru[l]; i++)
				if (ours(k->ru[l][i].proto))
					idx[n++] = i;
			if (!n)
				return false;
			n = idx[rnd(n)];
			rule_text(&k->ru[l][n], buf, sizeof(buf));
			mlog("  ** %s deleted\n", buf);
			rule_remove(k, l, n);
		}
		return true;
	case P_FOREIGN:
		foreign_add(k, t);
		mlog("  ** foreign objects added\n");
		return true;
	case P_REFUSE: {
		int ifi = pick_ifindex(k), f = rnd(2);

		if (ifi >= 64)
			return false;
		refuse[f] |= 1ull << ifi;
		link_flush(k, ifi);
		mlog("  ** link %d flapped, now refuses v%c\n", ifi, f ? '6' : '4');
		return true;
	}
	case P_UNREFUSE:
		if (!refusals())
			return false;
		refuse[rnd(2)] = 0;
		mlog("  ** refusals lifted\n");
		return true;
	case P_GROUP_A:
		nh_remove(k, 1004, BY_KERNEL);
		mlog("  ** nexthop 1004 deleted\n");
		return true;
	case P_LEFTOVER:
	case P_LEFTOVER_FULL:
		if (!t->tc)
			return false;
		for (unsigned i = 1 + rnd(4); i; i--)
			leftover_add(k, t, p == P_LEFTOVER_FULL);
		mlog("  ** %s added\n", pkind_names[p]);
		return true;
	default:
		return false;
	}
}

/* Prefix routes of t's CIDR table: the requests that count as prefix requests. */
static bool prefix_table(uint32_t table)
{
	return (inv_prev && inv_prev->tc && table == inv_prev->tc->c.table_id) ||
	       (inv_want && inv_want->tc && table == inv_want->tc->c.table_id);
}

/* Is (family, dst, plen) a prefix inv_want has? */
static bool want_has_prefix(int family, const uint8_t *dst, uint8_t plen)
{
	return inv_want && prefix_group(inv_want, fi(family), dst, plen) >= 0;
}

static void note_route_gone(const struct mroute *r, enum cause c)
{
	char buf[256];

	if (!checking || c != BY_ROUTEBOT || !inv_want || !inv_want->tc ||
	    r->table != inv_want->tc->c.table_id || r->tos || r->src_len ||
	    r->metric != (r->family == AF_INET6 ? 1024u : 0u) ||
	    !want_has_prefix(r->family, r->dst, r->dst_len))
		return;
	acc.leaks++;
	route_text(K, r, false, buf, sizeof(buf));
	violation("request #%u deleted the nexthop under a wanted prefix route: %s went with it",
	     acc.msgs, buf);
}

/* A perturbation armed to hit in the middle of an apply. */
static struct {
	bool armed, hit;
	unsigned at;
	enum pkind kind;
	const struct tworld *t;
} race;

/*
 * The order of a full reconcile: every prefix route at a key want has but
 * on another nexthop is first made a plain blackhole, then set.
 */
#define MAXAUDIT 2048

static struct kernel kref;	/* what want renders to */
static struct {
	bool on;
	struct mroute wrong[MAXAUDIT];	/* wanted keys on the wrong nexthop */
	bool seen[MAXAUDIT];
	size_t n_wrong;
} au;

static void audit_start(const struct world *sp, const struct tworld *w)
{
	const struct config *c = w->tc ? &w->tc->c : NULL;

	au.on = c != NULL;
	au.n_wrong = 0;
	if (!c)
		return;
	for (int i = 0; i < MAXR; i++) {
		const struct mroute *r = &K->r[i];
		int slot;

		if (!r->used || r->table != c->table_id ||
		    !(r->proto == c->rt_proto || (sp->cfg && r->proto == sp->cfg->rt_proto)))
			continue;
		slot = r_find(&kref, r);
		if (slot >= 0 && r->type == RTN_UNICAST && r->nh_id &&
		    r->nh_id != kref.r[slot].nh_id && au.n_wrong < MAXAUDIT) {
			au.seen[au.n_wrong] = false;
			au.wrong[au.n_wrong++] = *r;
		}
	}
}

/* The key a route request names. */
static void request_key(const struct nlmsghdr *nlh, struct mroute *r)
{
	const struct rtmsg *rtm = mnl_nlmsg_get_payload(nlh);
	struct attrs t = {};

	memset(r, 0, sizeof(*r));
	mnl_attr_parse(nlh, sizeof(*rtm), attrs_cb, &t);
	r->family = rtm->rtm_family;
	r->dst_len = rtm->rtm_dst_len;
	r->src_len = rtm->rtm_src_len;
	r->tos = rtm->rtm_tos;
	r->table = rtm->rtm_table;
	attr_u32(&t, RTA_TABLE, &r->table);
	attr_u32(&t, RTA_PRIORITY, &r->metric);
	if (r->family == AF_INET6 && !r->metric)
		r->metric = 1024;
	if (t.tb[RTA_DST] && mnl_attr_get_payload_len(t.tb[RTA_DST]) <= 16)
		memcpy(r->dst, mnl_attr_get_payload(t.tb[RTA_DST]),
		       mnl_attr_get_payload_len(t.tb[RTA_DST]));
	if (t.tb[RTA_SRC] && mnl_attr_get_payload_len(t.tb[RTA_SRC]) <= 16)
		memcpy(r->src, mnl_attr_get_payload(t.tb[RTA_SRC]),
		       mnl_attr_get_payload_len(t.tb[RTA_SRC]));
}

static void audit_message(const struct nlmsghdr *nlh)
{
	const struct rtmsg *rtm = mnl_nlmsg_get_payload(nlh);
	char buf[256];
	struct mroute k;

	if (!au.on || (nlh->nlmsg_type != RTM_NEWROUTE && nlh->nlmsg_type != RTM_DELROUTE))
		return;
	request_key(nlh, &k);
	for (size_t i = 0; i < au.n_wrong; i++) {
		if (au.seen[i] || !rkey_eq(&au.wrong[i], &k))
			continue;
		au.seen[i] = true;
		route_text(K, &au.wrong[i], false, buf, sizeof(buf));
		CHECK(nlh->nlmsg_type == RTM_NEWROUTE && rtm->rtm_type == RTN_BLACKHOLE,
		      "request #%u: full sync: %s is on the wrong nexthop and was not first "
		      "made a blackhole", acc.msgs, buf);
	}
}

static void before_message(void)
{
	if (!checking || !race.armed || acc.msgs != race.at)
		return;
	race.armed = false;
	race.hit = true;
	after_race = true;
	au.on = false;	/* the rest of the batch was planned on what was before */
	totals.races_hit++;
	perturb(K, race.kind, race.t);
	/* what the race broke isn't sync's doing */
	targets_baseline();
}

static void test_bug(const char *what)
{
	fail("model: %s", what);
}

static void after_message(const struct nlmsghdr *nlh)
{
	if (checking)
		audit_message(nlh);
	bool route = nlh->nlmsg_type == RTM_NEWROUTE || nlh->nlmsg_type == RTM_DELROUTE;

	msg_index = acc.msgs++;
	totals.msgs++;
	if (route) {
		const struct rtmsg *rtm = mnl_nlmsg_get_payload(nlh);
		struct attrs t = {};
		uint32_t table = rtm->rtm_table;

		acc.route_msgs++;
		mnl_attr_parse(nlh, sizeof(*rtm), attrs_cb, &t);
		attr_u32(&t, RTA_TABLE, &table);
		if (prefix_table(table)) {
			acc.prefix_msgs++;
			if (nlh->nlmsg_type == RTM_NEWROUTE)
				acc.prefix_set++;
			else
				acc.prefix_del++;
		}
	} else if (nlh->nlmsg_type == RTM_NEWNEXTHOP || nlh->nlmsg_type == RTM_DELNEXTHOP) {
		acc.nh_msgs++;
	} else {
		acc.rule_msgs++;
	}
	if (!checking)
		return;
	if (route)
		targets_mark(nlh);
	targets_check(nlh, !route);
}

/* --- steps --- */

static struct sync *S_fresh;	/* fresh installs', apart from S, the one under test */
static struct tworld empty_world;

struct step_opts {
	bool full;
	bool restart;		/* prev = nothing: a crash, then startup */
	bool race;		/* a perturbation in the middle */
	enum pkind race_kind;
	unsigned race_at;
};

struct step_result {
	struct acct a;		/* the main apply */
	int ret;
	bool raced;
	bool skipped;		/* not run: TEST_SYNC_ONLY */
};

static void reset_step(const char *what)
{
	step_no++;
	step_fails = 0;
	step_what = what;
	loglen = msglen = 0;
	logbuf[0] = msglog[0] = '\0';
	totals.steps++;
}

static void report_step(struct tworld *prev, struct tworld *want)
{
	if (!step_fails || reports > MAX_REPORTS)
		return;
	world_text(prev, "prev");
	world_text(want, "want");
	fprintf(stderr, "    requests:\n%s", msglog);
	if (loglen)
		fprintf(stderr, "    routebot said:\n%s", logbuf);
}

/* One apply with every invariant checked; full or not, worlds as given. */
static int apply(const struct world *sp, struct tworld *ip, struct tworld *w, bool full,
                 struct sync_stats *st)
{
	int ret;

	memset(&acc, 0, sizeof(acc));
	inv_prev = ip;
	inv_want = w;
	targets_build(ip, w);
	targets_baseline();
	au.on = false;
	if (full && !after_race)
		audit_start(sp, w);
	checking = true;
	ret = sync_apply(S, &nl, sp, tw_world(w), full, st);
	checking = false;
	au.on = false;
	totals.applies++;
	totals.unexpected += acc.unexpected;
	CHECK(!q_len(&dumpq) && !q_len(&errq) && !ds.active,
	      "%zu datagrams left unread after sync_apply (a dump %s)",
	      q_len(&dumpq) + q_len(&errq), ds.active ? "unfinished" : "done");
	q_clear();
	/* a sweep counts what its dumps saw go, to which a race can add */
	CHECK(after_race || (st->route_set + st->route_del == acc.route_msgs &&
	      st->nh_set + st->nh_del == acc.nh_msgs && st->rule_add + st->rule_del == acc.rule_msgs),
	      "stats say %u+%u routes, %u+%u nexthops, %u+%u rules; sent %u, %u, %u",
	      st->route_set, st->route_del, st->nh_set, st->nh_del, st->rule_add, st->rule_del,
	      acc.route_msgs, acc.nh_msgs, acc.rule_msgs);
	return ret;
}

/* The fresh install of w: an empty kernel, sync from nothing. */
static void fresh_install(struct tworld *w, struct kernel *out)
{
	struct kernel *saved = K;
	struct sync_stats st;
	struct acct sa = acc;
	int ret;

	/* a kernel with everybody else's objects and none of ours */
	*out = FS;
	K = out;
	inv_prev = inv_want = NULL;
	memset(&acc, 0, sizeof(acc));
	ret = sync_apply(S_fresh, &nl, tw_world(&empty_world), tw_world(w), true, &st);
	q_clear();
	CHECK(!ret && acc.unexpected == acc.refused && (refusals() || !st.errors),
	      "fresh install: returned %d, %u requests failed, %u errors", ret, acc.unexpected,
	      st.errors);
	K = saved;
	acc = sa;
}

static struct kernel kfresh, kref, kprev;

/*
 * The kernel holds prev (more or less: perturbed already); bring it to want
 * and check everything.
 */
static struct step_result step(const char *what, struct tworld *prev, struct tworld *want,
                               const struct step_opts *o)
{
	struct step_result res = {};
	struct sync_stats st;
	char *got, *ref, *fresh, *fb, *fa;
	bool intact, at_want;

	reset_step(what);

	reference(want, &kref);
	fresh_install(want, &kfresh);
	ref = kernel_text(&kref, OURS);
	fresh = kernel_text(&kfresh, OURS);
	same_text(fresh, ref, "a fresh install differs from the reference rendering");
	free(ref);

	/* is the kernel what prev renders to, nothing perturbed? already want? */
	reference(prev, &kprev);
	got = kernel_text(K, OURS);
	ref = kernel_text(&kprev, OURS);
	intact = !strcmp(got, ref);
	at_want = !strcmp(got, fresh);
	free(got);
	free(ref);

	race.armed = o->race;
	race.hit = false;
	after_race = false;
	race.at = o->race_at;
	race.kind = o->race_kind;
	race.t = want;
	if (o->race)
		totals.races++;

	mlog("  apply (%s%s):\n", o->full ? "full" : "diff",
	     o->restart ? ", restart" : "");
	res.ret = apply(o->restart ? tw_world(&empty_world) : tw_world(prev), prev, want, o->full,
	                &st);
	res.a = acc;
	res.raced = race.hit;
	race.armed = false;
	after_race = false;

	if (!race.hit) {
		CHECK(!res.ret, "sync_apply returned %d with nothing in its way", res.ret);
		CHECK(acc.unexpected == acc.refused && (refusals() || !st.errors),
		      "%u requests failed (%u refused by devices), %u errors, with nothing in "
		      "their way", acc.unexpected, acc.refused, st.errors);
		CHECK(!(intact && !o->restart && prev->tc == want->tc && !refusals()) || !st.lost,
		      "%u objects reported lost from an intact kernel", st.lost);
		/* what the kernel refuses is asked again on every sync */
		if (intact && !refusals() && !o->full && prev->tc == want->tc &&
		    !memcmp(&prev->env, &want->env, sizeof(prev->env)))
			CHECK(!acc.msgs, "%u requests sent with nothing changed", acc.msgs);
		if (intact && !o->full && prev->tc == want->tc) {
			bool only_up = true;

			for (int s = 0; s < NSPEC; s++)
				for (int f = 0; f < 2; f++) {
					const struct ifrender *a = &prev->env.spec[s][f],
					                      *b = &want->env.spec[s][f];

					only_up = only_up && a->ifindex == b->ifindex &&
					          a->has_gw == b->has_gw && !memcmp(a->gw, b->gw, 16);
				}
			if (only_up)
				CHECK(!acc.prefix_msgs,
				      "%u prefix route requests for member changes alone", acc.prefix_msgs);
		}
		if (at_want && !refusals() && o->full)
			CHECK(!acc.route_msgs, "%u route requests from a full sync of a kernel "
			      "already equal to a fresh install", acc.route_msgs);
	}

	/* the next sync repairs what got in the way: a retry, or the event's */
	if (res.ret || race.hit) {
		bool m = res.ret;
		int ret;

		totals.followups++;
		mlog("  follow-up (%s):\n", m ? "full" : "diff");
		ret = apply(tw_world(want), want, want, m, &st);
		if (ret && !m) {
			totals.full_retries++;
			mlog("  follow-up (full):\n");
			ret = apply(tw_world(want), want, want, true, &st);
		}
		CHECK(!ret && acc.unexpected == acc.refused && (refusals() || !st.errors),
		      "follow-up sync returned %d, %u requests failed, %u errors", ret,
		      acc.unexpected, st.errors);
	}

	/* a race that changed what the devices take changed it too */
	if (res.raced) {
		free(fresh);
		fresh_install(want, &kfresh);
		fresh = kernel_text(&kfresh, OURS);
	}
	got = kernel_text(K, OURS);
	same_text(got, fresh, "the kernel differs from a fresh install");
	free(got);
	free(fresh);
	fa = kernel_text(K, FOREIGN);
	fb = kernel_text(&FS, FOREIGN);
	same_text(fa, fb, "foreign objects changed");
	free(fa);
	free(fb);
	q_clear();
	report_step(prev, want);
	return res;
}

/* An empty kernel, devices that take everything. */
static void kernel_reset(void)
{
	k_init(K);
	k_init(&FS);
	memset(refuse, 0, sizeof(refuse));
	/* a new sync for every scenario: nothing told carries over */
	sync_free(S);
	S = sync_new();
}

static void begin(const char *name, struct tworld *w)
{
	struct step_opts o = { .full = true, .restart = true };

	snprintf(scenario, sizeof(scenario), "%s", name);
	step_no = 0;
	kernel_reset();
	/* sync always has a config to bring the kernel to: nothing to install */
	if (w->tc)
		step("install", &empty_world, w, &o);
}

/* --- named scenarios --- */

static struct kernel kmain;

static struct tgroup mkgroup(uint8_t name, uint32_t fwmark, uint16_t buckets)
{
	return (struct tgroup){ .name = name, .fwmark = fwmark, .buckets = buckets, .idle = 120,
	                        .busy = 600 };
}

static void add_member(struct tgroup *g, uint8_t spec, uint16_t weight)
{
	g->spec[g->n] = spec;
	g->weight[g->n++] = weight;
}

static void add_prefix(struct tsrc *s, int f, unsigned key, uint8_t rule)
{
	if (s->np == MAXP)
		return;
	s->p[s->np].f = f;
	s->p[s->np].key = key;
	s->p[s->np++].rule = rule;
}

/*
 * Groups: a = dev0, dev1 (fwmark), b = dev2 (fwmark, probed v4),
 * c = dev3 (no fwmark). Rules 0 -> a, 1 -> b, 2 -> c.
 * v4 keys 0..5 and 11 (10.5.0.0/24) rule 0, 6..9 rule 1, 10 (10.5.0.0/16) rule 2;
 * v6 0..2 rule 0, 3 rule 1.
 */
static struct tsrc base_src(void)
{
	struct tsrc s = { .table_id = 100, .rule_prio = 1000, .nexthop_id = 1000,
	                  .proto = PROTO_A };

	s.g[0] = mkgroup(0, 0x01000000, 16);
	add_member(&s.g[0], 0, 1);
	add_member(&s.g[0], 1, 2);
	s.g[1] = mkgroup(1, 0x02000000, 16);
	add_member(&s.g[1], 2, 1);
	s.g[1].probe[0] = true;
	s.g[2] = mkgroup(2, 0, 8);
	add_member(&s.g[2], 3, 1);
	s.ng = 3;
	s.nrules = 3;
	s.rule_group[0] = 0;
	s.rule_group[1] = 1;
	s.rule_group[2] = 2;
	for (unsigned k = 0; k < 12; k++)
		add_prefix(&s, 0, k, k < 6 || k == 11 ? 0 : k < 10 ? 1 : 2);
	for (unsigned k = 0; k < 4; k++)
		add_prefix(&s, 1, k, k < 3 ? 0 : 1);
	return s;
}

#define EXPECT_PREFIX(r, s, d) \
	CHECK((r).skipped || ((r).a.prefix_set == (s) && (r).a.prefix_del == (d)), \
	"want %u prefix routes set, %u deleted; got %u, %u", (unsigned)(s), (unsigned)(d), \
	(r).a.prefix_set, (r).a.prefix_del)
#define EXPECT_MSGS(r, n) CHECK((r).skipped || (r).a.msgs == (n), \
	"want %u requests, got %u", (unsigned)(n), (r).a.msgs)

static const struct step_opts DIFF = { .full = false };
static const struct step_opts FULL = { .full = true };

/* Fresh install of a, then a -> b, optionally after perturbing the kernel. */
static struct step_result pair(const char *name, struct tworld *a, struct tworld *b,
                               void (*pre)(void), const struct step_opts *o)
{
	struct step_result r = {};
	const char *only = getenv("TEST_SYNC_ONLY");

	/* TEST_SYNC_ONLY=text: only the named scenarios with text in their name */
	if (only && !strstr(name, only)) {
		r.skipped = true;
		return r;
	}
	begin(name, a);
	if (pre)
		pre();
	r = step(name, a, b, o);
	return r;
}

static void pre_flush3(void)
{
	link_flush(K, 4);	/* dev2: group b's only member */
}

static void pre_flush1(void)
{
	link_flush(K, 2);	/* dev0: one of group a's */
}

static void pre_flush12(void)
{
	link_flush(K, 2);
	link_flush(K, 3);
}

static uint32_t witness_table;

static void pre_witness(void)
{
	for (int i = 0; i < MAXR; i++)
		if (K->r[i].used && K->r[i].table == witness_table && K->r[i].family == AF_INET &&
		    K->r[i].nh_id) {
			r_remove(K, i);
			return;
		}
}

static void pre_rule(void)
{
	for (size_t i = 0; i < K->nru[0]; i++)
		if (ours(K->ru[0][i].proto) && K->ru[0][i].mark) {
			rule_remove(K, 0, i);
			return;
		}
}

static struct tworld *pre_world;

static void pre_foreign(void)
{
	for (int i = 0; i < 6; i++)
		foreign_add(K, pre_world);
}

static void pre_leftovers(void)
{
	for (int i = 0; i < 8; i++)
		leftover_add(K, pre_world, i % 2);
}

/* dev1 (ifindex 3) comes back with IPv6 disabled */
static void pre_v6_off(void)
{
	refuse[1] |= 1ull << 3;
	link_flush(K, 3);
}

/* dev2 (ifindex 4), group b's only member, its gateway now off-link */
static void pre_gw_off(void)
{
	refuse[0] |= 1ull << 4;
	link_flush(K, 4);
}

/* Someone else's nexthop at id, ours there (and its routes) gone. */
static void foreign_at(uint32_t id, int family)
{
	struct mnh n = { .id = id, .family = family, .proto = PROTO_FOREIGN, .oif = 50 };

	nh_remove(K, id, BY_KERNEL);
	nh_insert(K, &n);
	nh_insert(&FS, &n);
}

/* Every device of the big config refuses both families. */
static void pre_all_refuse(void)
{
	for (int f = 0; f < 2; f++)
		refuse[f] = ((1ull << (NSPEC + 2)) - 1) & ~3ull;
	for (int i = 2; i < NSPEC + 2; i++)
		link_flush(K, i);
}

/*
 * Someone else's nexthop in our range: sync refuses to touch anything, then
 * puts everything back once it's gone.
 */
static void named_foreign_abort(const char *name, struct tworld *a, uint32_t id, int family,
                                bool restart)
{
	struct sync_stats st;
	int ret;

	begin(name, a);
	foreign_at(id, family);
	reset_step(name);
	mlog("  apply (%s):\n", restart ? "full, restart" : "diff");
	reference(a, &kref);
	ret = apply(restart ? tw_world(&empty_world) : tw_world(a), a, a,
	            restart, &st);
	CHECK(ret == -1, "sync_apply returned %d with someone else's nexthop at id %u", ret, id);
	CHECK(!acc.msgs, "%u requests with someone else's nexthop at id %u", acc.msgs, id);
	report_step(a, a);
	nh_remove(K, id, BY_KERNEL);
	nh_remove(&FS, id, BY_KERNEL);
	step("and once it's gone", a, a, &FULL);
}

static void named(void)
{
	struct tsrc s = base_src(), s2;
	struct tcfg *c = tcfg_build(&s), *c2;
	struct env e, e2;
	struct tworld a, b, x;
	struct step_result r;

	env_default(&e);
	tw_make(&a, c, &e);

	r = pair("same config, nothing changed", &a, &a, NULL, &DIFF);
	EXPECT_MSGS(r, 0);

	e2 = e;
	e2.spec[1][0].usable = false;
	tw_make(&b, c, &e2);
	r = pair("same config, a member leaves", &a, &b, NULL, &DIFF);
	EXPECT_MSGS(r, 2);	/* group replace, member delete */

	e2.spec[0][0].usable = false;
	tw_make(&b, c, &e2);
	r = pair("same config, v4 of group a blackholed", &a, &b, NULL, &DIFF);
	EXPECT_MSGS(r, 3);	/* group replace, 2 member deletes */
	r = pair("same config, v4 of group a back", &b, &a, NULL, &DIFF);
	EXPECT_PREFIX(r, 0, 0);

	e2 = e;
	e2.up[1][2] = false;
	tw_make(&b, c, &e2);
	r = pair("same config, group b probed down", &a, &b, NULL, &DIFF);
	EXPECT_MSGS(r, 2);	/* 2 group replaces */

	/* group b's only link flaps: the kernel took the group and its routes */
	r = pair("same config, group b's link flapped", &a, &a, pre_flush3, &DIFF);
	EXPECT_PREFIX(r, 5, 0);
	/* ... and stays down: the group is back as the blackhole */
	e2 = e;
	e2.spec[2][0].usable = e2.spec[2][1].usable = false;
	tw_make(&b, c, &e2);
	r = pair("same config, group b's link went down", &a, &b, pre_flush3, &DIFF);
	EXPECT_PREFIX(r, 5, 0);
	/* one of group a's links: no route goes, none is set */
	r = pair("same config, one of group a's links flapped", &a, &a, pre_flush1, &DIFF);
	EXPECT_PREFIX(r, 0, 0);
	/* the witness goes alone: the group's v4 prefixes are set again */
	witness_table = cfg_group_table(&c->c, 0);
	r = pair("same config, group a's v4 witness deleted", &a, &a, pre_witness, &DIFF);
	EXPECT_PREFIX(r, 7, 0);
	/* a probe route changes (its gateway): changed, not lost */
	e2 = e;
	e2.spec[2][0].gw[3] = 99;
	tw_make(&b, c, &e2);
	r = pair("same config, a probed gateway changes", &a, &b, NULL, &DIFF);
	EXPECT_PREFIX(r, 0, 0);
	r = pair("same config, a rule deleted", &a, &a, pre_rule, &DIFF);
	CHECK(r.skipped || (r.a.rule_msgs == 1 && !r.a.route_msgs && !r.a.nh_msgs),
	      "want 1 rule request, got %u (and %u route, %u nexthop requests)", r.a.rule_msgs,
	      r.a.route_msgs, r.a.nh_msgs);
	pre_world = &a;
	r = pair("same config, foreign objects", &a, &a, pre_foreign, &DIFF);
	EXPECT_MSGS(r, 0);
	r = pair("restart, leftovers", &a, &a, pre_leftovers,
	         &(struct step_opts){ .full = true, .restart = true });
	r = pair("restart, kernel intact", &a, &a, NULL,
	         &(struct step_opts){ .full = true, .restart = true });
	CHECK(r.skipped || !r.a.route_msgs, "%u route requests", r.a.route_msgs);
	r = pair("full sync, kernel intact", &a, &a, NULL, &FULL);
	CHECK(r.skipped || !r.a.route_msgs, "%u route requests", r.a.route_msgs);

	/* reload: group a's buckets change: its routes become blackholes, then move */
	s2 = s;
	s2.g[0].buckets = 32;
	c2 = tcfg_build(&s2);
	tw_make(&b, c2, &e);
	r = pair("reload, buckets changed", &a, &b, NULL, &DIFF);
	EXPECT_PREFIX(r, 20, 0);
	/* ... while both its links went down and one came back */
	e2 = e;
	e2.spec[1][0].usable = e2.spec[1][1].usable = false;
	tw_make(&b, c2, &e2);
	r = pair("reload, buckets changed, links flapped", &a, &b, pre_flush12, &DIFF);
	CHECK(r.skipped || (r.a.prefix_set <= 20 && !r.a.prefix_del), "%u prefix routes set, %u deleted",
	      r.a.prefix_set, r.a.prefix_del);
	/* ... while it is blackholed */
	e2 = e;
	e2.spec[0][0].usable = e2.spec[1][0].usable = false;
	tw_make(&x, c, &e2);
	e2.spec[1][0].usable = true;
	tw_make(&b, c2, &e2);
	r = pair("reload, buckets changed, blackholed", &x, &b, NULL, &DIFF);
	EXPECT_PREFIX(r, 20, 0);
	free(c2);

	/* reload: rule 1 moves to group a */
	s2 = s;
	s2.rule_group[1] = 0;
	c2 = tcfg_build(&s2);
	tw_make(&b, c2, &e);
	r = pair("reload, rule moved", &a, &b, NULL, &DIFF);
	EXPECT_PREFIX(r, 5, 0);
	/* the same with the lists shared, as across a reload with unchanged lists */
	tcfg_borrow(c2, c);
	CHECK(c2->borrowed, "lists not shared");
	r = pair("reload, lists shared, rule moved", &a, &b, NULL, &DIFF);
	EXPECT_PREFIX(r, 5, 0);
	tcfg_release(c2, NULL);
	c2 = tcfg_build(&s);
	tcfg_borrow(c2, c);
	tw_make(&b, c2, &e);
	r = pair("reload, lists shared, nothing changed", &a, &b, NULL, &DIFF);
	EXPECT_MSGS(r, 0);
	tcfg_release(c2, NULL);

	/* reload: another rule wins a duplicate (v4 key 7 also listed by rule 0) */
	s2 = s;
	add_prefix(&s2, 0, 7, 0);
	c2 = tcfg_build(&s2);
	tw_make(&b, c2, &e);
	r = pair("reload, another rule wins a duplicate", &a, &b, NULL, &DIFF);
	EXPECT_PREFIX(r, 1, 0);
	free(c2);

	/* reload: one prefix gone, one new */
	s2 = s;
	s2.p[0].key = 40;
	c2 = tcfg_build(&s2);
	tw_make(&b, c2, &e);
	r = pair("reload, a prefix replaced", &a, &b, NULL, &DIFF);
	EXPECT_PREFIX(r, 1, 1);
	free(c2);

	/* reload: the CIDR table moves */
	s2 = s;
	s2.table_id = 5000;
	c2 = tcfg_build(&s2);
	tw_make(&b, c2, &e);
	r = pair("reload, table_id changed", &a, &b, NULL, &DIFF);
	EXPECT_PREFIX(r, 16, 16);
	free(c2);

	/* reload: everything else that moves ids, tables, rules, owners */
	{
		static const char *const names[] = { "rt_proto", "rule_prio", "nexthop_id +1",
			"nexthop_id +2", "nexthop_id +4", "groups reordered", "group renamed",
			"device renamed", "group removed", "group added", "member added", "fwmark moved",
			"probes on", "timers", "first group removed", "table and rule_prio moved",
			"first group removed, nexthop_id +1",
			/* old and new tables overlapping: +-2 and +-3 trade CIDR and group tables */
			"table_id +1", "table_id -1", "table_id +2", "table_id -2", "table_id +3",
			"table_id -3", "table_id +4", "table_id -4" };

		for (unsigned i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
			char name[64];

			s2 = s;
			switch (i) {
			case 0: s2.proto = PROTO_B; break;
			case 1: s2.rule_prio = 2000; break;
			case 2: s2.nexthop_id = 1001; break;
			case 3: s2.nexthop_id = 1002; break;
			case 4: s2.nexthop_id = 1004; break;
			case 5:
				s2.g[0] = s.g[1];
				s2.g[1] = s.g[0];
				s2.rule_group[0] = 1;
				s2.rule_group[1] = 0;
				break;
			case 6: s2.g[0].name = 5; break;
			case 7: s2.g[0].spec[1] = 6; break;
			case 8:
				s2.g[1] = s.g[2];
				s2.ng = 2;
				s2.rule_group[1] = 0;
				s2.rule_group[2] = 1;
				break;
			case 9:
				s2.g[3] = mkgroup(3, 0x04000000, 16);
				add_member(&s2.g[3], 1, 1);
				s2.ng = 4;
				s2.rule_group[2] = 3;
				break;
			case 10: add_member(&s2.g[1], 3, 1); break;
			case 11: s2.g[0].fwmark = 0x05000000; s2.g[2].fwmark = 0x01000000; break;
			case 12: s2.g[2].probe[1] = true; break;
			case 13: s2.g[0].idle = 60; s2.g[0].busy = 0; break;
			case 17: case 18: case 19: case 20: case 21: case 22: case 23: case 24: {
				static const int shift[] = { 1, -1, 2, -2, 3, -3, 4, -4 };

				s2.table_id += shift[i - 17];
				break;
			}
			case 16:
				s2.nexthop_id = 1001;
				/* fall through */
			case 14:
				/* b and c move up: tables 102 and 103 change owner */
				s2.g[0] = s.g[1];
				s2.g[1] = s.g[2];
				s2.ng = 2;
				s2.rule_group[0] = 0;
				s2.rule_group[1] = 0;
				s2.rule_group[2] = 1;
				break;
			case 15:
				/* the new CIDR rule comes first; 10.5.0.0/24 (a) sits in 10.5.0.0/16 (c) */
				s2.table_id = 5000;
				s2.rule_prio = 500;
				break;
			}
			c2 = tcfg_build(&s2);
			tw_make(&b, c2, &e);
			unsigned before = fails;

			snprintf(name, sizeof(name), "reload, %s", names[i]);
			pair(name, &a, &b, NULL, &DIFF);
			snprintf(name, sizeof(name), "reload, %s, back", names[i]);
			pair(name, &b, &a, NULL, &DIFF);

			/* and races spread over its requests, if it works without */
			for (unsigned k = 0; k < 64 && fails == before; k += k < 4 ? 1 : k / 2) {
				struct step_opts o = { .race = true, .race_at = k,
				                       .race_kind = (enum pkind)((i + k) % P_N_ANYTIME) };

				snprintf(name, sizeof(name), "reload, %s, %s at request %u", names[i],
				         pkind_names[o.race_kind], k);
				pre_world = &a;
				r = pair(name, &a, &b, NULL, &o);
				if (!r.raced)
					break;
			}
			free(c2);
		}
	}

	tw_make(&x, NULL, &e);
	r = pair("old world empty", &x, &a, NULL, &FULL);
	EXPECT_PREFIX(r, 16, 0);

	/* devices that refuse: members left out, the sync not uncertain */
	pair("refused, v6 disabled on one of a's members", &a, &a, pre_v6_off, &DIFF);
	pair("refused, group b's only member", &a, &a, pre_gw_off, &DIFF);
	pair("refused, at startup", &a, &a, pre_v6_off,
	     &(struct step_opts){ .full = true, .restart = true });
	pair("refused, full sync", &a, &a, pre_gw_off, &FULL);
	begin("refused, then taken again", &a);
	pre_v6_off();
	pre_gw_off();
	step("refused", &a, &a, &DIFF);
	memset(refuse, 0, sizeof(refuse));
	step("taken again", &a, &a, &DIFF);

	/*
	 * What's to change is refused (dev2's gateway moves, its device no
	 * longer takes it): the old one at that id or key goes.
	 */
	e2 = e;
	e2.spec[2][0].gw[3] = 99;
	tw_make(&b, c, &e2);
	{
		const char *only = getenv("TEST_SYNC_ONLY");

		if (!only || strstr("refused, a member that changes", only)) {
			begin("refused, a member that changes", &a);
			refuse[0] |= 1ull << 4;
			step("refused, a member that changes", &a, &b, &DIFF);
		}
	}
	/*
	 * The kernel deletes group a (and its routes) between the dump and
	 * the group's replace, which comes with a member leaving: a replace
	 * that creates it anew, and the witness set again behind it, would hide
	 * the loss from the next sync.
	 */
	e2 = e;
	e2.spec[1][0].usable = false;
	tw_make(&b, c, &e2);
	for (unsigned k = 0; k < 4; k++) {
		char name[96];

		snprintf(name, sizeof(name), "member leaves, group a deleted at request %u", k);
		pair(name, &a, &b, NULL, &(struct step_opts){ .race = true,
		                                               .race_at = k, .race_kind = P_GROUP_A });
	}

	/* more refusals in one sync than nl.c used to keep: 24 devices, 48 members */
	{
		struct tsrc big = { .table_id = 100, .rule_prio = 1000, .nexthop_id = 1000,
		                    .proto = PROTO_A, .ng = 4, .nrules = 4 };
		struct tcfg *c3;
		struct tworld w;

		for (unsigned g = 0; g < 4; g++) {
			big.g[g] = mkgroup(g, g < 2 ? (g + 1) << 24 : 0, 16);
			big.g[g].probe[g % 2] = true;
			for (unsigned m = 0; m < 6; m++)
				add_member(&big.g[g], 6 * g + m, 1);
			big.rule_group[g] = g;
		}
		for (unsigned k = 0; k < 16; k++)
			add_prefix(&big, k % 2, k, k % 4);
		c3 = tcfg_build(&big);
		tw_make(&w, c3, &e);
		pair("refused, 48 members and their probe routes at once", &w, &w, pre_all_refuse,
		     &DIFF);
		pair("refused, 48 members at once, at startup", &x, &w, pre_all_refuse,
		     &(struct step_opts){ .full = true, .restart = true });
		free(c3);
	}

	/* someone else's nexthops in our range */
	named_foreign_abort("foreign nexthop at a member id", &a, 1006, AF_INET, false);
	named_foreign_abort("foreign nexthop at a group id", &a, 1004, AF_INET, false);
	named_foreign_abort("foreign nexthop at a group id, at startup", &a, 1009, AF_INET6, true);
	named_foreign_abort("foreign nexthop at the blackhole id", &a, 1001, AF_INET6, false);

	/* at startup over another layout's leftovers, tables overlapping */
	for (int shift = -4; shift <= 4; shift++) {
		char name[64];

		if (!shift)
			continue;
		s2 = s;
		s2.table_id += shift;
		c2 = tcfg_build(&s2);
		tw_make(&b, c2, &e);
		snprintf(name, sizeof(name), "restart, table_id %+d", shift);
		pre_world = &a;
		pair(name, &a, &b, pre_leftovers,
		     &(struct step_opts){ .full = true, .restart = true });
		free(c2);
	}

	free(c);
}

/* --- random runs --- */

static void random_env(struct env *e, bool small)
{
	for (int s = 0; s < NSPEC; s++)
		for (int f = 0; f < 2; f++) {
			struct ifrender *r = &e->spec[s][f];

			if (small && rnd(4))
				continue;
			r->usable = rnd(5);
			if (!small || !rnd(3)) {
				r->has_gw = rnd(2);
				r->ifindex = 2 + rnd(9);
				memset(r->gw, 0, 16);
				if (!f) {
					r->gw[0] = 10;
					r->gw[2] = r->ifindex;
					r->gw[3] = 1 + rnd(2);
				} else {
					r->gw[0] = 0xfe;
					r->gw[1] = 0x80;
					r->gw[15] = 1 + rnd(2);
				}
			}
		}
	for (int n = 0; n < NNAME; n++)
		for (int s = 0; s < NSPEC; s++)
			if (!small || !rnd(6))
				e->up[n][s] = rnd(5);
}

static bool name_used(const struct tsrc *s, uint8_t name)
{
	return src_group(s, name) != NULL;
}

static bool fwmark_used(const struct tsrc *s, uint32_t m)
{
	for (size_t g = 0; g < s->ng; g++)
		if (s->g[g].fwmark == m)
			return true;
	return false;
}

static void random_group(struct tsrc *s, struct tgroup *g)
{
	unsigned first = rnd(NSPEC);
	uint8_t name;

	do
		name = rnd(NNAME);
	while (name_used(s, name));
	*g = mkgroup(name, 0, rnd(3) ? 16 : rnd(2) ? 8 : 32);
	if (rnd(3)) {
		uint32_t m;

		do
			m = (1 + rnd(7)) << 24;
		while (fwmark_used(s, m));
		g->fwmark = m;
	}
	g->idle = rnd(4) ? 120 : 30;
	g->busy = rnd(4) ? 600 : 0;
	g->probe[0] = !rnd(4);
	g->probe[1] = !rnd(5);
	/* shared devices: specs overlap across groups */
	for (unsigned m = 0, n = 1 + rnd(4); m < n; m++)
		add_member(g, (first + m) % 6, 1 + rnd(3) + (rnd(8) ? 0 : 252));
}

static void random_prefixes(struct tsrc *s)
{
	s->np = 0;
	for (unsigned i = 0, n = rnd(40); i < n && s->np < MAXP; i++)
		add_prefix(s, 0, rnd(NPOOL4), rnd(s->nrules));
	for (unsigned i = 0, n = rnd(16); i < n && s->np < MAXP; i++)
		add_prefix(s, 1, rnd(NPOOL6), rnd(s->nrules));
}

static void random_src(struct tsrc *s, uint8_t proto)
{
	static const uint32_t nhids[] = { 1000, 1000, 1001, 1002, 1004 };

	memset(s, 0, sizeof(*s));
	s->table_id = rnd(4) ? 98 + rnd(5) : 5000;
	s->rule_prio = rnd(4) ? 998 + rnd(5) : 2000;
	s->nexthop_id = nhids[rnd(5)];
	s->proto = proto ? proto : rnd(5) ? PROTO_A : PROTO_B;
	s->ng = 1 + rnd(MAXG);
	for (size_t g = 0; g < s->ng; g++) {
		uint8_t ng = s->ng;

		s->ng = g;
		random_group(s, &s->g[g]);
		s->ng = ng;
	}
	s->nrules = 1 + rnd(MAXRULES);
	for (size_t r = 0; r < s->nrules; r++)
		s->rule_group[r] = rnd(s->ng);
	random_prefixes(s);
}

/* A reload's worth of change. */
static void mutate(struct tsrc *s, bool keep_proto)
{
	switch (rnd(16)) {
	case 0:
		s->rule_group[rnd(s->nrules)] = rnd(s->ng);
		break;
	case 1:
		if (s->np)
			s->p[rnd(s->np)].rule = rnd(s->nrules);
		break;
	case 2:
		s->g[rnd(s->ng)].buckets ^= 24;
		break;
	case 3:
		if (s->np) {
			unsigned i = rnd(s->np);

			s->np--;
			s->p[i] = s->p[s->np];
		}
		if (s->np < MAXP)
			add_prefix(s, rnd(2), rnd(NPOOL6), rnd(s->nrules));
		break;
	case 4: {
		/* far, or overlapping: CIDR, probe and group tables trading places */
		int shift[] = { 1, -1, 2, -2, s->ng, -(int)s->ng, 2 + s->ng, -2 - (int)s->ng, 0 };

		if (rnd(4) == 0)
			s->table_id = s->table_id < 1000 ? 5000 : 100;
		else
			s->table_id += shift[rnd(8)];
		break;
	}
	case 5: {
		struct tgroup *g = &s->g[rnd(s->ng)];
		uint32_t m = (1 + rnd(7)) << 24;

		if (!fwmark_used(s, m))
			g->fwmark = rnd(3) ? m : 0;
		break;
	}
	case 6: {
		/* far, or overlapping: CIDR, probe and group rules trading priorities */
		int shift[] = { 1, -1, 2, -2, s->ng, -(int)s->ng, 2 + s->ng, -2 - (int)s->ng };

		if (rnd(3) == 0)
			s->rule_prio = s->rule_prio < 1500 ? 2000 : 1000;
		else
			s->rule_prio += shift[rnd(8)];
		/* and the tables with them, at times */
		if (rnd(3) == 0)
			s->table_id += shift[rnd(8)];
		break;
	}
	case 7: {
		static const uint32_t nhids[] = { 1000, 1001, 1002, 1004 };

		s->nexthop_id = nhids[rnd(4)];
		break;
	}
	case 8:
		if (!keep_proto)
			s->proto = s->proto == PROTO_A ? PROTO_B : PROTO_A;
		break;
	case 9:
		if (s->ng > 1) {
			/* reorder: two groups swap places, rules follow them by name */
			unsigned i = rnd(s->ng), j = rnd(s->ng);
			struct tgroup t = s->g[i];

			s->g[i] = s->g[j];
			s->g[j] = t;
			for (size_t r = 0; r < s->nrules; r++)
				s->rule_group[r] = s->rule_group[r] == i ? j :
				                   s->rule_group[r] == j ? i : s->rule_group[r];
		}
		break;
	case 10:
		if (s->ng > 1) {
			unsigned i = rnd(s->ng);

			memmove(&s->g[i], &s->g[i + 1], (s->ng - i - 1) * sizeof(s->g[0]));
			s->ng--;
			for (size_t r = 0; r < s->nrules; r++)
				if (s->rule_group[r] == i)
					s->rule_group[r] = 0;
				else if (s->rule_group[r] > i)
					s->rule_group[r]--;
		}
		break;
	case 11: {
		struct tgroup *g = &s->g[rnd(s->ng)];
		uint8_t name;

		do
			name = rnd(NNAME);
		while (name_used(s, name));
		g->name = name;
		break;
	}
	case 12: {
		/* a device spec renamed everywhere */
		uint8_t from = rnd(6), to = 6 + rnd(2);

		for (size_t g = 0; g < s->ng; g++)
			for (size_t m = 0; m < s->g[g].n; m++)
				if (s->g[g].spec[m] == from)
					s->g[g].spec[m] = to;
				else if (s->g[g].spec[m] == to)
					s->g[g].spec[m] = from;
		break;
	}
	case 13:
		if (s->ng < MAXG) {
			random_group(s, &s->g[s->ng]);
			s->ng++;
			if (rnd(2))
				s->rule_group[rnd(s->nrules)] = s->ng - 1;
		}
		break;
	case 14: {
		struct tgroup *g = &s->g[rnd(s->ng)];

		if (g->n > 1 && rnd(2)) {
			g->n--;
		} else if (g->n < 4) {
			uint8_t sp = rnd(8);
			bool dup = false;

			for (size_t m = 0; m < g->n; m++)
				dup = dup || g->spec[m] == sp;
			if (!dup)
				add_member(g, sp, 1 + rnd(2));
		} else {
			g->weight[rnd(g->n)] = 1 + rnd(4);
		}
		break;
	}
	default: {
		struct tgroup *g = &s->g[rnd(s->ng)];

		g->probe[rnd(2)] ^= 1;
		if (rnd(2))
			g->idle = g->idle == 120 ? 30 : 120;
		break;
	}
	}
}

static void random_run(unsigned run, unsigned n_steps)
{
	struct tsrc src;
	struct env env;
	struct tworld *cur = calloc(1, sizeof(*cur)), *next = calloc(1, sizeof(*next));
	struct tcfg *tc;
	unsigned fails_before = fails;

	seed = 0x9e3779b97f4a7c15ULL ^ (uint64_t)(run + 1) * 0xbf58476d1ce4e5b9ULL;
	rng = seed;
	snprintf(scenario, sizeof(scenario), "random run %u", run);
	step_no = 0;
	kernel_reset();
	env_default(&env);
	tw_make(cur, NULL, &env);

	random_env(&env, false);
	random_src(&src, 0);
	tc = tcfg_build(&src);
	tw_make(next, tc, &env);
	step("startup", cur, next, &(struct step_opts){ .full = true, .restart = true });

	for (unsigned i = 1; i < n_steps && fails == fails_before; i++) {
		struct tworld *t;
		struct step_opts o = { .full = false };
		const char *what;
		unsigned kind = rnd(100);
		struct tcfg *ntc;

		/* the next world */
		t = cur;
		cur = next;
		next = t;
		ntc = cur->tc;
		env = cur->env;
		src = cur->tc->src;
		if (kind < 40) {
			what = "event";
			random_env(&env, true);
			if (rnd(4) == 0)
				env = cur->env;	/* nothing changed */
		} else if (kind < 65) {
			what = "reload";
			for (unsigned n = 1 + rnd(3); n; n--)
				mutate(&src, false);
			ntc = tcfg_build(&src);
			if (rnd(3) == 0)
				tcfg_borrow(ntc, cur->tc);
			if (rnd(3) == 0)
				random_env(&env, true);
		} else if (kind < 70) {
			what = "new config";
			random_src(&src, 0);
			ntc = tcfg_build(&src);
		} else if (kind < 82) {
			what = "restart";
			o.full = true;
			o.restart = true;
			if (rnd(2)) {
				mutate(&src, true);
				ntc = tcfg_build(&src);
			}
		} else if (kind < 90) {
			what = "full";
			o.full = true;
		} else {
			what = "nothing new";
		}
		tw_make(next, ntc, &env);

		/* the kernel, behind routebot's back */
		if (chance(45)) {
			for (unsigned n = 1 + rnd(3); n; n--)
				perturb(K, (enum pkind)rnd(o.full ? P_N : P_N_ANYTIME), cur);
		}
		if (chance(15)) {
			o.race = true;
			o.race_at = rnd(24);
			o.race_kind = (enum pkind)rnd(P_N_ANYTIME);
		}
		step(what, cur, next, &o);

		/* cur goes, next stays */
		if (cur->tc != next->tc) {
			tcfg_release(cur->tc, next->tc);
			cur->tc = NULL;
		}
	}
	if (cur->tc != next->tc)
		tcfg_release(cur->tc, next->tc);
	tcfg_release(next->tc, NULL);
	free(cur);
	free(next);
}

int main(int argc, char **argv)
{
	unsigned runs = 16, steps = 100, first = 0, failed_runs = 0;

	/* test_sync [runs [steps [first run]]]: a first run skips the named scenarios */
	if (argc > 1)
		runs = atoi(argv[1]);
	if (argc > 2)
		steps = atoi(argv[2]);
	if (argc > 3)
		first = atoi(argv[3]);
	if (getenv("TEST_SYNC_REPORTS"))
		max_reports = atoi(getenv("TEST_SYNC_REPORTS"));
	if (nl_open(&nl))
		return 2;
	S = sync_new();
	S_fresh = sync_new();
	for (int i = 0; i < NSPEC; i++) {
		snprintf(spec_buf[i], sizeof(spec_buf[i]), "dev%d", i);
		spec_names[i] = spec_buf[i];
	}
	K = &kmain;
	tw_make(&empty_world, NULL, &(struct env){});

	if (argc <= 3)
		named();
	for (unsigned r = first; r < first + runs && failed_runs < 3; r++) {
		unsigned before = fails;

		random_run(r, steps);
		failed_runs += fails != before;
	}

	fprintf(stderr, "test_sync: %u steps, %u applies, %u requests, %u perturbations, "
	        "%u races (%u hit, %u traffic checks broken after them), "
	        "%u follow-ups (%u needed a full one), %u requests sent mid-dump\n",
	        totals.steps, totals.applies, totals.msgs, totals.perturbs, totals.races,
	        totals.races_hit, totals.race_violations, totals.followups, totals.full_retries,
	        totals.mid_dump);
	fprintf(stderr, "test_sync: expected errors: %u route deletes (ESRCH/ENOENT), %u rule "
	        "deletes (ENOENT), %u rule adds (EEXIST), %u nexthop deletes (ENOENT); "
	        "%u unexpected (races included)\n",
	        totals.expected_by_type[0], totals.expected_by_type[1], totals.expected_by_type[2],
	        totals.expected_by_type[3], totals.unexpected);

	sync_free(S);
	sync_free(S_fresh);
	nl_close(&nl);
	if (fails) {
		fprintf(stderr, "test_sync: %u checks failed\n", fails);
		return 1;
	}
	printf("test_sync: ok\n");
	return 0;
}
