#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "kstate.h"

struct kctx {
	const struct kscope *s;
	struct kstate *k;
	uint32_t table;		/* route dumps: the one table asked for */
	bool oom;
};

/* Room for one more; false and oom set if none: the dump is drained still. */
static bool grow(struct kctx *c, void **p, size_t *cap, size_t n, size_t size)
{
	size_t ncap;
	void *np;

	if (n < *cap)
		return true;
	ncap = *cap ? *cap * 2 : 16;
	np = realloc(*p, ncap * size);
	if (!np) {
		c->oom = true;
		return false;
	}
	*p = np;
	*cap = ncap;
	return true;
}

static bool proto_in(const struct kscope *s, uint8_t proto)
{
	for (size_t i = 0; i < s->n_protos; i++)
		if (s->protos[i] == proto)
			return true;
	return false;
}

static bool id_in(const struct kscope *s, uint32_t id)
{
	for (size_t i = 0; i < s->n_ranges; i++)
		if (id >= s->id_lo[i] && id <= s->id_hi[i])
			return true;
	return false;
}

static int nh_cb(const struct nlmsghdr *nlh, void *data)
{
	struct kctx *c = data;
	struct kstate *k = c->k;
	struct nexthop_spec n;

	/* a group too large to parse has id and proto: kept, and replaced */
	if (nl_parse_nexthop(nlh, &n) && !n.id)
		return MNL_CB_OK;
	if (!proto_in(c->s, n.proto) && !id_in(c->s, n.id))
		return MNL_CB_OK;
	if (grow(c, (void **)&k->nh, &k->cap_nh, k->n_nh, sizeof(*k->nh)))
		k->nh[k->n_nh++] = n;
	return MNL_CB_OK;
}

static int rule_cb(const struct nlmsghdr *nlh, void *data)
{
	struct kctx *c = data;
	struct kstate *k = c->k;
	struct rule_spec r;
	int ret = nl_parse_rule(nlh, &r);

	if (ret < 0 || !proto_in(c->s, r.proto))
		return MNL_CB_OK;
	if (ret)
		k->n_odd_rules++;
	else if (grow(c, (void **)&k->rules, &k->cap_rules, k->n_rules, sizeof(*k->rules)))
		k->rules[k->n_rules++] = r;
	return MNL_CB_OK;
}

static int route_cb(const struct nlmsghdr *nlh, void *data)
{
	struct kctx *c = data;
	struct kstate *k = c->k;
	struct kroute r;

	/* the kernel filters already, unless strict checking is missing */
	if (nl_parse_route(nlh, &r) || r.r.table != c->table || !proto_in(c->s, r.r.proto))
		return MNL_CB_OK;
	if (grow(c, (void **)&k->routes, &k->cap_routes, k->n_routes, sizeof(*k->routes)))
		k->routes[k->n_routes++] = r;
	return MNL_CB_OK;
}

int kstate_observe(struct nl *nl, const struct kscope *s, struct kstate *k)
{
	struct kctx c = { .s = s, .k = k };
	int ret;

	k->n_nh = k->n_rules = k->n_routes = k->n_odd_rules = 0;

	ret = nl_dump_nexthops(nl, nh_cb, &c);
	if (ret == -EOPNOTSUPP)
		ret = 0;
	if (!ret)
		ret = nl_dump_rules(nl, rule_cb, &c);
	for (size_t i = 0; !ret && i < s->n_tables; i++) {
		c.table = s->tables[i];
		ret = nl_dump_routes(nl, AF_UNSPEC, c.table,
		                     s->n_protos == 1 ? s->protos[0] : 0, route_cb, &c);
	}
	if (!ret && c.oom)
		ret = -ENOMEM;
	return ret;
}

void kstate_free(struct kstate *k)
{
	free(k->nh);
	free(k->rules);
	free(k->routes);
	memset(k, 0, sizeof(*k));
}
