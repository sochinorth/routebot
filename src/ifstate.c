#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <linux/nexthop.h>
#include <linux/rtnetlink.h>

#include "ifstate.h"
#include "log.h"

#define MAX_NEXTHOPS 16

#ifndef IFF_LOWER_UP
#define IFF_LOWER_UP 0x10000	/* missing from glibc's net/if.h */
#endif

/* the kernel flushes nexthops on a device that loses either */
#define LINK_USABLE (IFF_UP | IFF_LOWER_UP)

void live_init(struct live *l, const struct config *cfg)
{
	memset(l, 0, sizeof(*l));
	l->own_proto = cfg->rt_proto;
	l->gw_table = cfg->gw_table;
}

void live_free(struct live *l)
{
	free(l->links);
	free(l->defroutes);
	memset(l, 0, sizeof(*l));
}

/* --- links --- */

static struct link *link_find(const struct live *l, int ifindex)
{
	for (size_t i = 0; i < l->n_links; i++)
		if (l->links[i].ifindex == ifindex)
			return &l->links[i];
	return NULL;
}

static const struct link *link_by_name(const struct live *l, const char *name)
{
	for (size_t i = 0; i < l->n_links; i++)
		if (!strcmp(l->links[i].name, name))
			return &l->links[i];
	return NULL;
}

static void defroutes_purge_oif(struct live *l, int oif)
{
	size_t out = 0;

	for (size_t i = 0; i < l->n_defroutes; i++)
		if (l->defroutes[i].oif != oif)
			l->defroutes[out++] = l->defroutes[i];
	if (out != l->n_defroutes)
		l->dirty = true;
	l->n_defroutes = out;
}

static int link_attr_cb(const struct nlattr *a, void *data)
{
	const char **name = data;

	if (mnl_attr_get_type(a) == IFLA_IFNAME && !mnl_attr_validate(a, MNL_TYPE_STRING))
		*name = mnl_attr_get_str(a);
	return MNL_CB_OK;
}

static void handle_link(struct live *l, const struct nlmsghdr *nlh)
{
	const struct ifinfomsg *ifi = mnl_nlmsg_get_payload(nlh);
	struct link *lk = link_find(l, ifi->ifi_index);
	const char *name = NULL;

	if (nlh->nlmsg_type == RTM_DELLINK) {
		if (lk) {
			debug("link %s (%d) removed", lk->name, lk->ifindex);
			*lk = l->links[--l->n_links];
			l->dirty = true;
		}
		/* the kernel drops routes silently for v4 */
		defroutes_purge_oif(l, ifi->ifi_index);
		return;
	}

	mnl_attr_parse(nlh, sizeof(*ifi), link_attr_cb, &name);

	if (!lk) {
		struct link *nlk = realloc(l->links, (l->n_links + 1) * sizeof(*nlk));

		if (!nlk) {
			err("out of memory");
			return;
		}
		l->links = nlk;
		lk = &l->links[l->n_links++];
		memset(lk, 0, sizeof(*lk));
		lk->ifindex = ifi->ifi_index;
		l->dirty = true;
	}

	/* NEWLINK is a snapshot, not a change notification */
	if (lk->flags != ifi->ifi_flags) {
		if ((lk->flags ^ ifi->ifi_flags) & IFF_UP)
			debug("link %s (%d) %s", name ? name : lk->name, lk->ifindex,
			      ifi->ifi_flags & IFF_UP ? "up" : "down");
		lk->flags = ifi->ifi_flags;
		l->dirty = true;
	}
	if (name && strcmp(lk->name, name)) {
		snprintf(lk->name, sizeof(lk->name), "%s", name);
		l->dirty = true;
	}

	if (!(lk->flags & IFF_UP))
		defroutes_purge_oif(l, lk->ifindex);
}

/* --- default routes --- */

struct route_attrs {
	const struct nlattr *tb[RTA_MAX + 1];
};

static int route_attr_cb(const struct nlattr *a, void *data)
{
	struct route_attrs *ra = data;
	unsigned type = mnl_attr_get_type(a);

	if (type <= RTA_MAX)
		ra->tb[type] = a;
	return MNL_CB_OK;
}

static bool defroute_eq(const struct defroute *a, const struct defroute *b)
{
	return a->family == b->family && a->table == b->table &&
	       a->metric == b->metric && a->oif == b->oif && a->has_gw == b->has_gw &&
	       (!a->has_gw || !memcmp(a->gw, b->gw, family_alen(a->family)));
}

static void set_gw(struct defroute *d, const struct nlattr *a)
{
	size_t alen = family_alen(d->family);

	if (a && mnl_attr_get_payload_len(a) == alen) {
		memcpy(d->gw, mnl_attr_get_payload(a), alen);
		d->has_gw = true;
	}
}

/* Expand one route message into one defroute per nexthop. */
static size_t parse_nexthops(const struct route_attrs *ra, const struct defroute *base,
                             struct defroute *out)
{
	const struct nlattr *mp = ra->tb[RTA_MULTIPATH];
	size_t n = 0;

	if (!mp) {
		out[0] = *base;
		if (ra->tb[RTA_OIF])
			out[0].oif = mnl_attr_get_u32(ra->tb[RTA_OIF]);
		set_gw(&out[0], ra->tb[RTA_GATEWAY]);
		return out[0].oif ? 1 : 0;
	}

	const struct rtnexthop *nh = mnl_attr_get_payload(mp);
	int len = mnl_attr_get_payload_len(mp);

	while (len >= (int)sizeof(*nh) && nh->rtnh_len >= sizeof(*nh) &&
	       nh->rtnh_len <= len && n < MAX_NEXTHOPS) {
		const struct nlattr *a;
		struct defroute *d = &out[n++];

		*d = *base;
		d->oif = nh->rtnh_ifindex;
		/* nested attrs follow the rtnexthop header */
		for (a = (const struct nlattr *)RTNH_DATA(nh);
		     mnl_attr_ok(a, (const char *)nh + nh->rtnh_len - (const char *)a);
		     a = mnl_attr_next(a))
			if (mnl_attr_get_type(a) == RTA_GATEWAY)
				set_gw(d, a);

		len -= RTNH_ALIGN(nh->rtnh_len);
		nh = RTNH_NEXT(nh);
	}

	return n;
}

static void handle_route(struct live *l, const struct nlmsghdr *nlh)
{
	const struct rtmsg *rtm = mnl_nlmsg_get_payload(nlh);
	struct defroute base = {}, hops[MAX_NEXTHOPS];
	struct route_attrs ra = {};
	size_t n;

	if (rtm->rtm_family != AF_INET && rtm->rtm_family != AF_INET6)
		return;
	if (rtm->rtm_dst_len || rtm->rtm_type != RTN_UNICAST ||
	    rtm->rtm_protocol == l->own_proto || (rtm->rtm_flags & RTM_F_CLONED))
		return;

	mnl_attr_parse(nlh, sizeof(*rtm), route_attr_cb, &ra);

	base.family = rtm->rtm_family;
	base.table = ra.tb[RTA_TABLE] ? mnl_attr_get_u32(ra.tb[RTA_TABLE]) : rtm->rtm_table;
	base.metric = ra.tb[RTA_PRIORITY] ? mnl_attr_get_u32(ra.tb[RTA_PRIORITY]) : 0;
	if (base.table != l->gw_table)
		return;

	if (nlh->nlmsg_type == RTM_NEWROUTE && (nlh->nlmsg_flags & NLM_F_REPLACE)) {
		/* a replaced route doesn't get its own DELROUTE */
		size_t out = 0;

		for (size_t i = 0; i < l->n_defroutes; i++) {
			const struct defroute *d = &l->defroutes[i];

			if (!(d->family == base.family && d->metric == base.metric))
				l->defroutes[out++] = *d;
		}
		if (out != l->n_defroutes)
			l->dirty = true;
		l->n_defroutes = out;
	}

	n = parse_nexthops(&ra, &base, hops);
	for (size_t h = 0; h < n; h++) {
		size_t i;

		for (i = 0; i < l->n_defroutes; i++)
			if (defroute_eq(&l->defroutes[i], &hops[h]))
				break;

		if (nlh->nlmsg_type == RTM_DELROUTE) {
			if (i < l->n_defroutes) {
				l->defroutes[i] = l->defroutes[--l->n_defroutes];
				l->dirty = true;
			}
		} else if (i == l->n_defroutes) {
			struct defroute *nd = realloc(l->defroutes, (i + 1) * sizeof(*nd));

			if (!nd) {
				err("out of memory");
				return;
			}
			l->defroutes = nd;
			l->defroutes[l->n_defroutes++] = hops[h];
			l->dirty = true;
		}
	}
}

/* proto of a nexthop or rule message, -1 if it is malformed */
static int nh_proto(const struct nlmsghdr *nlh)
{
	const struct nhmsg *nhm = mnl_nlmsg_get_payload(nlh);

	return mnl_nlmsg_get_payload_len(nlh) >= sizeof(*nhm) ? nhm->nh_protocol : -1;
}

static int rule_proto(const struct nlmsghdr *nlh)
{
	struct rule_spec r;

	return nl_parse_rule(nlh, &r) < 0 ? -1 : r.proto;
}

int live_event_cb(const struct nlmsghdr *nlh, void *data)
{
	struct live *l = data;
	const struct rtmsg *rtm = mnl_nlmsg_get_payload(nlh);
	const struct ifaddrmsg *ifa = mnl_nlmsg_get_payload(nlh);

	switch (nlh->nlmsg_type) {
	case RTM_NEWLINK:
	case RTM_DELLINK:
		l->poked = true;
		handle_link(l, nlh);
		break;
	case RTM_NEWROUTE:
	case RTM_DELROUTE:
		/* the event filter lets default routes through only */
		if (mnl_nlmsg_get_payload_len(nlh) < sizeof(*rtm))
			break;
		if (nlh->nlmsg_type == RTM_DELROUTE && rtm->rtm_protocol == l->own_proto)
			l->poked = true;
		handle_route(l, nlh);
		break;
	case RTM_DELADDR:
		/* v4 routes via gateways in that subnet may vanish without notice */
		if (mnl_nlmsg_get_payload_len(nlh) >= sizeof(*ifa) &&
		    ifa->ifa_family == AF_INET)
			l->resync = true;
		/* fall through */
	case RTM_NEWADDR:
		l->poked = true;
		break;
	case RTM_DELNEXTHOP:
		if (nh_proto(nlh) == l->own_proto)
			l->poked = true;
		break;
	case RTM_DELRULE:
		if (rule_proto(nlh) == l->own_proto)
			l->poked = true;
		break;
	}
	return MNL_CB_OK;
}

int live_dump(struct live *l, struct nl *nl)
{
	char buf[256] __attribute__((aligned(4)));
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	struct rtmsg *rtm;
	int ret;

	free(l->links);
	l->links = NULL;
	l->n_links = 0;
	l->n_defroutes = 0;
	l->dirty = true;
	l->resync = false;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = RTM_GETLINK;
	ifi = mnl_nlmsg_put_extra_header(nlh, sizeof(*ifi));
	ifi->ifi_family = AF_UNSPEC;
	ret = nl_dump(nl, nlh, live_event_cb, l);


	if (ret) {
		err("netlink: link dump failed: %s", strerror(-ret));
		return ret;
	}

	/* with NETLINK_GET_STRICT_CHK the kernel filters by table and type */
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = RTM_GETROUTE;
	rtm = mnl_nlmsg_put_extra_header(nlh, sizeof(*rtm));
	rtm->rtm_family = AF_UNSPEC;
	rtm->rtm_type = RTN_UNICAST;
	rtm->rtm_table = l->gw_table < 256 ? l->gw_table : RT_TABLE_UNSPEC;
	mnl_attr_put_u32(nlh, RTA_TABLE, l->gw_table);
	ret = nl_dump(nl, nlh, live_event_cb, l);
	if (ret) {
		err("netlink: route dump failed: %s", strerror(-ret));
		return ret;
	}

	debug("live: %zu links, %zu default routes in table %u",
	      l->n_links, l->n_defroutes, l->gw_table);
	return 0;
}

/* --- resolve --- */

void live_resolve(const struct live *l, const struct config *cfg,
                  const char *const *netdev, struct ifview *out)
{
	for (size_t i = 0; i < cfg->n_devices; i++) {
		const struct cfg_device *dev = &cfg->devices[i];
		const struct link *lk = NULL;

		memset(&out[i], 0, sizeof(out[i]));
		if (netdev[i] && *netdev[i])
			lk = link_by_name(l, netdev[i]);
		if (!lk || (lk->flags & LINK_USABLE) != LINK_USABLE)
			continue;

		for (int f = 0; f < 2; f++) {
			int family = f ? AF_INET6 : AF_INET;
			struct ifrender *r = &out[i].fam[f];
			const struct defroute *best = NULL;

			if (dev->has_gw[f]) {
				r->has_gw = true;
				memcpy(r->gw, dev->gw[f], sizeof(r->gw));
			} else {
				for (size_t j = 0; j < l->n_defroutes; j++) {
					const struct defroute *d = &l->defroutes[j];

					if (d->family != family || d->oif != lk->ifindex ||
					    d->table != cfg->gw_table || !d->has_gw)
						continue;
					if (!best || d->metric < best->metric)
						best = d;
				}
				if (best) {
					r->has_gw = true;
					memcpy(r->gw, best->gw, sizeof(r->gw));
				}
			}

			r->usable = r->has_gw || (lk->flags & (IFF_POINTOPOINT | IFF_NOARP));
			if (r->usable)
				r->ifindex = lk->ifindex;
			else
				memset(r, 0, sizeof(*r));
		}
	}
}

bool ifrender_eq(const struct ifrender *a, const struct ifrender *b)
{
	return a->usable == b->usable && a->has_gw == b->has_gw &&
	       a->ifindex == b->ifindex && !memcmp(a->gw, b->gw, sizeof(a->gw));
}
