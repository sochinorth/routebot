#ifndef ROUTEBOT_IFSTATE_H
#define ROUTEBOT_IFSTATE_H

#include <net/if.h>
#include <stdbool.h>
#include <stdint.h>

#include "config.h"
#include "nl.h"

/* Live view of the system, fed by dumps and netlink events. */
struct link {
	int ifindex;
	unsigned flags;
	char name[IF_NAMESIZE];
};

struct defroute {
	uint8_t family;
	bool has_gw;
	uint32_t table;
	uint32_t metric;
	int oif;
	uint8_t gw[16];
};

struct live {
	struct link *links;
	size_t n_links, cap_links;
	struct defroute *defroutes;
	size_t n_defroutes, cap_defroutes;

	uint8_t own_proto;	/* ignore our own default routes */
	uint32_t gw_table;	/* only default routes from here are tracked */
	bool dirty;		/* links or gateways changed since last resolve */
	bool resync;		/* addresses removed: gateways may be gone unseen */
	/*
	 * An event says the kernel may have changed routebot's objects, or
	 * what it would accept: any link event (a link going down or away
	 * flushes nexthops and routes silently), an address added or removed
	 * (a nexthop the kernel refused may now be accepted), a nexthop, rule
	 * or default route with routebot's proto deleted. Cleared by the
	 * caller.
	 */
	bool poked;
};

/* What one device looks like to the routing tables, per family. */
struct ifrender {
	bool usable;
	bool has_gw;
	int ifindex;
	uint8_t gw[16];
};

struct ifview {
	struct ifrender fam[2];	/* [0] = v4, [1] = v6 */
};

static inline int fam_idx(int family)
{
	return family == AF_INET6;
}

void live_init(struct live *l, const struct config *cfg);
void live_free(struct live *l);

/* Full re-dump of links and default routes. */
int live_dump(struct live *l, struct nl *nl);

/* mnl callback for the event socket. */
int live_event_cb(const struct nlmsghdr *nlh, void *data);

/*
 * Compute the per-device view for cfg; out has cfg->n_devices entries.
 * netdev[d] names device d's kernel netdev; NULL or "" = unresolved.
 */
void live_resolve(const struct live *l, const struct config *cfg,
                  const char *const *netdev, struct ifview *out);

bool ifrender_eq(const struct ifrender *a, const struct ifrender *b);

#endif
