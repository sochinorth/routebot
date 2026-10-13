#ifndef ROUTEBOT_SYNC_H
#define ROUTEBOT_SYNC_H

#include "config.h"
#include "ifstate.h"
#include "nl.h"

/* Desired kernel state is a pure function of this. */
struct world {
	const struct config *cfg;	/* NULL = nothing installed */
	const struct ifview *ifs;	/* cfg->n_devices entries */
	const char *const *netdev;	/* per device; NULL or "" = unresolved */
	const bool *member_up;		/* per group member, flattened in group order */
};

struct sync_stats {
	unsigned route_set;
	unsigned route_del;
	unsigned nh_set;
	unsigned nh_del;
	unsigned rule_add;
	unsigned rule_del;
	unsigned errors;
};

/* Index of member m of group g in world.member_up. */
size_t cfg_member_index(const struct config *c, size_t g, size_t m);

/* Whether member m of group g is in the group's family f nexthop. */
bool world_member_usable(const struct world *w, size_t g, size_t m, int f);

/* Bring the kernel from old to new, touching only what differs. */
void sync_apply(struct nl *nl, const struct world *old, const struct world *new,
		struct sync_stats *st);

/* Delete every rule, route and nexthop tagged with proto, whatever created it. */
int sync_flush(struct nl *nl, uint8_t proto);

/*
 * Refuse nexthop ids in cfg's range that belong to someone else (a replace
 * would hijack them), and groups on kernels without nexthop objects.
 * Returns 0 or -1, logged.
 */
int sync_check_nhids(struct nl *nl, const struct config *cfg);

#endif
