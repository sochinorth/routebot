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
	unsigned errors;	/* unexpected netlink errors, failed dumps, OOM */
	unsigned lost;		/* objects the kernel lost behind routebot's back */
	size_t kept;		/* full reconcile: prefix routes found in place */
};

enum sync_mode {
	/*
	 * Small objects (nexthops, rules, group and probe table routes) are
	 * observed; prefix routes are believed: those of prev, on prev's
	 * groups, except where a group's witness (its table's default route,
	 * which the kernel deletes along with the group and every route on
	 * it) is missing.
	 */
	SYNC_DIFF,
	/* Everything is observed, the prefix routes too (streamed, bounded memory). */
	SYNC_FULL,
};

/* Persistent buffers: a sync allocates nothing once they are big enough. */
struct sync;

struct sync *sync_new(void);
void sync_free(struct sync *s);

/* Index of member m of group g in world.member_up. */
size_t cfg_member_index(const struct config *c, size_t g, size_t m);

/* Whether member m of group g is in the group's family f nexthop. */
bool world_member_usable(const struct world *w, size_t g, size_t m, int f);

/*
 * Bring the kernel to want: build the desired state, observe the kernel,
 * set what's missing or different, delete what's extra, make before break.
 * prev is the world last applied, prev->cfg NULL if none (startup): its
 * layout names the owners of kernel ids (a group's name, a device's spec),
 * its prefix routes are what SYNC_DIFF believes installed, its rt_proto is
 * observed too, and what it rendered tells what the kernel lost (logged,
 * counted in st->lost) from what is merely new. prev->cfg may be
 * want->cfg. prev->cfg == NULL implies SYNC_FULL. A layout change (prev's
 * table_id, rule_prio, nexthop_id or rt_proto not want's) turns prev's
 * groups into blackholes in place first, then is a SYNC_FULL.
 *
 * A member nexthop the kernel refuses is left out of its groups (logged),
 * along with its probe route; that's no failure.
 *
 * Returns 0, or -1 if the kernel may now differ from want in ways a
 * SYNC_DIFF can't see (a dump failed, a request failed, out of memory):
 * the caller retries with SYNC_FULL.
 */
int sync_apply(struct sync *s, struct nl *nl, const struct world *prev,
               const struct world *want, enum sync_mode mode, struct sync_stats *st);

/* Delete every rule, route and nexthop tagged with proto, whatever created it. */
int sync_flush(struct nl *nl, uint8_t proto);

/*
 * Refuse nexthop ids in cfg's range that belong to someone else (a replace
 * would hijack them), and groups on kernels without nexthop objects. Ids
 * with cfg's rt_proto or prev's (NULL = none) are routebot's.
 * Returns 0 or -1, logged.
 */
int sync_check_nhids(struct sync *s, struct nl *nl, const struct config *cfg,
                     const struct config *prev);

#endif
