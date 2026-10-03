#ifndef ROUTEBOT_SYNC_H
#define ROUTEBOT_SYNC_H

#include "config.h"
#include "ifstate.h"
#include "nl.h"

/* Desired kernel state is a pure function of these two. */
struct world {
	const struct config *cfg;	/* NULL = nothing installed */
	const struct ifview *ifs;	/* cfg->n_ifaces entries */
};

struct sync_stats {
	unsigned route_set;
	unsigned route_del;
	unsigned rule_add;
	unsigned rule_del;
	unsigned errors;
};

/* Bring the kernel from old to new, touching only what differs. */
void sync_apply(struct nl *nl, const struct world *old, const struct world *new,
		struct sync_stats *st);

/* Delete every rule and route tagged with proto, whatever created it. */
int sync_flush(struct nl *nl, uint8_t proto);

#endif
