#ifndef ROUTEBOT_CONFIG_H
#define ROUTEBOT_CONFIG_H

#include <stdbool.h>
#include <stdint.h>

#include "cidr.h"

struct cfg_iface {
	char *name;		/* section name */
	char *device;		/* netdev name */
	uint32_t fwmark;	/* already shifted into fwmask; 0 = no table/rule */
	bool has_gw[2];		/* static gateway override, [0] = v4, [1] = v6 */
	uint8_t gw[2][16];
};

struct config {
	uint32_t fwmask;
	uint32_t table_id;	/* rule table; iface tables are table_id + idx */
	uint32_t iface_prio;	/* iface rules are iface_prio + idx */
	uint32_t rule_prio;
	uint32_t gw_table;	/* table to learn gateways from */
	uint8_t rt_proto;	/* rtm_protocol tag on everything we own */

	struct cfg_iface *ifaces;
	size_t n_ifaces;

	struct prefix *prefixes;	/* sorted, deduped */
	size_t n_prefixes;
};

/* idx is 1-based in table/prio arithmetic */
static inline uint32_t cfg_iface_table(const struct config *c, size_t i)
{
	return c->table_id + 1 + i;
}

static inline uint32_t cfg_iface_prio(const struct config *c, size_t i)
{
	return c->iface_prio + 1 + i;
}

struct config *config_load(const char *path);
void config_free(struct config *c);

#endif
