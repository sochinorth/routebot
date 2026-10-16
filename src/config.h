#ifndef ROUTEBOT_CONFIG_H
#define ROUTEBOT_CONFIG_H

#include <stdbool.h>
#include <stdint.h>

#include "cidr.h"

#define MAX_GROUP_MEMBERS 32

/* A device spec: netifd interface name or kernel netdev name, resolved at runtime. */
struct cfg_device {
	char *spec;
	bool has_gw[2];		/* static gateway override, [0] = v4, [1] = v6 */
	uint8_t gw[2][16];
};

struct cfg_member {
	uint16_t dev;		/* index into config.devices */
	uint16_t weight;	/* 1..256 */
};

struct cfg_group {
	char *name;		/* section name */
	uint32_t fwmark;	/* already shifted into fwmask; 0 = no table/rule */
	struct cfg_member *members;
	size_t n_members;

	bool has_probe[2];	/* [0] = v4, [1] = v6 */
	uint8_t probe[2][16];
	uint32_t probe_timer_ms;
	uint8_t probe_count;

	/* resilient nexthop group parameters */
	uint16_t buckets;
	uint32_t timer_idle;	/* seconds */
	uint32_t timer_busy;	/* seconds, 0 = never force */
};

struct config {
	uint32_t fwmask;
	uint32_t table_id;	/* CIDR table; +1 probe table; +2.. group tables */
	uint32_t rule_prio;	/* CIDR rule; +1 probe rule; +2.. group rules */
	uint32_t gw_table;	/* table to learn gateways from */
	uint8_t rt_proto;	/* rtm_protocol tag on everything we own */
	uint32_t nexthop_id;	/* base for nexthop object ids */
	uint32_t probe_mark;	/* already shifted into fwmask */

	struct cfg_device *devices;	/* deduplicated across groups, by spec */
	size_t n_devices;
	struct cfg_group *groups;
	size_t n_groups;

	/*
	 * CIDR list entries, sorted by (addr, plen), deduped, exact size.
	 * prefix.rule indexes rule_group, which gives the group. lists owns
	 * them, shared with the configs reloaded while the files didn't change.
	 */
	struct cfg_lists *lists;
	struct prefix4 *p4;
	size_t n_p4;
	struct prefix6 *p6;
	size_t n_p6;
	uint16_t *rule_group;	/* per rule, in config order */
	size_t n_rules;
};

static inline uint32_t cfg_probe_table(const struct config *c)
{
	return c->table_id + 1;
}

static inline uint32_t cfg_probe_prio(const struct config *c)
{
	return c->rule_prio + 1;
}

/* g is 0-based */
static inline uint32_t cfg_group_table(const struct config *c, size_t g)
{
	return c->table_id + 2 + g;
}

static inline uint32_t cfg_group_prio(const struct config *c, size_t g)
{
	return c->rule_prio + 2 + g;
}

/*
 * Nexthop ids start at nexthop_id, in blocks of four from there: the
 * blackhole nexthops that an empty group holds at f, device d at 2 + 4d + f,
 * group g at 4 + 4g + f. Each id depends on its own index alone, so a group
 * count change doesn't renumber every device. f = fam_idx.
 */
static inline uint32_t cfg_blackhole_nhid(const struct config *c, int f)
{
	return c->nexthop_id + f;
}

static inline uint32_t cfg_member_nhid(const struct config *c, size_t d, int f)
{
	return c->nexthop_id + 2 + 4 * d + f;
}

static inline uint32_t cfg_group_nhid(const struct config *c, size_t g, int f)
{
	return c->nexthop_id + 4 + 4 * g + f;
}

/* Lowest and highest nexthop id in use, for range checks. */
static inline uint32_t cfg_nhid_start(const struct config *c)
{
	return c->nexthop_id;
}

static inline uint64_t cfg_nhid_end(const struct config *c)
{
	uint64_t d = c->n_devices ? 4 * (uint64_t)c->n_devices - 1 : 0;
	uint64_t g = 4 * (uint64_t)c->n_groups + 1;

	return (uint64_t)c->nexthop_id + (d > g ? d : g);
}

static inline const char *fam_name(int f)
{
	return f ? "v6" : "v4";
}

/* Index of the device with spec, the group named name; -1 if none (or c NULL). */
int config_find_device(const struct config *c, const char *spec);
int config_find_group(const struct config *c, const char *name);

/* Is device d a member of a probed group? */
bool config_dev_probed(const struct config *c, size_t d);

/* prev: the config in use, whose lists are shared if their files are unchanged */
struct config *config_load(const char *path, const struct config *prev);
void config_free(struct config *c);

#endif
