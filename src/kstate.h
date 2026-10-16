#ifndef ROUTEBOT_KSTATE_H
#define ROUTEBOT_KSTATE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "nl.h"

/*
 * What the kernel holds of routebot's small objects, dumped before every
 * sync: nexthops, rules and the routes of a few small tables (the group
 * tables and the probe table; never the CIDR table). Tens of objects.
 */

/* What to observe. */
struct kscope {
	uint8_t protos[2];	/* rules, routes and nexthops with these protos */
	size_t n_protos;	/* 1 or 2 (old and new rt_proto across a reload) */
	uint32_t id_lo[2];	/* nexthops with an id in [id_lo, id_hi], */
	uint32_t id_hi[2];	/*   whatever their proto (to spot foreign ones) */
	size_t n_ranges;
	const uint32_t *tables;	/* routes in these tables only, one dump each */
	size_t n_tables;
};

struct kstate {
	/* in kernel dump order; groups have family AF_UNSPEC */
	struct nexthop_spec *nh;
	size_t n_nh, cap_nh;
	struct rule_spec *rules;	/* plain rules only (nl_parse_rule() == 0) */
	size_t n_rules, cap_rules;
	struct kroute *routes;
	size_t n_routes, cap_routes;
	/* rules with a proto in scope that nl_parse_rule() couldn't express */
	size_t n_odd_rules;
};

/*
 * Replace k's contents with what the kernel holds in scope s. Buffers are
 * kept across calls and only grow: no allocation once they are big enough.
 * Returns 0, or -errno (-ENOMEM included) with k's contents undefined.
 * -EOPNOTSUPP from the nexthop dump (no nexthop objects) is not an error:
 * k->nh is left empty.
 */
int kstate_observe(struct nl *nl, const struct kscope *s, struct kstate *k);

void kstate_free(struct kstate *k);

#endif
