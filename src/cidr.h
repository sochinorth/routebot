#ifndef ROUTEBOT_CIDR_H
#define ROUTEBOT_CIDR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>

#define PREFIX_STRLEN	(INET6_ADDRSTRLEN + 4)

struct prefix {
	uint8_t family;		/* AF_INET or AF_INET6 */
	uint8_t plen;
	uint16_t group;		/* index into config.groups */
	uint16_t rule;		/* config order of the owning rule, for first-wins */
	uint8_t addr[16];
};

/* Parse "addr[/plen]". Host bits are cleared; *masked tells whether any were set. */
int cidr_parse(const char *s, struct prefix *p, bool *masked);

const char *prefix_fmt(const struct prefix *p, char *buf);

static inline size_t family_alen(int family)
{
	return family == AF_INET ? 4 : 16;
}

/* Orders by (family, addr, plen); the key the kernel table is unique on. */
int prefix_cmp(const struct prefix *a, const struct prefix *b);

#define CONFLICT_WARN	10

/*
 * Sort and dedupe in place; for duplicate keys the lowest .rule wins.
 * Conflicts between different groups are counted in *n_conflicts, the
 * first CONFLICT_WARN reported via warn(). Returns the new length.
 */
size_t prefixes_normalize(struct prefix *p, size_t n, const char *const *rule_names,
                          const char *const *group_names, size_t *n_conflicts);

#endif
