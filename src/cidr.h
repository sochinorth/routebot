#ifndef ROUTEBOT_CIDR_H
#define ROUTEBOT_CIDR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>

#define PREFIX_STRLEN	(INET6_ADDRSTRLEN + 4)

/*
 * One list entry per family, sorted by (addr, plen): addr and plen are
 * adjacent, so memcmp over the first alen + 1 bytes is the order. rule is
 * the owning rule's config index, not its group: the arrays don't depend on
 * group numbering (config.rule_group maps one to the other).
 */
struct prefix4 {
	uint8_t addr[4];
	uint8_t plen;
	uint8_t pad;
	uint16_t rule;
};

struct prefix6 {
	uint8_t addr[16];
	uint8_t plen;
	uint8_t pad;
	uint16_t rule;
};

_Static_assert(sizeof(struct prefix4) == 8 && _Alignof(struct prefix4) == 2, "prefix4 layout");
_Static_assert(sizeof(struct prefix6) == 20 && _Alignof(struct prefix6) == 2, "prefix6 layout");

static inline size_t family_alen(int family)
{
	return family == AF_INET ? 4 : 16;
}

/*
 * Parse "addr[/plen]" from s[0..len). Returns AF_INET or AF_INET6, -1 if
 * invalid. Host bits are cleared; *masked tells whether any were set.
 */
int cidr_parse(const char *s, size_t len, uint8_t addr[16], uint8_t *plen, bool *masked);

const char *prefix_fmt(int family, const uint8_t *addr, uint8_t plen, char *buf);

/* Collects one family's prefixes, then sorts them into a struct prefix4/6 array. */
struct prefix_build {
	uint8_t *p;		/* elements of esz bytes */
	size_t n, cap;
	uint8_t esz, alen;
};

void prefix_build_init(struct prefix_build *b, int family);
int prefix_build_add(struct prefix_build *b, const uint8_t *addr, uint8_t plen, uint16_t rule);

/* What prefix_build_finish reports a conflict with. */
struct conflict_log {
	const uint16_t *rule_group;
	const char *const *rule_names;
	const char *const *group_names;
	size_t n;		/* conflicts so far; the first CONFLICT_WARN are logged */
};

#define CONFLICT_WARN	10

/*
 * Sorts by (addr, plen) and the lowest rule, drops all but the first of
 * each key, warning when a dropped one belongs to another group. Hands the
 * exact-size array over in *out and frees the rest. Returns the length.
 */
size_t prefix_build_finish(struct prefix_build *b, int family, void **out,
                           struct conflict_log *log);

void prefix_build_free(struct prefix_build *b);

#endif
