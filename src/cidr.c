#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cidr.h"
#include "log.h"

/*
 * Dotted quad as inet_pton(AF_INET) takes it, on glibc and musl alike:
 * exactly four decimal octets of 1-3 digits, each at most 255, no leading
 * zero unless the octet is "0", no sign, no other characters.
 */
static bool parse_v4(const char *s, size_t len, uint8_t *addr)
{
	const char *end = s + len;

	for (int i = 0; i < 4; i++) {
		unsigned v = 0, digits = 0;

		for (; s < end && *s >= '0' && *s <= '9'; s++, digits++) {
			if (digits == 3 || (digits && !v))
				return false;	/* too long, or a leading zero */
			v = v * 10 + (*s - '0');
		}
		if (!digits || v > 255)
			return false;
		addr[i] = v;
		if (i < 3 && (s == end || *s++ != '.'))
			return false;
	}
	return s == end;
}

int cidr_parse(const char *s, size_t len, uint8_t addr[16], uint8_t *plen, bool *masked)
{
	const char *slash;
	size_t alen, a_len;
	unsigned long pl;
	int family;

	memset(addr, 0, 16);
	*masked = false;
	if (len >= PREFIX_STRLEN)
		return -1;

	slash = memchr(s, '/', len);
	a_len = slash ? (size_t)(slash - s) : len;
	if (parse_v4(s, a_len, addr)) {
		family = AF_INET;
	} else {
		char buf[PREFIX_STRLEN];

		memcpy(buf, s, a_len);
		buf[a_len] = '\0';
		if (inet_pton(AF_INET6, buf, addr) != 1)
			return -1;
		family = AF_INET6;
	}

	alen = family_alen(family);
	pl = alen * 8;
	if (slash) {
		/* decimal digits only, leading zeros fine, as strtoul took them */
		const char *p = slash + 1, *end = s + len;

		if (p == end)
			return -1;
		for (pl = 0; p < end; p++) {
			if (*p < '0' || *p > '9')
				return -1;
			if (pl <= 128)
				pl = pl * 10 + (*p - '0');
		}
		if (pl > alen * 8)
			return -1;
	}
	*plen = pl;

	for (size_t i = 0; i < alen; i++) {
		int bits = (int)pl - (int)i * 8;
		uint8_t mask = bits >= 8 ? 0xff : bits <= 0 ? 0 : (uint8_t)(0xff << (8 - bits));

		if (addr[i] & ~mask)
			*masked = true;
		addr[i] &= mask;
	}

	return family;
}

const char *prefix_fmt(int family, const uint8_t *addr, uint8_t plen, char *buf)
{
	inet_ntop(family, addr, buf, INET6_ADDRSTRLEN);
	sprintf(buf + strlen(buf), "/%u", plen);
	return buf;
}

int prefix_cmp(const struct prefix *a, const struct prefix *b)
{
	int r;

	if (a->family != b->family)
		return a->family < b->family ? -1 : 1;
	r = memcmp(a->addr, b->addr, family_alen(a->family));
	if (r)
		return r;
	if (a->plen != b->plen)
		return a->plen < b->plen ? -1 : 1;
	return 0;
}

static int prefix_sort_cmp(const void *pa, const void *pb)
{
	const struct prefix *a = pa, *b = pb;
	int r = prefix_cmp(a, b);

	if (r)
		return r;
	return (int)a->rule - (int)b->rule;
}

size_t prefixes_normalize(struct prefix *p, size_t n, const char *const *rule_names,
                          const char *const *group_names, size_t *n_conflicts)
{
	char buf[PREFIX_STRLEN];
	size_t out = 0;

	if (!n)
		return 0;

	qsort(p, n, sizeof(*p), prefix_sort_cmp);

	for (size_t i = 0; i < n; i++) {
		if (out && !prefix_cmp(&p[out - 1], &p[i])) {
			const struct prefix *win = &p[out - 1];

			if (win->group != p[i].group && (*n_conflicts)++ < CONFLICT_WARN)
				warn("%s: claimed by rule '%s' (%s) and rule '%s' (%s), first one wins",
				     prefix_fmt(p[i].family, p[i].addr, p[i].plen, buf),
				     rule_names[win->rule], group_names[win->group],
				     rule_names[p[i].rule], group_names[p[i].group]);
			continue;
		}
		p[out++] = p[i];
	}

	return out;
}
