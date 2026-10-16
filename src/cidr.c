#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

#include "cidr.h"
#include "log.h"

int cidr_parse(const char *s, struct prefix *p, bool *masked)
{
	char buf[PREFIX_STRLEN];
	const char *slash;
	size_t alen, len;
	unsigned long plen;
	char *end;

	memset(p, 0, sizeof(*p));
	*masked = false;

	len = strlen(s);
	if (len >= sizeof(buf))
		return -1;
	memcpy(buf, s, len + 1);

	slash = strchr(buf, '/');
	if (slash)
		buf[slash - buf] = '\0';

	if (inet_pton(AF_INET, buf, p->addr) == 1)
		p->family = AF_INET;
	else if (inet_pton(AF_INET6, buf, p->addr) == 1)
		p->family = AF_INET6;
	else
		return -1;

	alen = family_alen(p->family);
	plen = alen * 8;
	if (slash) {
		const char *ps = s + (slash - buf) + 1;

		if (*ps < '0' || *ps > '9')
			return -1;
		plen = strtoul(ps, &end, 10);
		if (*end || plen > alen * 8)
			return -1;
	}
	p->plen = plen;

	for (size_t i = 0; i < alen; i++) {
		int bits = (int)plen - (int)i * 8;
		uint8_t mask = bits >= 8 ? 0xff : bits <= 0 ? 0 : (uint8_t)(0xff << (8 - bits));

		if (p->addr[i] & ~mask)
			*masked = true;
		p->addr[i] &= mask;
	}

	return 0;
}

const char *prefix_fmt(const struct prefix *p, char *buf)
{
	inet_ntop(p->family, p->addr, buf, INET6_ADDRSTRLEN);
	sprintf(buf + strlen(buf), "/%u", p->plen);
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
				     prefix_fmt(&p[i], buf),
				     rule_names[win->rule], group_names[win->group],
				     rule_names[p[i].rule], group_names[p[i].group]);
			continue;
		}
		p[out++] = p[i];
	}

	return out;
}
