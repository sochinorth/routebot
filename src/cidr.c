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

/* --- building the sorted arrays --- */

/*
 * Entries are handled as bytes: alen address bytes, plen, pad, rule. The
 * helpers take alen (4 or 16) so each call site compiles to fixed sizes.
 */
#define ESZ(alen)	((alen) + 4u)

static inline uint32_t load_be32(const uint8_t *p)
{
	return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

static inline uint64_t load_be64(const uint8_t *p)
{
	return (uint64_t)load_be32(p) << 32 | load_be32(p + 4);
}

/* (addr, plen) order */
static inline int key_cmp(unsigned alen, const uint8_t *x, const uint8_t *y)
{
	uint64_t a, b;

	if (alen == 4) {
		a = (uint64_t)load_be32(x) << 8 | x[4];
		b = (uint64_t)load_be32(y) << 8 | y[4];
	} else {
		a = load_be64(x);
		b = load_be64(y);
		if (a == b) {
			a = load_be64(x + 8);
			b = load_be64(y + 8);
		}
		if (a == b) {
			a = x[16];
			b = y[16];
		}
	}
	return (a > b) - (a < b);
}

static inline void copy(unsigned alen, uint8_t *d, const uint8_t *s)
{
	if (alen == 4)
		memcpy(d, s, ESZ(4));
	else
		memcpy(d, s, ESZ(16));
}

static inline uint16_t rule_of(unsigned alen, const uint8_t *x)
{
	uint16_t r;

	memcpy(&r, x + alen + 2, sizeof(r));
	return r;
}

/* (addr, plen, rule) order: total, entries that tie are identical */
static int full_cmp(unsigned alen, const uint8_t *x, const uint8_t *y)
{
	int r = key_cmp(alen, x, y);

	if (r)
		return r;
	return (int)rule_of(alen, x) - (int)rule_of(alen, y);
}

static inline uint8_t *at(const struct prefix_build *b, size_t i)
{
	return b->p + i * b->esz;
}

void prefix_build_init(struct prefix_build *b, int family)
{
	memset(b, 0, sizeof(*b));
	b->alen = family_alen(family);
	b->esz = ESZ(b->alen);
}

int prefix_build_add(struct prefix_build *b, const uint8_t *addr, uint8_t plen, uint16_t rule)
{
	uint8_t *e;

	if (b->n == b->cap) {
		/* 1.5x: big blocks are mmapped, realloc moves them with mremap */
		size_t cap = b->cap ? b->cap + b->cap / 2 : 1024;
		uint8_t *np = realloc(b->p, cap * b->esz);

		if (!np)
			return -1;
		b->p = np;
		b->cap = cap;
	}
	e = at(b, b->n++);
	memcpy(e, addr, b->alen);
	e[b->alen] = plen;
	e[b->alen + 1] = 0;
	memcpy(e + b->alen + 2, &rule, sizeof(rule));
	return 0;
}

static int cmp4(const void *x, const void *y)
{
	return full_cmp(4, x, y);
}

static int cmp6(const void *x, const void *y)
{
	return full_cmp(16, x, y);
}

size_t prefix_build_finish(struct prefix_build *b, int family, void **out,
                           struct conflict_log *log)
{
	const unsigned alen = b->alen;
	char buf[PREFIX_STRLEN];
	size_t w = 0;

	/* the rule breaks ties: the order is total, the lowest rule comes first */
	if (b->n > 1)
		qsort(b->p, b->n, b->esz, alen == 4 ? cmp4 : cmp6);

	for (size_t i = 0; i < b->n; i++) {
		uint8_t *e = at(b, i);

		if (w) {
			const uint8_t *win = at(b, w - 1);

			if (!key_cmp(alen, win, e)) {
				uint16_t rw = rule_of(alen, win), rl = rule_of(alen, e);
				uint16_t gw = log->rule_group[rw], gl = log->rule_group[rl];

				if (gw != gl && log->n++ < CONFLICT_WARN)
					warn("%s: claimed by rule '%s' (%s) and rule '%s' (%s), "
					     "first one wins", prefix_fmt(family, e, e[alen], buf),
					     log->rule_names[rw], log->group_names[gw],
					     log->rule_names[rl], log->group_names[gl]);
				continue;
			}
		}
		if (w != i)
			copy(alen, at(b, w), e);
		w++;
	}

	if (!w) {
		free(b->p);
		*out = NULL;
	} else {
		/* exact size; shrinking a mmapped block is an mremap, no copy */
		uint8_t *np = realloc(b->p, w * b->esz);

		*out = np ? np : b->p;
	}
	b->p = NULL;
	prefix_build_free(b);
	return w;
}

void prefix_build_free(struct prefix_build *b)
{
	free(b->p);
	prefix_build_init(b, b->alen == 4 ? AF_INET : AF_INET6);
}
