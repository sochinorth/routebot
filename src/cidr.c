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
	b->sorted = true;
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
	e = at(b, b->n);
	memcpy(e, addr, b->alen);
	e[b->alen] = plen;
	e[b->alen + 1] = 0;
	memcpy(e + b->alen + 2, &rule, sizeof(rule));
	if (b->sorted && b->n > b->run && key_cmp(b->alen, e - b->esz, e) > 0)
		b->sorted = false;
	b->n++;
	return 0;
}

/* In place, no allocation; the order is total, so stability doesn't matter. */
static void heapsort_(unsigned alen, uint8_t *p, size_t n)
{
	const size_t esz = ESZ(alen);
	uint8_t t[ESZ(16)];

	for (size_t end = n, start = n / 2; end > 1;) {
		size_t root, child;

		if (start) {
			start--;
		} else {
			end--;
			copy(alen, t, p);
			copy(alen, p, p + end * esz);
			copy(alen, p + end * esz, t);
		}
		/* sift p[start] down */
		copy(alen, t, p + start * esz);
		for (root = start; (child = 2 * root + 1) < end; root = child) {
			uint8_t *c = p + child * esz;

			if (child + 1 < end && full_cmp(alen, c, c + esz) < 0)
				c += esz, child++;
			if (full_cmp(alen, t, c) >= 0)
				break;
			copy(alen, p + root * esz, c);
		}
		copy(alen, p + root * esz, t);
	}
}

#define POP_MAX	4

/* Room for need set-aside entries; no more than limit. */
static bool side_room(struct prefix_build *b, size_t need, size_t limit)
{
	size_t cap = b->side_cap ? b->side_cap : 128;
	uint8_t *ns;

	if (need <= b->side_cap)
		return true;
	if (need > limit)
		return false;
	while (cap < need)
		cap *= 2;
	if (cap > limit)
		cap = limit;
	ns = realloc(b->side, cap * b->esz);
	if (!ns)
		return false;
	b->side = ns;
	b->side_cap = cap;
	return true;
}

/*
 * Sorts one run of n entries (one file, one rule: ties are identical). Lists
 * are dumps, sorted but for a few entries out of place, so: keep what is in
 * order, set the rest aside, sort that and merge it back from the end. An
 * entry below the last kept one is set aside itself, unless fewer kept ones
 * are above it than POP_MAX, or than the entries set aside in a row just
 * before it: then those kept ones were the odd ones and go aside instead.
 * A run that isn't nearly sorted gets a heapsort.
 */
static void sort_run(struct prefix_build *b, uint8_t *p, size_t n)
{
	const unsigned alen = b->alen, esz = b->esz;
	size_t w = 0, k = 0, streak = 0, r;

	for (r = 0; r < n; r++) {
		uint8_t *e = p + r * esz;
		size_t lo = w, hi, pop;

		if (w && key_cmp(alen, p + (w - 1) * esz, e) > 0) {
			/* the kept ones above e: p[lo..w) */
			for (lo = 0, hi = w - 1; lo < hi;) {
				size_t mid = lo + (hi - lo) / 2;

				if (key_cmp(alen, p + mid * esz, e) > 0)
					hi = mid;
				else
					lo = mid + 1;
			}
		}
		pop = w - lo;

		if (pop > POP_MAX && pop > streak) {
			if (!side_room(b, k + 1, n / 4))
				break;
			copy(alen, b->side + k++ * esz, e);
			streak++;
			continue;
		}
		if (pop) {
			if (!side_room(b, k + pop, n / 4))
				break;
			memcpy(b->side + k * esz, p + lo * esz, pop * esz);
			k += pop;
			w = lo;
		}
		if (w != r)
			copy(alen, p + w * esz, e);
		w++;
		streak = 0;
	}

	if (r < n) {
		/* not nearly sorted: put the set-aside entries back, sort in place */
		if (k)
			memcpy(p + w * esz, b->side, k * esz);
		heapsort_(alen, p, n);
		return;
	}

	heapsort_(alen, b->side, k);
	for (size_t i = w, j = k, d = n; j;) {
		if (i && key_cmp(alen, p + (i - 1) * esz, b->side + (j - 1) * esz) > 0)
			copy(alen, p + --d * esz, p + --i * esz);
		else
			copy(alen, p + --d * esz, b->side + --j * esz);
	}
}

int prefix_build_end_run(struct prefix_build *b)
{
	size_t start = b->run;

	if (b->n == start)
		return 0;
	if (!b->sorted)
		sort_run(b, at(b, start), b->n - start);
	b->run = b->n;
	b->sorted = true;
	/* in order after the previous run (the usual case): one run */
	if (!start || key_cmp(b->alen, at(b, start - 1), at(b, start)) <= 0)
		return 0;
	if (b->n_runs == b->cap_runs) {
		size_t cap = b->cap_runs ? 2 * b->cap_runs : 16;
		size_t *nr = realloc(b->runs, cap * sizeof(*nr));

		if (!nr) {
			b->lost_run = true;
			return -1;
		}
		b->runs = nr;
		b->cap_runs = cap;
	}
	b->runs[b->n_runs++] = start;
	return 0;
}

/* First index in [lo, hi) whose key is > x (upper) or >= x (!upper). */
static size_t bound(const struct prefix_build *b, size_t lo, size_t hi, const uint8_t *x,
                    bool upper)
{
	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;
		int r = key_cmp(b->alen, at(b, mid), x);

		if (r < 0 || (upper && r == 0))
			lo = mid + 1;
		else
			hi = mid;
	}
	return lo;
}

/*
 * Stable merge of the sorted runs [lo, mid) and [mid, hi): what is already
 * in place is skipped, the smaller remaining side goes through tmp.
 */
static int merge(struct prefix_build *b, size_t lo, size_t mid, size_t hi, uint8_t **tmp,
                 size_t *tmp_cap)
{
	const unsigned alen = b->alen, esz = b->esz;
	size_t na, nb;

	lo = bound(b, lo, mid, at(b, mid), true);
	if (lo == mid)
		return 0;
	hi = bound(b, mid, hi, at(b, mid - 1), false);
	na = mid - lo;
	nb = hi - mid;

	if (*tmp_cap < (na < nb ? na : nb)) {
		size_t cap = na < nb ? na : nb;
		uint8_t *nt = realloc(*tmp, cap * esz);

		if (!nt)
			return -1;
		*tmp = nt;
		*tmp_cap = cap;
	}

	if (na <= nb) {
		uint8_t *t = *tmp, *te = t + na * esz;
		uint8_t *d = at(b, lo), *y = at(b, mid), *ye = at(b, hi);

		memcpy(t, d, na * esz);
		for (; t < te && y < ye; d += esz) {
			if (key_cmp(alen, y, t) < 0) {
				copy(alen, d, y);
				y += esz;
			} else {
				copy(alen, d, t);
				t += esz;
			}
		}
		memcpy(d, t, te - t);
	} else {
		uint8_t *t = *tmp, *te = t + nb * esz;
		uint8_t *d = at(b, hi), *x = at(b, mid), *xb = at(b, lo);

		memcpy(t, x, nb * esz);
		while (te > t && x > xb) {
			d -= esz;
			if (key_cmp(alen, x - esz, te - esz) > 0) {
				x -= esz;
				copy(alen, d, x);
			} else {
				te -= esz;
				copy(alen, d, te);
			}
		}
		memcpy(d - (te - t), t, te - t);
	}
	return 0;
}

/*
 * Runs follow each other in rule order and each is sorted, so a stable
 * merge leaves duplicates lowest rule first.
 */
static void sort(struct prefix_build *b)
{
	uint8_t *tmp = NULL;
	size_t tmp_cap = 0;

	if (b->lost_run) {
		heapsort_(b->alen, b->p, b->n);
		return;
	}
	while (b->n_runs) {
		/* bounds: 0, runs..., n; merge neighbours pairwise */
		size_t k = 0;

		for (size_t i = 0; i < b->n_runs; i += 2) {
			size_t lo = i ? b->runs[i - 1] : 0;
			size_t hi = i + 1 < b->n_runs ? b->runs[i + 1] : b->n;

			if (merge(b, lo, b->runs[i], hi, &tmp, &tmp_cap)) {
				/* no memory for tmp: same order, slower */
				heapsort_(b->alen, b->p, b->n);
				b->n_runs = 0;
				break;
			}
			if (i + 1 < b->n_runs)
				b->runs[k++] = b->runs[i + 1];
		}
		b->n_runs = k;
	}
	free(tmp);
}

size_t prefix_build_finish(struct prefix_build *b, int family, void **out,
                           struct conflict_log *log)
{
	const unsigned alen = b->alen;
	char buf[PREFIX_STRLEN];
	size_t w = 0;

	sort(b);

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
	free(b->runs);
	free(b->side);
	prefix_build_init(b, b->alen == 4 ? AF_INET : AF_INET6);
}
