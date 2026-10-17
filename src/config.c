#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <uci.h>

#include "config.h"
#include "log.h"

#define DEFAULT_FWMASK		0xff000000
#define DEFAULT_TABLE_ID	10000
#define DEFAULT_RULE_PRIO	10000
#define DEFAULT_GW_TABLE	254	/* main */
#define DEFAULT_RT_PROTO	233
#define DEFAULT_NEXTHOP_ID	10000
#define DEFAULT_PROBE_MARK	0xfe
#define DEFAULT_BUCKETS		1024
#define DEFAULT_TIMER_IDLE	120
#define DEFAULT_TIMER_BUSY	600
#define DEFAULT_PROBE_MS	1000
#define DEFAULT_PROBE_COUNT	3

#define MIN_PROBE_MS		100
#define MAX_TIMER		(UINT32_MAX / 100)	/* kernel wants centiseconds */
#define TIMER_UNSET		UINT32_MAX		/* never valid, see MAX_TIMER */

/* Resilient group defaults; per-group values fall back to these after pass 1. */
struct nh_defaults {
	uint32_t buckets;
	uint32_t timer_idle;
	uint32_t timer_busy;
};

static int parse_u32(const char *s, uint32_t *out)
{
	unsigned long long v;
	char *end;

	if (!s || !*s || *s == '-')
		return -1;
	errno = 0;
	v = strtoull(s, &end, 0);
	if (errno || *end || v > UINT32_MAX)
		return -1;
	*out = v;
	return 0;
}

/* Decimal seconds with up to 3 fractional digits, e.g. "1", "0.2". */
static int parse_ms(const char *s, uint32_t *out)
{
	unsigned long long v = 0;
	int frac = -1;

	if (!*s)
		return -1;
	for (; *s; s++) {
		if (*s == '.' && frac < 0) {
			frac = 0;
			continue;
		}
		if (!isdigit((unsigned char)*s) || frac >= 3)
			return -1;
		v = v * 10 + (*s - '0');
		if (frac >= 0)
			frac++;
		if (v > UINT32_MAX)
			return -1;
	}
	for (frac = frac < 0 ? 0 : frac; frac < 3; frac++)
		v *= 10;
	if (v > UINT32_MAX)
		return -1;
	*out = v;
	return 0;
}

static int parse_table(const char *s, uint32_t *out)
{
	if (!strcmp(s, "main"))
		*out = 254;
	else if (!strcmp(s, "default"))
		*out = 253;
	else if (!strcmp(s, "local"))
		*out = 255;
	else if (parse_u32(s, out) || !*out)
		return -1;
	return 0;
}

static const char *opt_str(struct uci_context *ctx, struct uci_section *s, const char *name)
{
	return uci_lookup_option_string(ctx, s, name);
}

static int opt_u32(struct uci_context *ctx, struct uci_section *s, const char *name,
                   uint32_t *out)
{
	const char *v = opt_str(ctx, s, name);

	if (!v)
		return 0;
	if (parse_u32(v, out)) {
		err("config: invalid %s '%s'", name, v);
		return -1;
	}
	return 0;
}

static int parse_globals(struct uci_context *ctx, struct uci_section *s, struct config *c,
                         struct nh_defaults *d)
{
	const char *v;
	uint32_t proto = c->rt_proto;

	if (opt_str(ctx, s, "iface_prio")) {
		err("config: 'iface_prio' was removed, rules now live at rule_prio, "
		    "rule_prio + 1 and rule_prio + 2..");
		return -1;
	}

	if (opt_u32(ctx, s, "fwmask", &c->fwmask) ||
	    opt_u32(ctx, s, "table_id", &c->table_id) ||
	    opt_u32(ctx, s, "rule_prio", &c->rule_prio) ||
	    opt_u32(ctx, s, "rt_proto", &proto) ||
	    opt_u32(ctx, s, "nexthop_id", &c->nexthop_id) ||
	    opt_u32(ctx, s, "probe_mark", &c->probe_mark) ||
	    opt_u32(ctx, s, "buckets", &d->buckets) ||
	    opt_u32(ctx, s, "timer_idle", &d->timer_idle) ||
	    opt_u32(ctx, s, "timer_busy", &d->timer_busy))
		return -1;

	if (proto <= 4 || proto > 255) {
		/* 0..4 belong to the kernel/boot/static, flushing those would be rude */
		err("config: rt_proto must be in 5..255");
		return -1;
	}
	c->rt_proto = proto;

	v = opt_str(ctx, s, "gw_table");
	if (v && parse_table(v, &c->gw_table)) {
		err("config: invalid gw_table '%s'", v);
		return -1;
	}

	return 0;
}

int config_find_device(const struct config *c, const char *spec)
{
	for (size_t i = 0; c && i < c->n_devices; i++)
		if (!strcmp(c->devices[i].spec, spec))
			return i;
	return -1;
}

int config_find_group(const struct config *c, const char *name)
{
	for (size_t i = 0; c && i < c->n_groups; i++)
		if (!strcmp(c->groups[i].name, name))
			return i;
	return -1;
}

bool config_dev_probed(const struct config *c, size_t d)
{
	for (size_t g = 0; g < c->n_groups; g++) {
		const struct cfg_group *grp = &c->groups[g];

		if (!grp->has_probe[0] && !grp->has_probe[1])
			continue;
		for (size_t m = 0; m < grp->n_members; m++)
			if (grp->members[m].dev == d)
				return true;
	}
	return false;
}

static int add_member(struct config *c, struct cfg_group *g, const char *entry)
{
	const char *colon = strrchr(entry, ':');
	size_t len = colon ? (size_t)(colon - entry) : strlen(entry);
	uint32_t weight = 1;
	char spec[16];
	int idx;

	if (!len || len >= sizeof(spec)) {
		err("config: group '%s': invalid device '%s' (1..15 chars)", g->name, entry);
		return -1;
	}
	memcpy(spec, entry, len);
	spec[len] = '\0';

	if (colon && (parse_u32(colon + 1, &weight) || weight < 1 || weight > 256)) {
		err("config: group '%s': device '%s': weight must be in 1..256", g->name, entry);
		return -1;
	}
	if (g->n_members >= MAX_GROUP_MEMBERS) {
		err("config: group '%s': more than %d devices", g->name, MAX_GROUP_MEMBERS);
		return -1;
	}

	idx = config_find_device(c, spec);
	if (idx < 0) {
		struct cfg_device *nd;

		if (c->n_devices >= UINT16_MAX)
			return -1;
		nd = realloc(c->devices, (c->n_devices + 1) * sizeof(*nd));
		if (!nd)
			return -1;
		c->devices = nd;
		memset(&nd[c->n_devices], 0, sizeof(*nd));
		nd[c->n_devices].spec = strdup(spec);
		if (!nd[c->n_devices].spec)
			return -1;
		idx = c->n_devices++;
	}

	for (size_t i = 0; i < g->n_members; i++) {
		if (g->members[i].dev == idx) {
			err("config: group '%s': device '%s' listed twice", g->name, spec);
			return -1;
		}
	}

	g->members[g->n_members].dev = idx;
	g->members[g->n_members].weight = weight;
	g->n_members++;
	return 0;
}

static int parse_addr(const char *group, const char *opt, const char *v, int family,
                      uint8_t *out)
{
	if (inet_pton(family, v, out) != 1) {
		err("config: group '%s': invalid %s '%s'", group, opt, v);
		return -1;
	}
	return 0;
}

static int parse_gw(struct config *c, struct cfg_group *g, const char *v, int f)
{
	const char *opt = f ? "gateway6" : "gateway";
	struct cfg_device *dev;
	uint8_t gw[16] = {};

	if (g->n_members != 1) {
		err("config: group '%s': '%s' needs exactly one device", g->name, opt);
		return -1;
	}
	if (parse_addr(g->name, opt, v, f ? AF_INET6 : AF_INET, gw))
		return -1;

	dev = &c->devices[g->members[0].dev];
	if (dev->has_gw[f] && memcmp(dev->gw[f], gw, sizeof(gw))) {
		err("config: device '%s': conflicting %s from group '%s'", dev->spec, opt, g->name);
		return -1;
	}
	memcpy(dev->gw[f], gw, sizeof(gw));
	dev->has_gw[f] = true;
	return 0;
}

static int opt_timer(struct uci_context *ctx, struct uci_section *s, const char *group,
                     const char *name, uint32_t *out)
{
	uint32_t v;

	if (!opt_str(ctx, s, name))
		return 0;
	if (opt_u32(ctx, s, name, &v))
		return -1;
	if (v > MAX_TIMER) {
		err("config: group '%s': %s must be at most %u", group, name, MAX_TIMER);
		return -1;
	}
	*out = v;
	return 0;
}

static int parse_group(struct uci_context *ctx, struct uci_section *s, struct config *c,
                       struct cfg_group *g)
{
	struct uci_option *o;
	struct uci_element *le;
	uint32_t v32;
	const char *v;

	g->name = strdup(s->e.name);
	g->members = calloc(MAX_GROUP_MEMBERS, sizeof(*g->members));
	if (!g->name || !g->members)
		return -1;
	g->timer_idle = g->timer_busy = TIMER_UNSET;	/* buckets 0 = unset */
	g->probe_timer_ms = DEFAULT_PROBE_MS;
	g->probe_count = DEFAULT_PROBE_COUNT;

	o = uci_lookup_option(ctx, s, "device");
	if (o && o->type == UCI_TYPE_STRING) {
		if (add_member(c, g, o->v.string))
			return -1;
	} else if (o) {
		uci_foreach_element(&o->v.list, le)
			if (add_member(c, g, le->name))
				return -1;
	}
	if (!g->n_members) {
		if (s->anonymous) {
			err("config: anonymous group section needs 'list device'");
			return -1;
		}
		if (add_member(c, g, s->e.name))
			return -1;
	}

	if (opt_u32(ctx, s, "fwmark", &g->fwmark))
		return -1;

	v = opt_str(ctx, s, "gateway");
	if (v && parse_gw(c, g, v, 0))
		return -1;
	v = opt_str(ctx, s, "gateway6");
	if (v && parse_gw(c, g, v, 1))
		return -1;

	v = opt_str(ctx, s, "probe");
	if (v) {
		if (parse_addr(g->name, "probe", v, AF_INET, g->probe[0]))
			return -1;
		g->has_probe[0] = true;
	}
	v = opt_str(ctx, s, "probe6");
	if (v) {
		if (parse_addr(g->name, "probe6", v, AF_INET6, g->probe[1]))
			return -1;
		g->has_probe[1] = true;
	}

	v = opt_str(ctx, s, "probe_timer");
	if (v && (parse_ms(v, &g->probe_timer_ms) || g->probe_timer_ms < MIN_PROBE_MS)) {
		err("config: group '%s': probe_timer '%s' must be seconds >= 0.1",
		    g->name, v);
		return -1;
	}
	v32 = g->probe_count;
	if (opt_u32(ctx, s, "probe_count", &v32))
		return -1;
	if (v32 < 1 || v32 > 255) {
		err("config: group '%s': probe_count must be in 1..255", g->name);
		return -1;
	}
	g->probe_count = v32;

	v32 = 0;
	if (opt_u32(ctx, s, "buckets", &v32))
		return -1;
	if (opt_str(ctx, s, "buckets") && (v32 < 1 || v32 > UINT16_MAX)) {
		err("config: group '%s': buckets must be in 1..65535", g->name);
		return -1;
	}
	g->buckets = v32;

	if (opt_timer(ctx, s, g->name, "timer_idle", &g->timer_idle) ||
	    opt_timer(ctx, s, g->name, "timer_busy", &g->timer_busy))
		return -1;

	return 0;
}

/* --- CIDR lists --- */

#define PREFIX_STRLEN	(INET6_ADDRSTRLEN + 4)
#define CONFLICT_WARN	10

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

/*
 * Parse "addr[/plen]" from s[0..len). Returns AF_INET or AF_INET6, -1 if
 * invalid. Host bits are cleared; *masked tells whether any were set.
 */
static int cidr_parse(const char *s, size_t len, uint8_t addr[16], uint8_t *plen, bool *masked)
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

	alen = family == AF_INET ? 4 : 16;
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

static const char *prefix_fmt(int family, const uint8_t *addr, uint8_t plen, char *buf)
{
	inet_ntop(family, addr, buf, INET6_ADDRSTRLEN);
	sprintf(buf + strlen(buf), "/%u", plen);
	return buf;
}

/* --- building the sorted arrays --- */

/* Collects one family's prefixes, then sorts them into a struct prefix4/6 array. */
struct prefix_build {
	uint8_t *p;		/* elements of esz bytes */
	size_t n, cap;
	uint8_t esz, alen;
};

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

static void prefix_build_init(struct prefix_build *b, int family)
{
	memset(b, 0, sizeof(*b));
	b->alen = family == AF_INET ? 4 : 16;
	b->esz = ESZ(b->alen);
}

static int prefix_build_add(struct prefix_build *b, const uint8_t *addr, uint8_t plen, uint16_t rule)
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

static void prefix_build_free(struct prefix_build *b)
{
	free(b->p);
	prefix_build_init(b, b->alen == 4 ? AF_INET : AF_INET6);
}

/*
 * Sorts by (addr, plen) and the lowest rule, drops all but the first of
 * each key, warning when a dropped one belongs to another group (the first
 * CONFLICT_WARN times, counted in *n_conflicts). Hands the exact-size
 * array over in *out and frees the rest. Returns the length.
 */
static size_t prefix_build_finish(struct prefix_build *b, int family, void **out,
                                  const struct config *c, const char *const *rule_names,
                                  size_t *n_conflicts)
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
				uint16_t gw = c->rule_group[rw], gl = c->rule_group[rl];

				if (gw != gl && (*n_conflicts)++ < CONFLICT_WARN)
					warn("%s: claimed by rule '%s' (%s) and rule '%s' (%s), "
					     "first one wins", prefix_fmt(family, e, e[alen], buf),
					     rule_names[rw], c->groups[gw].name,
					     rule_names[rl], c->groups[gl].name);
				continue;
			}
		}
		if (w != i)
			memcpy(at(b, w), e, b->esz);
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

/*
 * List files are read through one window, each line scanned once. A line is
 * cut every 511 bytes, as the fgets() with a 512-byte buffer this replaced
 * did: the rest of an over-long line is a line of its own.
 */
#define LIST_WINDOW	16384
#define LIST_LINE	511

static char list_window[LIST_WINDOW];

/* One line of len bytes (with its newline, if any). Returns -1 when out of memory. */
static int load_line(const char *path, unsigned lineno, const char *s, size_t len,
                     uint16_t rule, struct prefix_build *pb, size_t *n_bad)
{
	uint8_t addr[16], plen;
	const char *e;
	bool masked;
	int family;

	/* as C strings: a NUL ends the line, then '#' does */
	e = memchr(s, '\0', len);
	if (e)
		len = e - s;
	e = memchr(s, '#', len);
	e = e ? e : s + len;
	for (; s < e && isspace((unsigned char)*s); s++)
		;
	for (; e > s && isspace((unsigned char)e[-1]); e--)
		;
	if (s == e)
		return 0;

	family = cidr_parse(s, e - s, addr, &plen, &masked);
	if (family < 0) {
		if ((*n_bad)++ < 10)
			warn("%s:%u: invalid CIDR '%.*s', skipped", path, lineno, (int)(e - s), s);
		return 0;
	}
	if (masked) {
		char buf[PREFIX_STRLEN];

		if ((*n_bad)++ < 10)
			warn("%s:%u: '%.*s' has host bits set, using %s", path, lineno,
			     (int)(e - s), s, prefix_fmt(family, addr, plen, buf));
	}
	return prefix_build_add(&pb[family == AF_INET6], addr, plen, rule);
}

/*
 * Returns -1 when out of memory or on a read error: a partial list would
 * drop the rest's routes.
 */
static int load_list_file(const char *path, uint16_t rule, struct prefix_build *pb,
                          size_t *n_bad)
{
	size_t have = 0, pos = 0;
	unsigned lineno = 0;
	bool eof = false;
	int fd, ret = 0;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		warn("%s: %s", path, strerror(errno));
		return 0;
	}

	for (;;) {
		const char *line = list_window + pos, *nl;
		size_t avail = have - pos, len;

		nl = memchr(line, '\n', avail < LIST_LINE ? avail : LIST_LINE);
		if (nl) {
			len = nl - line + 1;
		} else if (avail >= LIST_LINE) {
			len = LIST_LINE;
		} else if (eof) {
			if (!avail)
				break;
			len = avail;
		} else {
			ssize_t r;

			memmove(list_window, line, avail);
			have = avail;
			pos = 0;
			r = read(fd, list_window + have, sizeof(list_window) - have);
			if (r < 0 && errno == EINTR)
				continue;
			if (r < 0 && errno == EISDIR && !lineno) {
				/* a glob may match a subdirectory: not an error */
				warn("%s: is a directory, skipped", path);
				break;
			}
			if (r < 0) {
				err("%s: %s", path, strerror(errno));
				ret = -1;
				break;
			}
			eof = !r;
			have += r;
			continue;
		}
		pos += len;
		if (load_line(path, ++lineno, line, len, rule, pb, n_bad)) {
			err("out of memory");
			ret = -1;
			break;
		}
	}
	close(fd);
	return ret;
}

/*
 * The prefix arrays and the files they were read from, shared by the
 * configs that find the same files. fp has, per rule, every file its
 * cidrsets match, as path, NUL and file_id; then a NUL. A file rewritten
 * in place to the same size within one timestamp tick goes unnoticed.
 */
struct cfg_lists {
	unsigned refs;
	size_t n_dup;		/* for the log */
	char *fp;		/* NULL: unknown, never matches */
	size_t fp_len;
};

struct file_id {
	uint64_t dev, ino;
	int64_t size, mtime, mtime_ns, ctime, ctime_ns;
};

struct fp_build {
	char *p;
	size_t n, cap;
	bool bad;		/* a stat failed, or out of memory */
};

static void fp_add(struct fp_build *fp, const void *data, size_t len)
{
	if (fp->bad)
		return;
	if (fp->n + len > fp->cap) {
		size_t cap = (fp->n + len) * 2;
		char *np = realloc(fp->p, cap);

		if (!np) {
			fp->bad = true;
			return;
		}
		fp->p = np;
		fp->cap = cap;
	}
	memcpy(fp->p + fp->n, data, len);
	fp->n += len;
}

static void fp_add_file(struct fp_build *fp, const char *path)
{
	struct file_id id;
	struct stat st;

	if (stat(path, &st)) {
		fp->bad = true;
		return;
	}
	id = (struct file_id){
		.dev = st.st_dev, .ino = st.st_ino, .size = st.st_size,
		.mtime = st.st_mtim.tv_sec, .mtime_ns = st.st_mtim.tv_nsec,
		.ctime = st.st_ctim.tv_sec, .ctime_ns = st.st_ctim.tv_nsec,
	};
	fp_add(fp, path, strlen(path) + 1);
	fp_add(fp, &id, sizeof(id));
}

/* A cidrset's matches, read once the lists turn out to have changed. */
struct cidrset {
	const char *rule_name, *pattern;
	uint16_t rule;
	bool matched;
	glob_t g;
};

static int glob_cidrset(const char *rule_name, const char *pattern, uint16_t rule,
                        struct cidrset **sets, size_t *n_sets, struct fp_build *fp)
{
	struct cidrset *cs = realloc(*sets, (*n_sets + 1) * sizeof(*cs));
	int r;

	if (!cs)
		return -1;
	*sets = cs;
	cs += *n_sets;
	*cs = (struct cidrset){ .rule_name = rule_name, .pattern = pattern, .rule = rule };
	++*n_sets;
	if (!pattern)
		return 0;

	r = glob(pattern, 0, NULL, &cs->g);
	if (r == GLOB_NOMATCH)
		return 0;
	if (r) {
		err("rule '%s': glob '%s' failed", rule_name, pattern);
		return -1;
	}
	cs->matched = true;
	for (size_t i = 0; i < cs->g.gl_pathc; i++)
		fp_add_file(fp, cs->g.gl_pathv[i]);
	return 0;
}

/* Reads cs into pb; with pb NULL (lists reused), only says what needs no reading. */
static int load_cidrset(const struct cidrset *cs, struct prefix_build *pb)
{
	size_t n_bad = 0, before;

	if (!cs->pattern) {
		warn("config: rule '%s' has no cidrset", cs->rule_name);
		return 0;
	}
	if (!cs->matched) {
		info("rule '%s': cidrset '%s' matches nothing", cs->rule_name, cs->pattern);
		return 0;
	}
	if (!pb)
		return 0;
	before = pb[0].n + pb[1].n;
	for (size_t i = 0; i < cs->g.gl_pathc; i++)
		if (load_list_file(cs->g.gl_pathv[i], cs->rule, pb, &n_bad))
			return -1;

	if (n_bad > 10)
		warn("rule '%s': %zu more problems in '%s'", cs->rule_name, n_bad - 10,
		     cs->pattern);
	debug("rule '%s': '%s' -> %zu prefixes", cs->rule_name, cs->pattern,
	      pb[0].n + pb[1].n - before);
	return 0;
}

/* Shares prev's lists with c if they were read from the files fp found. */
static bool lists_reuse(struct config *c, const struct config *prev,
                        const struct fp_build *fp)
{
	struct cfg_lists *l = prev ? prev->lists : NULL;

	if (fp->bad || !l || !l->fp || l->fp_len != fp->n || memcmp(l->fp, fp->p, fp->n))
		return false;
	l->refs++;
	c->lists = l;
	c->p4 = prev->p4;
	c->n_p4 = prev->n_p4;
	c->p6 = prev->p6;
	c->n_p6 = prev->n_p6;
	return true;
}

static int validate(struct config *c, const struct nh_defaults *d)
{
	uint32_t mask = c->fwmask, shift, max;
	uint64_t last;

	if (!mask) {
		err("config: fwmask must be non-zero");
		return -1;
	}
	shift = __builtin_ctz(mask);
	max = mask >> shift;
	if (max & (max + 1)) {
		err("config: fwmask 0x%x is not contiguous", mask);
		return -1;
	}

	if (!c->probe_mark || c->probe_mark > max) {
		err("config: probe_mark 0x%x must be non-zero and fit in fwmask 0x%x",
		    c->probe_mark, mask);
		return -1;
	}
	c->probe_mark <<= shift;

	for (size_t i = 0; i < c->n_groups; i++) {
		struct cfg_group *g = &c->groups[i];

		if (!g->fwmark)
			continue;
		if (g->fwmark > max) {
			err("config: group '%s': fwmark 0x%x does not fit in fwmask 0x%x",
			    g->name, g->fwmark, mask);
			return -1;
		}
		g->fwmark <<= shift;

		if (g->fwmark == c->probe_mark) {
			err("config: group '%s': fwmark 0x%x is the probe_mark",
			    g->name, g->fwmark >> shift);
			return -1;
		}
		for (size_t j = 0; j < i; j++) {
			if (c->groups[j].fwmark == g->fwmark) {
				err("config: groups '%s' and '%s' share fwmark",
				    c->groups[j].name, g->name);
				return -1;
			}
		}
	}

	last = (uint64_t)c->table_id + 1 + c->n_groups;
	if (!c->table_id || last > UINT32_MAX || (c->table_id <= 255 && last >= 253)) {
		err("config: table range %u..%llu is invalid or overlaps reserved tables",
		    c->table_id, (unsigned long long)last);
		return -1;
	}

	last = (uint64_t)c->rule_prio + 1 + c->n_groups;
	if (last > UINT32_MAX) {
		err("config: rule_prio %u + %zu groups overflows", c->rule_prio, c->n_groups);
		return -1;
	}
	if (last >= 32766)
		warn("config: rules %u..%llu reach the main table rule (32766)",
		     c->rule_prio, (unsigned long long)last);

	if (!c->nexthop_id || cfg_nhid_end(c) > UINT32_MAX) {
		err("config: nexthop_id %u: range %u..%llu is invalid", c->nexthop_id,
		    c->nexthop_id, (unsigned long long)cfg_nhid_end(c));
		return -1;
	}

	if (d->buckets < 1 || d->buckets > UINT16_MAX) {
		err("config: buckets must be in 1..65535");
		return -1;
	}
	if (d->timer_idle > MAX_TIMER || d->timer_busy > MAX_TIMER) {
		err("config: timer_idle and timer_busy must be at most %u", MAX_TIMER);
		return -1;
	}

	for (size_t i = 0; i < c->n_groups; i++) {
		struct cfg_group *g = &c->groups[i];

		if (!g->buckets)
			g->buckets = d->buckets;
		if (g->timer_idle == TIMER_UNSET)
			g->timer_idle = d->timer_idle;
		if (g->timer_busy == TIMER_UNSET)
			g->timer_busy = d->timer_busy;
		if (g->timer_busy && g->timer_busy <= g->timer_idle)
			warn("config: group '%s': timer_busy should exceed timer_idle, "
			     "otherwise idle buckets never get a chance to move first", g->name);
	}

	return 0;
}

static struct config *load(const char *path, const struct config *prev, bool lists)
{
	struct uci_context *ctx = NULL;
	struct uci_package *pkg = NULL;
	struct uci_element *e;
	struct prefix_build pb[2];
	struct cidrset *sets = NULL;
	struct fp_build fp = {};
	size_t n_raw, n_sets = 0;
	void *arr;
	struct nh_defaults defs = {
		.buckets = DEFAULT_BUCKETS,
		.timer_idle = DEFAULT_TIMER_IDLE,
		.timer_busy = DEFAULT_TIMER_BUSY,
	};
	const char **rule_names = NULL;
	size_t n_rules = 0, n_globals = 0, n_conflicts = 0;
	struct config *c;
	FILE *f = NULL;
	bool ok = false, reused;

	c = calloc(1, sizeof(*c));
	if (!c)
		return NULL;
	c->fwmask = DEFAULT_FWMASK;
	c->table_id = DEFAULT_TABLE_ID;
	c->rule_prio = DEFAULT_RULE_PRIO;
	c->gw_table = DEFAULT_GW_TABLE;
	c->rt_proto = DEFAULT_RT_PROTO;
	c->nexthop_id = DEFAULT_NEXTHOP_ID;
	c->probe_mark = DEFAULT_PROBE_MARK;
	prefix_build_init(&pb[0], AF_INET);
	prefix_build_init(&pb[1], AF_INET6);

	f = fopen(path, "r");
	if (!f) {
		err("config: %s: %s", path, strerror(errno));
		goto out;
	}

	ctx = uci_alloc_context();
	if (!ctx)
		goto out;
	if (uci_import(ctx, f, "routebot", &pkg, true) != UCI_OK) {
		char *msg = NULL;

		uci_get_errorstr(ctx, &msg, path);
		err("config: %s", msg ? msg : "parse error");
		free(msg);
		goto out;
	}

	/* pass 1: globals and groups, so rules can reference any group */
	uci_foreach_element(&pkg->sections, e) {
		struct uci_section *s = uci_to_section(e);

		if (!strcmp(s->type, "routebot")) {
			if (n_globals++)
				warn("config: multiple 'routebot' sections, merging");
			if (parse_globals(ctx, s, c, &defs))
				goto out;
		} else if (!strcmp(s->type, "group")) {
			struct cfg_group *ng;

			if (c->n_groups >= UINT16_MAX)
				goto out;
			ng = realloc(c->groups, (c->n_groups + 1) * sizeof(*ng));
			if (!ng)
				goto out;
			c->groups = ng;
			memset(&ng[c->n_groups], 0, sizeof(*ng));
			c->n_groups++;
			if (parse_group(ctx, s, c, &ng[c->n_groups - 1]))
				goto out;
			if (config_find_group(c, s->e.name) != (int)c->n_groups - 1) {
				err("config: duplicate group '%s'", s->e.name);
				goto out;
			}
		} else if (!strcmp(s->type, "interface")) {
			err("config: 'interface' sections were replaced by 'group' (see README)");
			goto out;
		} else if (strcmp(s->type, "rule")) {
			warn("config: unknown section type '%s'", s->type);
		}
	}

	if (validate(c, &defs))
		goto out;
	if (!lists) {
		ok = true;
		goto out;
	}

	/* pass 2: rules */
	uci_foreach_element(&pkg->sections, e) {
		struct uci_section *s = uci_to_section(e);
		struct uci_option *o;
		struct uci_element *le;
		const char *group;
		const char **nr;
		uint16_t *rg;
		int idx;

		if (strcmp(s->type, "rule"))
			continue;

		if (opt_str(ctx, s, "iface")) {
			err("config: rule '%s': 'option iface' was replaced by 'option group'",
			    s->e.name);
			goto out;
		}
		group = opt_str(ctx, s, "group");
		idx = group ? config_find_group(c, group) : -1;
		if (idx < 0) {
			if (group)
				err("config: rule '%s': unknown group '%s'", s->e.name, group);
			else
				err("config: rule '%s': missing 'option group'", s->e.name);
			goto out;
		}
		if (n_rules >= UINT16_MAX)
			goto out;

		nr = realloc(rule_names, (n_rules + 1) * sizeof(*nr));
		if (!nr)
			goto out;
		rule_names = nr;
		rule_names[n_rules] = s->e.name;
		rg = realloc(c->rule_group, (n_rules + 1) * sizeof(*rg));
		if (!rg)
			goto out;
		c->rule_group = rg;
		rg[n_rules] = idx;

		/* globbed now, read below unless the files are the same as prev's */
		o = uci_lookup_option(ctx, s, "cidrset");
		if (!o || o->type == UCI_TYPE_STRING) {
			if (glob_cidrset(s->e.name, o ? o->v.string : NULL, n_rules, &sets,
			                 &n_sets, &fp))
				goto out;
		} else {
			uci_foreach_element(&o->v.list, le)
				if (glob_cidrset(s->e.name, le->name, n_rules, &sets, &n_sets, &fp))
					goto out;
		}
		fp_add(&fp, "", 1);
		c->n_rules = ++n_rules;
	}

	reused = lists_reuse(c, prev, &fp);
	if (!reused) {
		c->lists = calloc(1, sizeof(*c->lists));
		if (!c->lists)
			goto out;
		c->lists->refs = 1;
	}
	for (size_t i = 0; i < n_sets; i++)
		if (load_cidrset(&sets[i], reused ? NULL : pb))
			goto out;

	if (reused) {
		debug("config: lists unchanged, reused");
	} else {
		n_raw = pb[0].n + pb[1].n;
		c->n_p4 = prefix_build_finish(&pb[0], AF_INET, &arr, c, rule_names, &n_conflicts);
		c->p4 = arr;
		c->n_p6 = prefix_build_finish(&pb[1], AF_INET6, &arr, c, rule_names, &n_conflicts);
		c->p6 = arr;
		if (n_conflicts > CONFLICT_WARN)
			warn("%zu more prefixes claimed by several rules, first one wins",
			     n_conflicts - CONFLICT_WARN);
		c->lists->n_dup = n_raw - c->n_p4 - c->n_p6;
		if (!fp.bad) {
			c->lists->fp = fp.p;
			c->lists->fp_len = fp.n;
			fp.p = NULL;
		}
	}

	info("config: %zu groups, %zu devices, %zu rules, %zu prefixes (%zu duplicates dropped)",
	     c->n_groups, c->n_devices, n_rules, c->n_p4 + c->n_p6, c->lists->n_dup);
	ok = true;

out:
	prefix_build_free(&pb[0]);
	prefix_build_free(&pb[1]);
	for (size_t i = 0; i < n_sets; i++)
		globfree(&sets[i].g);
	free(sets);
	free(fp.p);
	free(rule_names);
	if (ctx)
		uci_free_context(ctx);
	if (f)
		fclose(f);
	if (!ok) {
		config_free(c);
		return NULL;
	}
	return c;
}

struct config *config_load(const char *path, const struct config *prev)
{
	return load(path, prev, true);
}

struct config *config_load_globals(const char *path)
{
	return load(path, NULL, false);
}

void config_free(struct config *c)
{
	if (!c)
		return;
	for (size_t i = 0; i < c->n_groups; i++) {
		free(c->groups[i].name);
		free(c->groups[i].members);
	}
	free(c->groups);
	for (size_t i = 0; i < c->n_devices; i++)
		free(c->devices[i].spec);
	free(c->devices);
	/* the last config holding the lists frees them */
	if (!c->lists || !--c->lists->refs) {
		free(c->p4);
		free(c->p6);
		if (c->lists)
			free(c->lists->fp);
		free(c->lists);
	}
	free(c->rule_group);
	free(c);
}
