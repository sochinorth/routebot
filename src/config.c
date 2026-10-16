#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <stdlib.h>
#include <string.h>
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

struct prefix_vec {
	struct prefix *p;
	size_t n, cap;
};

static int prefix_vec_push(struct prefix_vec *v, const struct prefix *p)
{
	if (v->n == v->cap) {
		size_t cap = v->cap ? v->cap * 2 : 1024;
		struct prefix *np = realloc(v->p, cap * sizeof(*np));

		if (!np)
			return -1;
		v->p = np;
		v->cap = cap;
	}
	v->p[v->n++] = *p;
	return 0;
}

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

static int find_device(const struct config *c, const char *spec)
{
	for (size_t i = 0; i < c->n_devices; i++)
		if (!strcmp(c->devices[i].spec, spec))
			return i;
	return -1;
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

	idx = find_device(c, spec);
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

/*
 * List files are read through one window, each line scanned once. A line is
 * cut every 511 bytes, as the fgets() with a 512-byte buffer this replaced
 * did: the rest of an over-long line is a line of its own.
 */
#define LIST_WINDOW	65536
#define LIST_LINE	511

static char list_window[LIST_WINDOW];

/* One line of len bytes (with its newline, if any). Returns -1 when out of memory. */
static int load_line(const char *path, unsigned lineno, const char *s, size_t len,
                     uint16_t group, uint16_t rule, struct prefix_vec *out, size_t *n_bad)
{
	struct prefix p = { .group = group, .rule = rule };
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

	family = cidr_parse(s, e - s, p.addr, &p.plen, &masked);
	if (family < 0) {
		if ((*n_bad)++ < 10)
			warn("%s:%u: invalid CIDR '%.*s', skipped", path, lineno, (int)(e - s), s);
		return 0;
	}
	if (masked) {
		char buf[PREFIX_STRLEN];

		if ((*n_bad)++ < 10)
			warn("%s:%u: '%.*s' has host bits set, using %s", path, lineno,
			     (int)(e - s), s, prefix_fmt(family, p.addr, p.plen, buf));
	}
	p.family = family;
	return prefix_vec_push(out, &p);
}

static void load_list_file(const char *path, uint16_t group, uint16_t rule,
                           struct prefix_vec *out, size_t *n_bad)
{
	size_t have = 0, pos = 0;
	unsigned lineno = 0;
	bool eof = false;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		warn("%s: %s", path, strerror(errno));
		return;
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
			if (r < 0)
				break;	/* like fgets: a read error ends the file, quietly */
			eof = !r;
			have += r;
			continue;
		}
		pos += len;
		if (load_line(path, ++lineno, line, len, group, rule, out, n_bad)) {
			err("out of memory");
			break;
		}
	}
	close(fd);
}

static int load_cidrset(const char *rule_name, const char *pattern, uint16_t group,
			uint16_t rule, struct prefix_vec *out)
{
	size_t n_bad = 0, before = out->n;
	glob_t g;
	int r;

	r = glob(pattern, 0, NULL, &g);
	if (r == GLOB_NOMATCH) {
		info("rule '%s': cidrset '%s' matches nothing", rule_name, pattern);
		return 0;
	}
	if (r) {
		err("rule '%s': glob '%s' failed", rule_name, pattern);
		return -1;
	}

	for (size_t i = 0; i < g.gl_pathc; i++)
		load_list_file(g.gl_pathv[i], group, rule, out, &n_bad);
	globfree(&g);

	if (n_bad > 10)
		warn("rule '%s': %zu more problems in '%s'", rule_name, n_bad - 10, pattern);
	debug("rule '%s': '%s' -> %zu prefixes", rule_name, pattern, out->n - before);
	return 0;
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
		err("config: nexthop_id range %u..%llu is invalid",
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

static int find_group(const struct config *c, const char *name)
{
	for (size_t i = 0; i < c->n_groups; i++)
		if (!strcmp(c->groups[i].name, name))
			return i;
	return -1;
}

struct config *config_load(const char *path)
{
	struct uci_context *ctx = NULL;
	struct uci_package *pkg = NULL;
	struct uci_element *e;
	struct prefix_vec pv = {};
	struct nh_defaults defs = {
		.buckets = DEFAULT_BUCKETS,
		.timer_idle = DEFAULT_TIMER_IDLE,
		.timer_busy = DEFAULT_TIMER_BUSY,
	};
	const char **rule_names = NULL;
	const char **group_names = NULL;
	size_t n_rules = 0, n_globals = 0, n_conflicts = 0;
	struct config *c;
	FILE *f = NULL;
	bool ok = false;

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
			if (find_group(c, s->e.name) != (int)c->n_groups - 1) {
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

	/* pass 2: rules */
	uci_foreach_element(&pkg->sections, e) {
		struct uci_section *s = uci_to_section(e);
		struct uci_option *o;
		struct uci_element *le;
		const char *group;
		const char **nr;
		int idx;

		if (strcmp(s->type, "rule"))
			continue;

		if (opt_str(ctx, s, "iface")) {
			err("config: rule '%s': 'option iface' was replaced by 'option group'",
			    s->e.name);
			goto out;
		}
		group = opt_str(ctx, s, "group");
		idx = group ? find_group(c, group) : -1;
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

		o = uci_lookup_option(ctx, s, "cidrset");
		if (!o) {
			warn("config: rule '%s' has no cidrset", s->e.name);
		} else if (o->type == UCI_TYPE_STRING) {
			if (load_cidrset(s->e.name, o->v.string, idx, n_rules, &pv))
				goto out;
		} else {
			uci_foreach_element(&o->v.list, le)
				if (load_cidrset(s->e.name, le->name, idx, n_rules, &pv))
					goto out;
		}
		n_rules++;
	}

	group_names = calloc(c->n_groups + 1, sizeof(*group_names));
	if (!group_names)
		goto out;
	for (size_t i = 0; i < c->n_groups; i++)
		group_names[i] = c->groups[i].name;

	c->n_prefixes = prefixes_normalize(pv.p, pv.n, rule_names, group_names, &n_conflicts);
	if (n_conflicts > CONFLICT_WARN)
		warn("%zu more prefixes claimed by several rules, first one wins",
		     n_conflicts - CONFLICT_WARN);
	c->prefixes = pv.p;
	pv.p = NULL;
	if (c->n_prefixes && c->n_prefixes < pv.n / 2) {
		/* lots of dupes, give memory back */
		struct prefix *np = realloc(c->prefixes, c->n_prefixes * sizeof(*np));

		if (np)
			c->prefixes = np;
	}

	info("config: %zu groups, %zu devices, %zu rules, %zu prefixes (%zu duplicates dropped)",
	     c->n_groups, c->n_devices, n_rules, c->n_prefixes, pv.n - c->n_prefixes);
	ok = true;

out:
	free(pv.p);
	free(rule_names);
	free(group_names);
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
	free(c->prefixes);
	free(c);
}
