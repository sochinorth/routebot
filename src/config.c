#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <glob.h>
#include <stdlib.h>
#include <string.h>

#include <uci.h>

#include "config.h"
#include "log.h"

#define DEFAULT_FWMASK		0xff000000
#define DEFAULT_TABLE_ID	10000
#define DEFAULT_IFACE_PRIO	10000
#define DEFAULT_RULE_PRIO	20000
#define DEFAULT_GW_TABLE	254	/* main */
#define DEFAULT_RT_PROTO	233

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

static int parse_globals(struct uci_context *ctx, struct uci_section *s, struct config *c)
{
	const char *v;
	uint32_t proto = c->rt_proto;

	if (opt_u32(ctx, s, "fwmask", &c->fwmask) ||
	    opt_u32(ctx, s, "table_id", &c->table_id) ||
	    opt_u32(ctx, s, "iface_prio", &c->iface_prio) ||
	    opt_u32(ctx, s, "rule_prio", &c->rule_prio) ||
	    opt_u32(ctx, s, "rt_proto", &proto))
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

static int parse_gw(const char *iface, const char *v, int family, uint8_t *out)
{
	if (inet_pton(family, v, out) != 1) {
		err("config: interface '%s': invalid gateway '%s'", iface, v);
		return -1;
	}
	return 0;
}

static int parse_iface(struct uci_context *ctx, struct uci_section *s, struct cfg_iface *ifc)
{
	const char *v;

	ifc->name = strdup(s->e.name);
	v = opt_str(ctx, s, "device");
	if (!v && s->anonymous) {
		err("config: anonymous interface section needs 'option device'");
		return -1;
	}
	ifc->device = strdup(v ? v : s->e.name);
	if (!ifc->name || !ifc->device)
		return -1;

	if (strlen(ifc->device) >= 16) {
		err("config: interface '%s': device name '%s' too long", ifc->name, ifc->device);
		return -1;
	}

	if (opt_u32(ctx, s, "fwmark", &ifc->fwmark))
		return -1;

	v = opt_str(ctx, s, "gateway");
	if (v) {
		if (parse_gw(ifc->name, v, AF_INET, ifc->gw[0]))
			return -1;
		ifc->has_gw[0] = true;
	}
	v = opt_str(ctx, s, "gateway6");
	if (v) {
		if (parse_gw(ifc->name, v, AF_INET6, ifc->gw[1]))
			return -1;
		ifc->has_gw[1] = true;
	}

	return 0;
}

static void load_list_file(const char *path, uint16_t iface, uint16_t rule,
			   struct prefix_vec *out, size_t *n_bad)
{
	char line[512];
	unsigned lineno = 0;
	FILE *f;

	f = fopen(path, "r");
	if (!f) {
		warn("%s: %s", path, strerror(errno));
		return;
	}

	while (fgets(line, sizeof(line), f)) {
		struct prefix p;
		bool masked;
		char *s, *e;

		lineno++;
		s = strchr(line, '#');
		if (s)
			*s = '\0';
		for (s = line; isspace((unsigned char)*s); s++)
			;
		for (e = s + strlen(s); e > s && isspace((unsigned char)e[-1]); e--)
			;
		*e = '\0';
		if (!*s)
			continue;

		if (cidr_parse(s, &p, &masked)) {
			if ((*n_bad)++ < 10)
				warn("%s:%u: invalid CIDR '%s', skipped", path, lineno, s);
			continue;
		}
		if (masked) {
			char buf[PREFIX_STRLEN];

			if ((*n_bad)++ < 10)
				warn("%s:%u: '%s' has host bits set, using %s",
				     path, lineno, s, prefix_fmt(&p, buf));
		}

		p.iface = iface;
		p.rule = rule;
		if (prefix_vec_push(out, &p)) {
			err("out of memory");
			break;
		}
	}

	fclose(f);
}

static int load_cidrset(const char *rule_name, const char *pattern, uint16_t iface,
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
		load_list_file(g.gl_pathv[i], iface, rule, out, &n_bad);
	globfree(&g);

	if (n_bad > 10)
		warn("rule '%s': %zu more problems in '%s'", rule_name, n_bad - 10, pattern);
	debug("rule '%s': '%s' -> %zu prefixes", rule_name, pattern, out->n - before);
	return 0;
}

static int validate(struct config *c)
{
	uint32_t mask = c->fwmask, shift, max;

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

	for (size_t i = 0; i < c->n_ifaces; i++) {
		struct cfg_iface *ifc = &c->ifaces[i];

		if (!ifc->fwmark)
			continue;
		if (ifc->fwmark > max) {
			err("config: interface '%s': fwmark 0x%x does not fit in fwmask 0x%x",
			    ifc->name, ifc->fwmark, mask);
			return -1;
		}
		ifc->fwmark <<= shift;

		for (size_t j = 0; j < i; j++) {
			if (c->ifaces[j].fwmark == ifc->fwmark) {
				err("config: interfaces '%s' and '%s' share fwmark",
				    c->ifaces[j].name, ifc->name);
				return -1;
			}
		}
	}

	for (size_t i = 0; i <= c->n_ifaces; i++) {
		uint64_t t = (uint64_t)c->table_id + i;

		if (!c->table_id || t > UINT32_MAX || (t >= 253 && t <= 255)) {
			err("config: table range %u..%llu is invalid or overlaps reserved tables",
			    c->table_id, (unsigned long long)c->table_id + c->n_ifaces);
			return -1;
		}
	}

	if ((uint64_t)c->iface_prio + c->n_ifaces >= c->rule_prio) {
		err("config: iface_prio + interface count must stay below rule_prio");
		return -1;
	}
	if (c->rule_prio >= 32766)
		warn("config: rule_prio %u is after the main table rule (32766)", c->rule_prio);

	return 0;
}

static int find_iface(const struct config *c, const char *name)
{
	for (size_t i = 0; i < c->n_ifaces; i++)
		if (!strcmp(c->ifaces[i].name, name))
			return i;
	return -1;
}

struct config *config_load(const char *path)
{
	struct uci_context *ctx = NULL;
	struct uci_package *pkg = NULL;
	struct uci_element *e;
	struct prefix_vec pv = {};
	const char **rule_names = NULL;
	const char **iface_names = NULL;
	size_t n_rules = 0, n_globals = 0;
	struct config *c;
	FILE *f = NULL;
	bool ok = false;

	c = calloc(1, sizeof(*c));
	if (!c)
		return NULL;
	c->fwmask = DEFAULT_FWMASK;
	c->table_id = DEFAULT_TABLE_ID;
	c->iface_prio = DEFAULT_IFACE_PRIO;
	c->rule_prio = DEFAULT_RULE_PRIO;
	c->gw_table = DEFAULT_GW_TABLE;
	c->rt_proto = DEFAULT_RT_PROTO;

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

	/* pass 1: globals and interfaces, so rules can reference any interface */
	uci_foreach_element(&pkg->sections, e) {
		struct uci_section *s = uci_to_section(e);

		if (!strcmp(s->type, "routebot")) {
			if (n_globals++)
				warn("config: multiple 'routebot' sections, merging");
			if (parse_globals(ctx, s, c))
				goto out;
		} else if (!strcmp(s->type, "interface")) {
			struct cfg_iface *ni;

			if (c->n_ifaces >= UINT16_MAX)
				goto out;
			ni = realloc(c->ifaces, (c->n_ifaces + 1) * sizeof(*ni));
			if (!ni)
				goto out;
			c->ifaces = ni;
			memset(&ni[c->n_ifaces], 0, sizeof(*ni));
			c->n_ifaces++;
			if (parse_iface(ctx, s, &ni[c->n_ifaces - 1]))
				goto out;
			if (find_iface(c, s->e.name) != (int)c->n_ifaces - 1) {
				err("config: duplicate interface '%s'", s->e.name);
				goto out;
			}
		} else if (strcmp(s->type, "rule")) {
			warn("config: unknown section type '%s'", s->type);
		}
	}

	if (validate(c))
		goto out;

	/* pass 2: rules */
	uci_foreach_element(&pkg->sections, e) {
		struct uci_section *s = uci_to_section(e);
		struct uci_option *o;
		struct uci_element *le;
		const char *iface;
		const char **nr;
		int idx;

		if (strcmp(s->type, "rule"))
			continue;

		iface = opt_str(ctx, s, "iface");
		idx = iface ? find_iface(c, iface) : -1;
		if (idx < 0) {
			if (iface)
				err("config: rule '%s': unknown interface '%s'", s->e.name, iface);
			else
				err("config: rule '%s': missing 'option iface'", s->e.name);
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

	iface_names = calloc(c->n_ifaces + 1, sizeof(*iface_names));
	if (!iface_names)
		goto out;
	for (size_t i = 0; i < c->n_ifaces; i++)
		iface_names[i] = c->ifaces[i].name;

	c->n_prefixes = prefixes_normalize(pv.p, pv.n, rule_names, iface_names);
	c->prefixes = pv.p;
	pv.p = NULL;
	if (c->n_prefixes && c->n_prefixes < pv.n / 2) {
		/* lots of dupes, give memory back */
		struct prefix *np = realloc(c->prefixes, c->n_prefixes * sizeof(*np));

		if (np)
			c->prefixes = np;
	}

	info("config: %zu interfaces, %zu rules, %zu prefixes (%zu duplicates dropped)",
	     c->n_ifaces, n_rules, c->n_prefixes, pv.n - c->n_prefixes);
	ok = true;

out:
	free(pv.p);
	free(rule_names);
	free(iface_names);
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
	for (size_t i = 0; i < c->n_ifaces; i++) {
		free(c->ifaces[i].name);
		free(c->ifaces[i].device);
	}
	free(c->ifaces);
	free(c->prefixes);
	free(c);
}
