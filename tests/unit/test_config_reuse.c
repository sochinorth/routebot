/*
 * config_load with the previous config: its prefix arrays are shared when
 * every list file stats the same and goes to the same rule, read again
 * otherwise. Either way the result must match a fresh load.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "config.h"
#include "log.h"

int log_level = L_DEBUG;

const char *__ubsan_default_options(void);
const char *__ubsan_default_options(void)
{
	return "halt_on_error=1:print_stacktrace=1";
}

static char base[] = "/tmp/routebot-test-XXXXXX";
static char conf[256];
static bool said_reused;
static int bad;

void log_msg(int level, const char *fmt, ...)
{
	char buf[1024];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if (strstr(buf, "lists unchanged"))
		said_reused = true;
}

static void die(const char *what)
{
	fprintf(stderr, "test_config_reuse: %s: %s\n", what, strerror(errno));
	exit(2);
}

static const char *at(const char *name)
{
	static char path[4][256];
	static int i;

	i = (i + 1) % 4;
	snprintf(path[i], sizeof(path[i]), "%s/%s", base, name);
	return path[i];
}

static void put(const char *name, const char *s)
{
	FILE *f = fopen(at(name), "w");

	if (!f || fputs(s, f) < 0 || fclose(f))
		die(name);
}

/* Groups gA and gB, then rules: "group:cidrset[,cidrset]" each, '@' is base. */
static void write_config(const char *gA_dev, int n, const char *const *rules)
{
	FILE *f = fopen(conf, "w");

	if (!f)
		die(conf);
	fprintf(f, "config group 'gA'\n\tlist device '%s'\n"
	        "config group 'gB'\n\tlist device 'eth1'\n", gA_dev);
	for (int i = 0; i < n; i++) {
		const char *s = rules[i], *colon = strchr(s, ':');

		fprintf(f, "config rule 'r%d'\n\toption group '%.*s'\n", i, (int)(colon - s), s);
		for (s = colon + 1; *s;) {
			size_t len = strcspn(s, ",");

			fprintf(f, "\tlist cidrset '%s/%.*s'\n", base, (int)len, s);
			s += len + !!s[len];
		}
	}
	if (fclose(f))
		die(conf);
}

/* Loads with prev, checks sharing and that the result is a fresh load's. */
static struct config *reload(struct config *prev, bool want_shared, const char *what)
{
	struct config *c, *fresh;
	bool shared;

	said_reused = false;
	c = config_load(conf, prev);
	fresh = config_load(conf, NULL);
	if (!c || !fresh)
		die(what);
	shared = prev && c->lists == prev->lists;
	if (shared != want_shared || said_reused != want_shared ||
	    (prev && shared != (c->p4 == prev->p4 && c->p6 == prev->p6))) {
		fprintf(stderr, "FAIL %s: lists %s, want %s\n", what,
		        shared ? "shared" : "read", want_shared ? "shared" : "read");
		bad++;
	}
	if (c->n_p4 != fresh->n_p4 || c->n_p6 != fresh->n_p6 || c->n_rules != fresh->n_rules ||
	    (c->n_p4 && memcmp(c->p4, fresh->p4, c->n_p4 * sizeof(*c->p4))) ||
	    (c->n_p6 && memcmp(c->p6, fresh->p6, c->n_p6 * sizeof(*c->p6))) ||
	    memcmp(c->rule_group, fresh->rule_group, c->n_rules * sizeof(*c->rule_group))) {
		fprintf(stderr, "FAIL %s: differs from a fresh load\n", what);
		bad++;
	}
	config_free(fresh);
	return c;
}

/* Rewrites name with s, then makes its mtime another second. */
static void rewrite(const char *name, const char *s)
{
	struct stat st;
	struct timespec ts[2];

	if (stat(at(name), &st))
		die(name);
	put(name, s);
	ts[0] = ts[1] = st.st_mtim;
	ts[1].tv_sec++;
	if (utimensat(AT_FDCWD, at(name), ts, 0))
		die(name);
}

int main(void)
{
	static const char *const two[] = { "gA:a/*.lst", "gB:b.lst" };
	static const char *const swapped[] = { "gB:a/*.lst", "gA:b.lst" };
	static const char *const reordered[] = { "gB:b.lst", "gA:a/*.lst" };
	static const char *const moved1[] = { "gA:a/*.lst,b.lst", "gB:c.lst" };
	static const char *const moved2[] = { "gA:a/*.lst", "gB:b.lst,c.lst" };
	static const char *const dangling[] = { "gA:a/*.lst", "gB:d/*.lst" };
	struct config *c, *n, *keep;
	char cmd[300];

	if (!mkdtemp(base))
		die("mkdtemp");
	snprintf(conf, sizeof(conf), "%s/config", base);
	if (mkdir(at("a"), 0700) || mkdir(at("d"), 0700))
		die("mkdir");
	put("a/1.lst", "1.0.0.0/24\n2001:db8:1::/48\n");
	put("a/2.lst", "2.0.0.0/24\n1.0.0.0/24\n");
	put("b.lst", "3.0.0.0/24\n2.0.0.0/24\n2001:db8:3::/48\n");
	put("c.lst", "4.0.0.0/24\n");

	write_config("eth0", 2, two);
	c = reload(NULL, false, "first load");
	n = reload(c, true, "unchanged");
	/* the old one may go first, or stay on as the applied one */
	keep = c;
	c = n;
	n = reload(c, true, "unchanged, again");
	config_free(keep);
	config_free(c);
	c = n;

	write_config("eth2", 2, two);
	n = reload(c, true, "group members changed");
	config_free(c);
	c = n;
	write_config("eth2", 2, swapped);
	n = reload(c, true, "rules map to other groups");
	config_free(c);
	c = n;

	write_config("eth0", 2, two);
	n = reload(c, true, "back");
	config_free(c);
	c = n;
	rewrite("b.lst", "3.0.0.0/24\n2.0.0.0/24\n2001:db8:4::/48\n");
	n = reload(c, false, "file rewritten, same size");
	config_free(c);
	c = n;
	put("b.lst", "3.0.0.0/24\n");
	n = reload(c, false, "file size changed");
	config_free(c);
	c = n;
	put("a/3.lst", "5.0.0.0/24\n");
	n = reload(c, false, "new glob match");
	config_free(c);
	c = n;
	if (unlink(at("a/1.lst")))
		die("unlink");
	n = reload(c, false, "file removed");
	config_free(c);
	c = n;

	write_config("eth0", 2, reordered);
	n = reload(c, false, "rules reordered");
	config_free(c);
	c = n;
	write_config("eth0", 2, moved1);
	n = reload(c, false, "file moved to another rule");
	config_free(c);
	c = n;
	write_config("eth0", 2, moved2);
	n = reload(c, false, "file moved back");
	config_free(c);
	c = n;
	write_config("eth0", 1, moved2);
	n = reload(c, false, "rule removed");
	config_free(c);
	c = n;

	/* a stat failure: read every time */
	if (symlink(at("nowhere"), at("d/x.lst")))
		die("symlink");
	write_config("eth0", 2, dangling);
	n = reload(c, false, "dangling symlink");
	config_free(c);
	c = n;
	n = reload(c, false, "dangling symlink, again");
	config_free(c);
	config_free(n);

	snprintf(cmd, sizeof(cmd), "rm -rf '%s'", base);
	if (system(cmd))
		fprintf(stderr, "test_config_reuse: couldn't remove %s\n", base);
	printf("test_config_reuse: %d failures\n", bad);
	return bad != 0;
}
