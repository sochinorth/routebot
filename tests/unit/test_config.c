/*
 * config_load on tricky CIDR lists, against a golden transcript
 * (test_config.golden next to this file): every log line, then every
 * prefix in walk order with its owning group and rule.
 *
 * ROUTEBOT_GOLDEN_UPDATE=1 rewrites the golden file instead of comparing.
 * On a mismatch the transcript is left in ./test_config.out.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "config.h"
#include "log.h"

int log_level = L_DEBUG;

/* In a UBSan build, undefined behaviour fails the test rather than scrolling by. */
const char *__ubsan_default_options(void);
const char *__ubsan_default_options(void)
{
	return "halt_on_error=1:print_stacktrace=1";
}

static char *out;
static size_t out_len, out_cap;
static char base[64];		/* the temp dir */
static char dir[128];		/* the current scenario's dir, "@" in configs and output */

static void die(const char *what)
{
	fprintf(stderr, "test_config: %s: %s\n", what, strerror(errno));
	exit(2);
}

/* Formats prefix i in walk order (v4 first) into buf, sets *rule, returns its group. */
static size_t config_prefix(const struct config *c, size_t i, char *buf, size_t *rule)
{
	bool v6 = i >= c->n_p4;
	const uint8_t *addr = v6 ? c->p6[i - c->n_p4].addr : c->p4[i].addr;

	inet_ntop(v6 ? AF_INET6 : AF_INET, addr, buf, INET6_ADDRSTRLEN);
	sprintf(buf + strlen(buf), "/%u", addr[v6 ? 16 : 4]);
	*rule = v6 ? c->p6[i - c->n_p4].rule : c->p4[i].rule;
	return c->rule_group[*rule];
}

static void append(const char *s, size_t n)
{
	if (out_len + n + 1 > out_cap) {
		out_cap = (out_len + n + 1) * 2;
		out = realloc(out, out_cap);
		if (!out)
			die("realloc");
	}
	memcpy(out + out_len, s, n);
	out_len += n;
	out[out_len] = '\0';
}

/* Append s with the scenario dir replaced by "@". */
static void append_clean(const char *s)
{
	size_t dl = strlen(dir);
	const char *m;

	while (dl && (m = strstr(s, dir))) {
		append(s, m - s);
		append("@", 1);
		s = m + dl;
	}
	append(s, strlen(s));
}

static void outf(const char *fmt, ...)
{
	char buf[4096];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	append_clean(buf);
}

void log_msg(int level, const char *fmt, ...)
{
	static const char *const tag[] = { "E", "W", "I", "D" };
	char buf[4096];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	outf("%s %s\n", tag[level], buf);
}

/* --- scenario files --- */

static void put(const char *name, const char *data, size_t len)
{
	char path[512];
	FILE *f;

	snprintf(path, sizeof(path), "%s/%s", dir, name);
	for (char *s = path + strlen(dir) + 1; (s = strchr(s, '/')); s++) {
		*s = '\0';
		if (mkdir(path, 0700) && errno != EEXIST)
			die(path);
		*s = '/';
	}
	f = fopen(path, "wb");
	if (!f || fwrite(data, 1, len, f) != len || fclose(f))
		die(path);
}

#define PUT(name, lit)	put(name, lit, sizeof(lit) - 1)

static void puts_(const char *name, const char *s)
{
	put(name, s, strlen(s));
}

static void mkdir_(const char *name)
{
	char path[512];

	snprintf(path, sizeof(path), "%s/%s", dir, name);
	if (mkdir(path, 0700))
		die(path);
}

static unsigned n_scenario;

static void begin(const char *title)
{
	snprintf(dir, sizeof(dir), "%s/s%02u", base, n_scenario++);
	if (mkdir(dir, 0700))
		die(dir);
	outf("\n== %s\n", title);
}

/* Grows a heap string; for generated lists and configs. */
struct sb {
	char *s;
	size_t n, cap;
};

static void sbf(struct sb *b, const char *fmt, ...)
{
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);
	if (b->n + n + 1 > b->cap) {
		b->cap = (b->n + n + 1) * 2;
		b->s = realloc(b->s, b->cap);
		if (!b->s)
			die("realloc");
	}
	va_start(ap, fmt);
	vsnprintf(b->s + b->n, n + 1, fmt, ap);
	va_end(ap);
	b->n += n;
}

static uint64_t fnv(uint64_t h, const char *s)
{
	for (; *s; s++)
		h = (h ^ (unsigned char)*s) * 0x100000001b3ULL;
	return h;
}

/* Writes cfg (with "@" -> scenario dir) and loads it; dumps the result. */
static void load(const char *cfg)
{
	struct sb b = {};
	struct config *c;
	char path[512];
	size_t n;

	for (const char *s = cfg; *s; s++) {
		if (*s == '@')
			sbf(&b, "%s", dir);
		else
			sbf(&b, "%c", *s);
	}
	put("routebot.conf", b.s, b.n);
	free(b.s);

	snprintf(path, sizeof(path), "%s/routebot.conf", dir);
	c = config_load(path, NULL);
	if (!c) {
		outf("-> load failed\n");
		return;
	}
	n = c->n_p4 + c->n_p6;
	outf("-> %zu prefixes\n", n);
	if (n <= 400) {
		for (size_t i = 0; i < n; i++) {
			char buf[INET6_ADDRSTRLEN + 4];
			size_t rule, g = config_prefix(c, i, buf, &rule);

			outf("  %s %s r%zu\n", buf, c->groups[g].name, rule);
		}
	} else {
		/* too many to list: a hash of the listing, and its ends */
		uint64_t h = 0xcbf29ce484222325ULL;

		for (size_t i = 0; i < n; i++) {
			char buf[INET6_ADDRSTRLEN + 4], line[128];
			size_t rule, g = config_prefix(c, i, buf, &rule);

			snprintf(line, sizeof(line), "  %s %s r%zu\n", buf, c->groups[g].name, rule);
			h = fnv(h, line);
			if (i < 3 || i + 3 >= n)
				outf("%s", line);
			else if (i == 3)
				outf("  ...\n");
		}
		outf("  listing hash %016llx\n", (unsigned long long)h);
	}
	config_free(c);
}

#define GROUPS \
	"config group 'gA'\n\tlist device 'eth0'\n" \
	"config group 'gB'\n\tlist device 'eth1'\n" \
	"config group 'gC'\n\tlist device 'eth2'\n"

/* --- scenarios --- */

static void s_mixed(void)
{
	begin("v4 and v6 mixed, unsorted, comments, whitespace, CRLF, no final newline");
	PUT("a.lst",
	    "# header comment\n"
	    "10.0.0.0/8\n"
	    "  192.168.1.0/24   # trailing comment\n"
	    "2001:db8::/32\n"
	    "\t1.1.1.1\t\n"
	    "1.0.0.0/24\r\n"
	    "2606:4700::/32\r\n"
	    "\n"
	    "   \n"
	    "\v\f 9.9.9.0/24 \v\f\n"
	    "::/0\n"
	    "0.0.0.0/0\n"
	    "1.0.0.0/24\n"
	    "1.0.0.0/16\n"
	    "1.0.0.0/25\n"
	    "10.1.2.3/8\n"
	    "2001:db8::1/32\n"
	    "2001:db8::1\n"
	    "::1\n"
	    "fe80::/10#no space before the comment\n"
	    "::ffff:1.2.3.4/128\n"
	    "1.2.3.4/32\n"
	    "1.2.3.4\n"
	    "8.8.8.0/24");
	load(GROUPS "config rule 'r'\n\toption group 'gA'\n\tlist cidrset '@/a.lst'\n");
}

/* One file per string, one cidrset per file: every verdict gets its own line. */
static void s_edge(void)
{
	static const char *const edge[] = {
		"1.2.3.4", "0.0.0.0", "255.255.255.255", "256.1.1.1", "1.256.1.1",
		"1.2.3.256", "1234.1.1.1", "1.2.3.04", "01.2.3.4", "00.0.0.0", "0.0.0.00",
		"0.0.0.0/0", "1.2.3", "1.2.3.4.5", "1..2.3", "1.2.3.", ".1.2.3", "+1.2.3.4",
		"-1.2.3.4", "1.2.3.-4", "1.2.3.+4", "0x1.2.3.4", "1.2.3.0x4", "1.2.3.4a",
		"a1.2.3.4", "1.2.3.4/33", "1.2.3.4/32", "1.2.3.4/0", "1.2.3.4/", "/24", "/",
		"1.2.3.4/24x", "1.2.3.4/x24", "1.2.3.4/ 24", "1.2.3.4/+24", "1.2.3.4/-1",
		"1.2.3.4/024", "1.2.3.4/0024", "1.2.3.4/4294967320",
		"1.2.3.4/18446744073709551640", "1.2.3.4/24/24", "1.2.3.4//24",
		"1.2.3.4/0000000000000000000000000000000000000000024",
		"1.2.3.4/000000000000000000000000000000000000000024",
		"1.2.3.4%eth0", "1.2.3.4 junk", "1.2.3.4\tjunk", "1 .2.3.4", "1.2.3.4 /24",
		"::/129", "::/128", "::/0", "::", ":", ":::", "1::2::3", "::1/64",
		"::ffff:1.2.3.4", "::ffff:1.2.3.04", "::ffff:1.2.3.256", "::1.2.3.4/96",
		"fe80::1%eth0", "2001:db8::/32", "2001:DB8::/32", "2001:db8:0:0:0:0:0:0/32",
		"2001:db8:0:0:0:0:0:0:0/32", "12345::/16", "g::/16", "2001:db8::/032",
		"2001:db8::/", "0000:0000:0000:0000:0000:ffff:255.255.255.255/128",
		"0000:0000:0000:0000:0000:ffff:255.255.255.255/0128",
		"1.2.3.4\\", "\"1.2.3.4\"", "1,2,3,4", "1.2.3.4;", "1.2.3.4/24 ",
		"001.002.003.004", "1.2.3.4/2.4", "1.2.3.4/24\r", "1.2.3.4\r/24",
	};
	struct sb cfg = {};

	begin("one string per file: parse verdicts");
	sbf(&cfg, "%s", GROUPS "config rule 'r'\n\toption group 'gA'\n");
	for (size_t i = 0; i < sizeof(edge) / sizeof(*edge); i++) {
		char name[32];

		snprintf(name, sizeof(name), "e%03zu.lst", i);
		puts_(name, edge[i]);
		sbf(&cfg, "\tlist cidrset '@/%s'\n", name);
	}
	load(cfg.s);
	free(cfg.s);
}

/* Random v4-ish strings, same seed every run: octets from a table of
 * boundary cases, now and then too few or too many, or pure noise. */
static uint64_t rnd_x = 0x9e3779b97f4a7c15ULL;

static unsigned rnd(unsigned n)
{
	rnd_x ^= rnd_x << 13, rnd_x ^= rnd_x >> 7, rnd_x ^= rnd_x << 17;
	return rnd_x % n;
}

static void s_fuzz(void)
{
	static const char *const oct[] = {
		"0", "1", "9", "10", "99", "100", "199", "200", "249", "250", "255",
		"256", "299", "300", "999", "1000", "00", "01", "007", "", "x", " ",
	};
	static const char *const pl[] = {
		"", "/0", "/1", "/8", "/24", "/31", "/32", "/33", "/024", "/", "/x",
		"/3 2", "/-0", "/+8", "//8",
	};
	static const char noise[] = "0123456789012345678901234567890123456789....../:x";
	struct sb cfg = {};

	begin("random v4-ish strings, one per file");
	sbf(&cfg, "%s", GROUPS "config rule 'r'\n\toption group 'gA'\n");
	for (unsigned i = 0; i < 500; i++) {
		struct sb s = {};
		char name[32];

		if (i % 5 == 4) {
			unsigned len = 5 + rnd(14);

			for (unsigned k = 0; k < len; k++)
				sbf(&s, "%c", noise[rnd(sizeof(noise) - 1)]);
		} else {
			unsigned n = rnd(8) ? 4 : 3 + 2 * rnd(2);

			for (unsigned k = 0; k < n; k++) {
				unsigned o = rnd(4) ? rnd(11) : rnd(sizeof(oct) / sizeof(*oct));

				sbf(&s, "%s%s", k ? "." : "", oct[o]);
			}
			sbf(&s, "%s", pl[rnd(3) ? rnd(7) : rnd(sizeof(pl) / sizeof(*pl))]);
		}
		snprintf(name, sizeof(name), "f%03u.lst", i);
		puts_(name, s.s);
		free(s.s);
		sbf(&cfg, "\tlist cidrset '@/%s'\n", name);
	}
	load(cfg.s);
	free(cfg.s);
}

static void s_problems(void)
{
	begin("more than 10 problems in one cidrset, shared by a glob");
	PUT("p/1.lst",
	    "bad1\nbad2\n1.2.3.4/8\nbad3\n1.1.1.1\nbad4\nbad5\nbad6\n");
	PUT("p/2.lst",
	    "bad7\n2.2.2.2/8\nbad8\nbad9\nbad10\nbad11\n3.3.3.3/8\nbad12\n4.4.4.0/24\n");
	PUT("q.lst", "bad13\n5.5.5.5/24\n");
	load(GROUPS "config rule 'r'\n\toption group 'gA'\n"
	     "\tlist cidrset '@/p/*.lst'\n\tlist cidrset '@/q.lst'\n");
}

static void s_conflicts(void)
{
	begin("first rule wins, whatever the file and glob order");
	/* r0 (gB) loads z/1 then z/2; r1 (gA) loads a/1; r2 (gB) m; r3 (gC) z/2 again */
	PUT("z/1.lst", "10.0.0.0/8\n20.0.0.0/8\n2001:db8::/32\n30.0.0.0/8\n");
	PUT("z/2.lst", "40.0.0.0/8\n10.0.0.0/8\n50.0.0.0/8\n");
	PUT("a/1.lst", "50.0.0.0/8\n2001:db8::/32\n10.0.0.0/8\n60.0.0.0/8\n1.0.0.0/8\n");
	PUT("m.lst", "60.0.0.0/8\n1.0.0.0/8\n70.0.0.0/8\n10.0.0.0/8\n");
	load(GROUPS
	     "config rule 'r0'\n\toption group 'gB'\n\tlist cidrset '@/z/*'\n"
	     "config rule 'r1'\n\toption group 'gA'\n\tlist cidrset '@/a/*'\n"
	     "config rule 'r2'\n\toption group 'gB'\n\tlist cidrset '@/m.lst'\n"
	     "config rule 'r3'\n\toption group 'gC'\n\tlist cidrset '@/z/2.lst'\n");

	begin("same lists, rules swapped");
	PUT("z/1.lst", "10.0.0.0/8\n20.0.0.0/8\n2001:db8::/32\n30.0.0.0/8\n");
	PUT("z/2.lst", "40.0.0.0/8\n10.0.0.0/8\n50.0.0.0/8\n");
	PUT("a/1.lst", "50.0.0.0/8\n2001:db8::/32\n10.0.0.0/8\n60.0.0.0/8\n1.0.0.0/8\n");
	PUT("m.lst", "60.0.0.0/8\n1.0.0.0/8\n70.0.0.0/8\n10.0.0.0/8\n");
	load(GROUPS
	     "config rule 'r3'\n\toption group 'gC'\n\tlist cidrset '@/z/2.lst'\n"
	     "config rule 'r2'\n\toption group 'gB'\n\tlist cidrset '@/m.lst'\n"
	     "config rule 'r1'\n\toption group 'gA'\n\tlist cidrset '@/a/*'\n"
	     "config rule 'r0'\n\toption group 'gB'\n\tlist cidrset '@/z/*'\n");

	begin("one rule, files in several cidrsets and globs, duplicates everywhere");
	PUT("d/b.lst", "3.0.0.0/8\n1.0.0.0/8\n2.0.0.0/8\n1.0.0.0/8\n");
	PUT("d/a.lst", "2.0.0.0/8\n4.0.0.0/8\n");
	PUT("c.lst", "4.0.0.0/8\n0.0.0.0/8\n1.0.0.0/8\n");
	load(GROUPS "config rule 'r'\n\toption group 'gC'\n"
	     "\tlist cidrset '@/c.lst'\n\tlist cidrset '@/d/*'\n\tlist cidrset '@/c.lst'\n");
}

static void s_many_conflicts(void)
{
	struct sb a = {}, b = {}, c = {};

	begin("more than 10 conflicts");
	for (unsigned i = 0; i < 12; i++) {
		sbf(&a, "10.%u.0.0/16\n2001:db8:%x::/48\n", i, i);
		sbf(&b, "2001:db8:%x::/48\n10.%u.0.0/16\n", 11 - i, 11 - i);
		sbf(&c, "10.%u.0.0/16\n", i * 2);
	}
	puts_("a.lst", a.s);
	puts_("b.lst", b.s);
	puts_("c.lst", c.s);
	free(a.s);
	free(b.s);
	free(c.s);
	load(GROUPS
	     "config rule 'ra'\n\toption group 'gA'\n\tlist cidrset '@/a.lst'\n"
	     "config rule 'rb'\n\toption group 'gB'\n\tlist cidrset '@/b.lst'\n"
	     "config rule 'rc'\n\toption group 'gC'\n\tlist cidrset '@/c.lst'\n");
}

static void s_long_lines(void)
{
	struct sb s = {};

	begin("lines longer than 511 bytes");
	sbf(&s, "1.2.3.0/24 #");
	for (int i = 0; i < 588; i++)
		sbf(&s, "x");
	sbf(&s, "\n5.5.5.0/24");
	for (int i = 0; i < 501; i++)	/* 511 bytes, then the newline alone */
		sbf(&s, " ");
	sbf(&s, "\n6.6.6.0/24\nbad-after-511\n");
	for (int i = 0; i < 700; i++)
		sbf(&s, "y");
	sbf(&s, "7.7.7.0/24\n");
	for (int i = 0; i < 511; i++)	/* a CIDR right past the split */
		sbf(&s, " ");
	sbf(&s, "9.9.9.0/24\n");
	for (int i = 0; i < 500; i++)	/* 510 bytes and the newline: one line */
		sbf(&s, " ");
	sbf(&s, "8.8.8.0/24\nbad-after-510\n");
	for (int i = 0; i < 1100; i++)	/* no final newline */
		sbf(&s, i % 50 ? " " : "#");
	sbf(&s, "4.4.4.0/24");
	puts_("long.lst", s.s);
	free(s.s);
	load(GROUPS "config rule 'r'\n\toption group 'gA'\n\tlist cidrset '@/long.lst'\n");
}

static void s_nul(void)
{
	begin("NUL bytes");
	PUT("n.lst", "1.2.3.4\0junk\n2.0.0.0/8\0#\n\0003.0.0.0/8\nbad\0bad\n");
	load(GROUPS "config rule 'r'\n\toption group 'gA'\n\tlist cidrset '@/n.lst'\n");
}

static void s_files(void)
{
	struct sb cfg = {};

	begin("empty files, comment-only files, a directory, no match, no cidrset");
	PUT("e/0-empty.lst", "");
	PUT("e/1-comments.lst", "# nothing\n\n   # here\n");
	PUT("e/2-one.lst", "6.0.0.0/8");
	PUT("e/3-nl.lst", "\n");
	mkdir_("e/4-dir");
	PUT("e/5-last.lst", "5.0.0.0/8\n");
	load(GROUPS
	     "config rule 'r0'\n\toption group 'gA'\n\tlist cidrset '@/e/*'\n"
	     "\tlist cidrset '@/nothing/*.lst'\n"
	     "config rule 'r1'\n\toption group 'gB'\n"
	     "config rule 'r2'\n\toption group 'gC'\n\tlist cidrset '@/e/2-one.lst'\n");

	begin("no rules");
	load(GROUPS);

	begin("many files, each sorted, interleaved");
	for (unsigned f = 0; f < 40; f++) {
		struct sb s = {};
		char name[32];

		for (unsigned i = 0; i < 6; i++)
			sbf(&s, "10.%u.%u.0/24\n2001:db8:%x:%x::/64\n", i, f, i, f);
		snprintf(name, sizeof(name), "many/%02u.lst", (f * 7) % 40);
		puts_(name, s.s);
		free(s.s);
	}
	sbf(&cfg, "%s", GROUPS
	    "config rule 'r0'\n\toption group 'gA'\n\tlist cidrset '@/many/0*'\n"
	    "config rule 'r1'\n\toption group 'gB'\n\tlist cidrset '@/many/*'\n");
	load(cfg.s);
	free(cfg.s);
}

static void s_big(void)
{
	struct sb s = {}, t = {};

	begin("big files across the read window, unsorted, sorted, mixed");
	/* unsorted v4 with host bits, and the odd duplicate */
	for (unsigned i = 0; i < 20000; i++) {
		unsigned k = (i * 7919) % 20000;

		sbf(&s, "%u.%u.%u.%u/%u\n", 11 + k / 4000, (k / 16) % 250, k % 16,
		    k % 3 ? 0 : 7, 24 + k % 3);
		if (i % 997 == 0)
			sbf(&s, "11.0.0.0/24 # dup\n");
	}
	puts_("big/u.lst", s.s);
	/* sorted v4 and v6 interleaved, sharing ~20 prefixes with u.lst */
	for (unsigned i = 0; i < 20000; i++) {
		if (i % 999 == 0)
			sbf(&t, "%u.%u.%u.0/24\n", 11 + i / 4000, (i / 16) % 250, i % 16);
		sbf(&t, "%u.%u.%u.0/24\n2a00:%x:%x::/48%s", 100 + i / 4000, (i / 16) % 250,
		    i % 16, i / 256, i % 256, i % 5 ? "\n" : "\r\n");
	}
	puts_("big/v.lst", t.s);
	free(s.s);
	free(t.s);
	load(GROUPS
	     "config rule 'u'\n\toption group 'gA'\n\tlist cidrset '@/big/u.lst'\n"
	     "config rule 'v'\n\toption group 'gB'\n\tlist cidrset '@/big/v.lst'\n");
}

static void s_nearly_sorted(void)
{
	struct sb s = {}, t = {};

	begin("nearly sorted dumps: entries out of place, alone and in clumps");
	for (unsigned i = 0; i < 30000; i++) {
		sbf(&s, "%u.%u.%u.0/24\n", 20 + i / 10000, (i / 40) % 250, i % 40);
		if (rnd(33) == 0)	/* a copy of some entry, anywhere */
			sbf(&s, "%u.%u.%u.0/24\n", 20 + rnd(3), rnd(250), rnd(40));
		if (rnd(1000) == 0)	/* clumps of big ones, of small ones */
			sbf(&s, "250.0.0.0/8\n251.0.0.0/8\n252.0.0.0/8\n");
		if (rnd(1000) == 0)
			sbf(&s, "1.0.0.0/8\n2.0.0.0/8\n3.0.0.0/8\n4.0.0.0/8\n5.0.0.0/8\n6.0.0.0/8\n");
		if (i % 3 == 0)
			sbf(&s, "2a01:%x:%x::/48\n", i / 300, i % 300 + (rnd(50) ? 0 : 7));
	}
	puts_("n/a.lst", s.s);
	/* short ones: below any useful set-aside budget */
	sbf(&t, "9.0.0.0/8\n8.0.0.0/8\n7.0.0.0/8\n9.0.0.0/8\n::/0\n");
	puts_("n/b.lst", t.s);
	free(s.s);
	free(t.s);
	load(GROUPS
	     "config rule 'b'\n\toption group 'gB'\n\tlist cidrset '@/n/b.lst'\n"
	     "config rule 'a'\n\toption group 'gA'\n\tlist cidrset '@/n/*'\n");
}

int main(void)
{
	char golden[1024], *want = NULL;
	const char *dot;
	size_t want_len = 0;
	FILE *f;
	int rc;

	strcpy(base, "/tmp/routebot-test-XXXXXX");
	if (!mkdtemp(base))
		die("mkdtemp");

	s_mixed();
	s_edge();
	s_fuzz();
	s_problems();
	s_conflicts();
	s_many_conflicts();
	s_long_lines();
	s_nul();
	s_files();
	s_big();
	s_nearly_sorted();

	snprintf(golden, sizeof(golden), "rm -rf '%s'", base);
	if (system(golden))
		fprintf(stderr, "test_config: couldn't remove %s\n", base);

	dot = strrchr(__FILE__, '.');
	snprintf(golden, sizeof(golden), "%.*s.golden", (int)(dot - __FILE__), __FILE__);

	if (getenv("ROUTEBOT_GOLDEN_UPDATE")) {
		f = fopen(golden, "w");
		if (!f || fwrite(out, 1, out_len, f) != out_len || fclose(f))
			die(golden);
		printf("wrote %s\n", golden);
		return 0;
	}

	f = fopen(golden, "r");
	if (!f)
		die(golden);
	for (;;) {
		want = realloc(want, want_len + 65536);
		if (!want)
			die("realloc");
		size_t n = fread(want + want_len, 1, 65536, f);

		want_len += n;
		if (n < 65536)
			break;
	}
	fclose(f);

	rc = want_len != out_len || memcmp(want, out, out_len);
	if (rc) {
		size_t i = 0, line = 1;

		for (; i < want_len && i < out_len && want[i] == out[i]; i++)
			line += want[i] == '\n';
		f = fopen("test_config.out", "w");
		if (f) {
			fwrite(out, 1, out_len, f);
			fclose(f);
		}
		fprintf(stderr, "test_config: output differs from %s at line %zu; "
		        "got ./test_config.out\n", golden, line);
	} else {
		printf("test_config: %zu bytes match %s\n", out_len, golden);
	}
	free(want);
	free(out);
	return rc;
}
