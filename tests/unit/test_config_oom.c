/*
 * config_load when realloc fails: every realloc in src/ is wrapped
 * (-Wl,--wrap=realloc, see CMakeLists.txt), and the load is repeated with
 * the nth call failing, for every n until one goes through untouched. Each
 * load must either fail or come out whole: a partial list would make
 * routebot delete the missing part's routes.
 */
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "log.h"

int log_level = L_DEBUG;

const char *__ubsan_default_options(void);
const char *__ubsan_default_options(void)
{
	return "halt_on_error=1:print_stacktrace=1";
}

void *__real_realloc(void *p, size_t size);
void *__wrap_realloc(void *p, size_t size);

static long fail_at = -1;	/* the call to fail, counting from 0; -1 = none */
static long n_calls;
static bool failed;

void *__wrap_realloc(void *p, size_t size)
{
	if (n_calls++ == fail_at) {
		failed = true;
		return NULL;
	}
	return __real_realloc(p, size);
}

void log_msg(int level, const char *fmt, ...)
{
}

static void die(const char *what)
{
	fprintf(stderr, "test_config_oom: %s: %s\n", what, strerror(errno));
	exit(2);
}

int main(void)
{
	char base[] = "/tmp/routebot-test-XXXXXX", path[256], lst[256], cmd[300];
	size_t want4, want6;
	struct config *c;
	int bad = 0;
	long n;
	FILE *f;

	if (!mkdtemp(base))
		die("mkdtemp");

	/* enough prefixes for the build arrays to grow a few times */
	snprintf(lst, sizeof(lst), "%s/a.lst", base);
	f = fopen(lst, "w");
	if (!f)
		die(lst);
	for (unsigned i = 0; i < 5000; i++)
		fprintf(f, "10.%u.%u.0/24\n2001:db8:%x::/48\n", i >> 8, i & 255, i);
	if (fclose(f))
		die(lst);

	snprintf(path, sizeof(path), "%s/config", base);
	f = fopen(path, "w");
	if (!f)
		die(path);
	fprintf(f, "config group 'a'\n\tlist device 'a0'\n\tlist device 'a1'\n\n"
	        "config rule 'ra'\n\toption group 'a'\n\tlist cidrset '%s'\n", lst);
	if (fclose(f))
		die(path);

	c = config_load(path, NULL);
	if (!c) {
		fprintf(stderr, "test_config_oom: config doesn't load\n");
		return 1;
	}
	want4 = c->n_p4;
	want6 = c->n_p6;
	config_free(c);

	for (n = 0;; n++) {
		fail_at = n;
		n_calls = 0;
		failed = false;
		c = config_load(path, NULL);
		if (!failed) {
			config_free(c);
			break;
		}
		if (c && (c->n_p4 != want4 || c->n_p6 != want6)) {
			fprintf(stderr, "test_config_oom: realloc %ld failed, loaded %zu+%zu "
			        "prefixes instead of %zu+%zu\n", n, c->n_p4, c->n_p6, want4, want6);
			bad++;
		}
		config_free(c);
	}

	snprintf(cmd, sizeof(cmd), "rm -rf '%s'", base);
	if (system(cmd))
		fprintf(stderr, "test_config_oom: couldn't remove %s\n", base);
	printf("test_config_oom: %ld reallocs failed in turn, %d partial loads\n", n, bad);
	return bad != 0;
}
