/*
 * config_load when realloc or read() fails, the load repeated with the nth
 * call failing, for every n until one goes through untouched. Every realloc
 * in src/ is wrapped (-Wl,--wrap=realloc, see CMakeLists.txt); read() is
 * defined here, which takes the place of libc's for the list reader in
 * config.c. A partial list would make routebot delete the missing part's
 * routes: out of memory, each load must fail or come out whole; with EIO
 * each must fail; with EINTR each must come out whole (the read is retried).
 */
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

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
static int fail_errno;		/* 0: fail a realloc; else a read, with this */
static long n_calls;
static bool failed;

void *__wrap_realloc(void *p, size_t size)
{
	if (!fail_errno && n_calls++ == fail_at) {
		failed = true;
		return NULL;
	}
	return __real_realloc(p, size);
}

ssize_t read(int fd, void *buf, size_t len)
{
	if (fail_errno && n_calls++ == fail_at) {
		failed = true;
		errno = fail_errno;
		return -1;
	}
	return syscall(SYS_read, fd, buf, len);
}

void log_msg(int level, const char *fmt, ...)
{
}

static void die(const char *what)
{
	fprintf(stderr, "test_config_fail: %s: %s\n", what, strerror(errno));
	exit(2);
}

/* Fails the nth realloc (e 0) or read (with e) for every n; returns the number of bad loads. */
static int run(const char *path, int e, size_t want4, size_t want6)
{
	const char *what = e ? "read" : "realloc", *why = e ? strerror(e) : "ENOMEM";
	struct config *c;
	int bad = 0;
	long n;

	fail_errno = e;
	for (n = 0;; n++) {
		bool whole;

		fail_at = n;
		n_calls = 0;
		failed = false;
		c = config_load(path, NULL);
		if (!failed) {
			config_free(c);
			break;
		}
		whole = c && c->n_p4 == want4 && c->n_p6 == want6;
		if (e == EINTR ? !whole : e ? c != NULL : c && !whole) {
			fprintf(stderr, "test_config_fail: %s %ld failed with %s, loaded %zu+%zu "
			        "prefixes, want %s\n", what, n, why, c ? c->n_p4 : 0,
			        c ? c->n_p6 : 0, e == EINTR ? "all" : e ? "a failed load" :
			        "all or a failed load");
			bad++;
		}
		config_free(c);
	}
	fail_at = -1;
	printf("test_config_fail: %ld %ss failed with %s in turn, %d bad loads\n",
	       n, what, why, bad);
	if (n < 3) {
		fprintf(stderr, "test_config_fail: only %ld %ss, the lists are too small\n", n, what);
		bad++;
	}
	return bad;
}

int main(void)
{
	char base[] = "/tmp/routebot-test-XXXXXX", path[256], lst[256], cmd[300];
	size_t want4, want6;
	struct config *c;
	int bad = 0;
	FILE *f;

	if (!mkdtemp(base))
		die("mkdtemp");

	/*
	 * a few read windows' worth (64 KiB each), so a read fails mid-file,
	 * and enough prefixes for the build arrays to grow a few times
	 */
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
		fprintf(stderr, "test_config_fail: config doesn't load\n");
		return 1;
	}
	want4 = c->n_p4;
	want6 = c->n_p6;
	config_free(c);

	bad += run(path, 0, want4, want6);
	bad += run(path, EIO, want4, want6);
	bad += run(path, EINTR, want4, want6);

	snprintf(cmd, sizeof(cmd), "rm -rf '%s'", base);
	if (system(cmd))
		fprintf(stderr, "test_config_fail: couldn't remove %s\n", base);
	return bad != 0;
}
