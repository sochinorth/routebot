/*
 * LD_PRELOAD shim counting heap allocations, for tests/bench/bench.sh.
 *
 *   cc -O2 -fPIC -shared -o mallocstat.so mallocstat.c
 *   MALLOCSTAT_FILE=/tmp/ms LD_PRELOAD=./mallocstat.so prog
 *
 * Counters live in a shared mapping of MALLOCSTAT_FILE (struct ms_counters
 * below, read by rbstat.py), so they can be sampled from outside at any
 * time without signals, and survive the process. Without the variable they
 * are kept in-process only.
 *
 * At load the shim removes LD_PRELOAD and its own MALLOCSTAT_* variables
 * from the environment, so nothing the process spawns is instrumented.
 *
 * MALLOCSTAT_BT_MIN=<bytes> additionally logs a backtrace of every
 * allocation of at least that many bytes to MALLOCSTAT_BT_FILE (default
 * stderr), as "alloc <fn> <size>" followed by backtrace_symbols_fd() lines.
 * Feed "binary(+0xoff)" frames to addr2line -e binary to get file:line.
 *
 * glibc only: the real allocator is reached through its __libc_* entry
 * points (no dlsym, which itself allocates). glibc routes its own internal
 * allocations (strdup, fopen, qsort, glob, ...) through the interposed
 * malloc, so those are counted too. Single-threaded counting is enough for
 * routebot; updates are relaxed atomics so a reader never sees torn values.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <execinfo.h>
#include <fcntl.h>
#include <malloc.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define MS_MAGIC	0x3174617473636c6dULL	/* "mlcstat1" */
#define MS_VERSION	1

/* Keep in sync with FIELDS in rbstat.py. All uint64_t. */
struct ms_counters {
	uint64_t magic;
	uint64_t version;
	uint64_t n_malloc;
	uint64_t n_calloc;
	uint64_t n_realloc;	/* realloc, reallocarray with a non-NULL ptr */
	uint64_t n_memalign;	/* posix_memalign, aligned_alloc, memalign, [p]valloc */
	uint64_t n_free;	/* frees of non-NULL pointers, and the old block of a realloc */
	uint64_t n_allocs;	/* every call that returned memory, realloc included */
	uint64_t bytes;		/* bytes requested by those calls (realloc: new size) */
	uint64_t live;		/* malloc_usable_size of what is allocated now */
	uint64_t peak_live;
	uint64_t n_big;		/* allocations >= MALLOCSTAT_BT_MIN, if set */
	uint64_t n_failed;	/* calls that returned NULL */
};

extern void *__libc_malloc(size_t);
extern void *__libc_calloc(size_t, size_t);
extern void *__libc_realloc(void *, size_t);
extern void *__libc_memalign(size_t, size_t);
extern void __libc_free(void *);

static struct ms_counters local, *c;
static size_t bt_min;
static int bt_fd = 2;
static int in_bt;

#define ADD(field, v)	__atomic_fetch_add(&c->field, (v), __ATOMIC_RELAXED)

static void strip_env(void)
{
	extern char **environ;
	char **r, **w;

	for (r = w = environ; r && *r; r++)
		if (strncmp(*r, "LD_PRELOAD=", 11) && strncmp(*r, "MALLOCSTAT_", 11))
			*w++ = *r;
	if (w)
		*w = NULL;
}

/* No allocation in here: it runs from inside the first malloc. */
static void init(void)
{
	const char *path = getenv("MALLOCSTAT_FILE");
	const char *v;

	c = &local;
	if (path) {
		int fd = open(path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
		void *m = MAP_FAILED;

		if (fd >= 0 && !ftruncate(fd, 4096))
			m = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		if (fd >= 0)
			close(fd);
		if (m != MAP_FAILED)
			c = m;
	}
	v = getenv("MALLOCSTAT_BT_MIN");
	if (v)
		bt_min = strtoull(v, NULL, 0);
	v = getenv("MALLOCSTAT_BT_FILE");
	if (v && bt_min) {
		int fd = open(v, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);

		if (fd >= 0)
			bt_fd = fd;
	}
	c->version = MS_VERSION;
	__atomic_store_n(&c->magic, MS_MAGIC, __ATOMIC_RELEASE);
}

__attribute__((constructor(101)))
static void ms_ctor(void)
{
	if (!c)
		init();
	strip_env();
}

static void bt(const char *fn, size_t size)
{
	void *frames[32];
	char hdr[64];
	int n, len;

	ADD(n_big, 1);
	if (in_bt)
		return;
	in_bt = 1;	/* backtrace() may allocate the first time */
	len = snprintf(hdr, sizeof(hdr), "alloc %s %zu\n", fn, size);
	if (write(bt_fd, hdr, len) < 0)
		goto out;
	n = backtrace(frames, 32);
	backtrace_symbols_fd(frames + 2, n > 2 ? n - 2 : 0, bt_fd);
	if (write(bt_fd, "\n", 1) < 0)
		goto out;
out:
	in_bt = 0;
}

static void *account(void *p, size_t size, const char *fn)
{
	uint64_t live;

	if (!c)
		init();
	if (in_bt)
		return p;	/* the backtrace machinery's own, not the program's */
	if (!p) {
		ADD(n_failed, 1);
		return p;
	}
	ADD(n_allocs, 1);
	ADD(bytes, size);
	live = ADD(live, malloc_usable_size(p)) + malloc_usable_size(p);
	if (live > c->peak_live)
		__atomic_store_n(&c->peak_live, live, __ATOMIC_RELAXED);
	if (bt_min && size >= bt_min)
		bt(fn, size);
	return p;
}

static void unaccount(void *p)
{
	if (!c)
		init();
	if (!p || in_bt)
		return;
	ADD(n_free, 1);
	ADD(live, -(uint64_t)malloc_usable_size(p));
}

void *malloc(size_t size)
{
	if (!c)
		init();
	if (!in_bt)
		ADD(n_malloc, 1);
	return account(__libc_malloc(size), size, "malloc");
}

void *calloc(size_t n, size_t size)
{
	size_t total;

	if (!c)
		init();
	if (!in_bt)
		ADD(n_calloc, 1);
	if (__builtin_mul_overflow(n, size, &total))
		total = SIZE_MAX;
	return account(__libc_calloc(n, size), total, "calloc");
}

void *realloc(void *p, size_t size)
{
	void *np;

	if (!c)
		init();
	if (!p)
		return malloc(size);
	if (!size) {
		free(p);
		return NULL;
	}
	if (!in_bt)
		ADD(n_realloc, 1);
	/* the old block counts as freed, the result as a new allocation */
	{
		size_t old = malloc_usable_size(p);

		np = __libc_realloc(p, size);
		if (!np) {
			account(NULL, size, "realloc");
			return NULL;
		}
		if (!in_bt) {
			ADD(n_free, 1);
			ADD(live, -(uint64_t)old);
		}
	}
	return account(np, size, "realloc");
}

void *reallocarray(void *p, size_t n, size_t size)
{
	size_t total;

	if (__builtin_mul_overflow(n, size, &total)) {
		errno = ENOMEM;
		return NULL;
	}
	return realloc(p, total);
}

void free(void *p)
{
	unaccount(p);
	__libc_free(p);
}

static void *aligned(size_t align, size_t size, const char *fn)
{
	if (!c)
		init();
	if (!in_bt)
		ADD(n_memalign, 1);
	return account(__libc_memalign(align, size), size, fn);
}

int posix_memalign(void **out, size_t align, size_t size)
{
	void *p;

	if (align < sizeof(void *) || (align & (align - 1)))
		return EINVAL;
	p = aligned(align, size, "posix_memalign");
	if (!p)
		return ENOMEM;
	*out = p;
	return 0;
}

void *aligned_alloc(size_t align, size_t size)
{
	return aligned(align, size, "aligned_alloc");
}

void *memalign(size_t align, size_t size)
{
	return aligned(align, size, "memalign");
}

void *valloc(size_t size)
{
	return aligned(getpagesize(), size, "valloc");
}

void *pvalloc(size_t size)
{
	size_t pg = getpagesize();

	return aligned(pg, (size + pg - 1) & ~(pg - 1), "pvalloc");
}
