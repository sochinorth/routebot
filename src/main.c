#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <net/if.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/signalfd.h>
#include <unistd.h>

#include <libubox/uloop.h>

#include "config.h"
#include "ifstate.h"
#include "log.h"
#include "netifd.h"
#include "nl.h"
#include "probe.h"
#include "sync.h"

#define DEFAULT_CONFIG	"/etc/config/routebot"
#define RETRY_FIRST_MS	(1 * 1000)
#define RETRY_MS	(30 * 1000)

int log_level = L_INFO;

/*
 * Everything one rendering is computed from; see struct world. The buffers
 * belong to cfg: allocated on its first sync, refilled in place.
 */
struct snap {
	struct config *cfg;
	struct ifview *ifs;
	char (*netdev)[IFNAMSIZ];
	bool *member_up;
};

static struct {
	const char *cfg_path;
	struct config *cfg;	/* the config in use */
	struct snap spare;	/* cfg's next snapshot is built here (cfg NULL: not yet) */
	/*
	 * The world last applied successfully (cfg NULL until then), maybe of
	 * an older config, which it then owns. It stays prev while later
	 * worlds, maybe half-applied, are tried.
	 */
	struct snap applied;
	bool certain;		/* the last sync_apply() returned 0 */
	struct live live;
	struct nl nl;
	struct probes *probes;		/* for cfg, or the config being loaded */
	struct uloop_fd ev_fd;
	struct uloop_fd sig_fd;
	struct uloop_timeout retry;
	struct sync *sync;
} rb;

void log_msg(int level, const char *fmt, ...)
{
	static const char *const prefix[] = { "error", "warning", "info", "debug" };
	va_list ap;

	if (level > log_level)
		return;
	fprintf(stderr, "routebot: %s: ", prefix[level]);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

static struct world world_of(const struct snap *s)
{
	return (struct world){ s->cfg, s->ifs, s->member_up };
}

/* Frees the buffers, not s->cfg. */
static void snap_free(struct snap *s)
{
	free(s->ifs);
	free(s->netdev);
	free(s->member_up);
	*s = (struct snap){ 0 };
}

static int snap_alloc(struct snap *s, struct config *cfg)
{
	size_t n_dev = cfg->n_devices + 1;

	s->cfg = cfg;
	s->ifs = calloc(n_dev, sizeof(*s->ifs));
	s->netdev = calloc(n_dev, sizeof(*s->netdev));
	s->member_up = calloc(cfg_member_index(cfg, cfg->n_groups, 0) + 1,
	                      sizeof(*s->member_up));
	if (!s->ifs || !s->netdev || !s->member_up) {
		err("out of memory");
		snap_free(s);
		return -1;
	}
	return 0;
}

/*
 * Fill in what each device resolves to and which members are healthy.
 * netifd names are copied: they only live until its next change callback.
 * Allocates nothing.
 */
static void snap_fill(struct snap *s)
{
	const struct config *cfg = s->cfg;
	size_t m = 0;

	for (size_t d = 0; d < cfg->n_devices; d++) {
		const char *l3 = netifd_l3dev(cfg->devices[d].spec);
		const char *name = l3 ? l3 : cfg->devices[d].spec;

		/* too long for a netdev: can't resolve */
		if (strlen(name) >= IFNAMSIZ)
			name = "";
		strcpy(s->netdev[d], name);
	}
	for (size_t g = 0; g < cfg->n_groups; g++)
		for (size_t i = 0; i < cfg->groups[g].n_members; i++)
			s->member_up[m++] = probe_up(rb.probes, g, i);

	live_resolve(&rb.live, cfg, s->netdev, s->ifs);
}

static bool snap_eq(const struct snap *a, const struct snap *b)
{
	const struct config *cfg = a->cfg;

	for (size_t d = 0; d < cfg->n_devices; d++)
		if (!ifrender_eq(&a->ifs[d].fam[0], &b->ifs[d].fam[0]) ||
		    !ifrender_eq(&a->ifs[d].fam[1], &b->ifs[d].fam[1]))
			return false;
	return !memcmp(a->member_up, b->member_up,
	               cfg_member_index(cfg, cfg->n_groups, 0) * sizeof(*a->member_up));
}

/* "v4 via a, b" or "v4 blackholed" */
static void fmt_group(const struct snap *s, size_t g, int f, char *buf, size_t len)
{
	const struct cfg_group *grp = &s->cfg->groups[g];
	struct world w = world_of(s);
	size_t n = 0, off;

	off = snprintf(buf, len, "%s via", fam_name(f));
	for (size_t m = 0; m < grp->n_members && off < len; m++) {
		if (!world_member_usable(&w, g, m, f))
			continue;
		off += snprintf(buf + off, len - off, "%s %s", n++ ? "," : "",
				s->cfg->devices[grp->members[m].dev].spec);
	}
	if (!n)
		snprintf(buf, len, "%s blackholed", fam_name(f));
}

static void log_changes(const struct snap *old, const struct snap *cur)
{
	const struct config *cfg = cur->cfg;

	for (size_t d = 0; d < cfg->n_devices; d++) {
		int od = config_find_device(old->cfg, cfg->devices[d].spec);

		for (int f = 0; f < 2; f++) {
			const struct ifrender *r = &cur->ifs[d].fam[f];
			char gw[INET6_ADDRSTRLEN];

			if (od >= 0 && ifrender_eq(&old->ifs[od].fam[f], r))
				continue;
			if (!r->usable)
				debug("%s: %s unusable", cfg->devices[d].spec, fam_name(f));
			else if (r->has_gw)
				debug("%s: %s via %s dev %s", cfg->devices[d].spec, fam_name(f),
				      inet_ntop(f ? AF_INET6 : AF_INET, r->gw, gw, sizeof(gw)),
				      cur->netdev[d]);
			else
				debug("%s: %s dev %s", cfg->devices[d].spec, fam_name(f),
				      cur->netdev[d]);
		}
	}

	for (size_t g = 0; g < cfg->n_groups; g++) {
		int og = config_find_group(old->cfg, cfg->groups[g].name);

		for (int f = 0; f < 2; f++) {
			char now[640], was[640];

			fmt_group(cur, g, f, now, sizeof(now));
			if (og >= 0) {
				fmt_group(old, og, f, was, sizeof(was));
				if (!strcmp(was, now))
					continue;
			}
			info("%s: %s", cfg->groups[g].name, now);
		}
	}
}

static int read_rp_filter(const char *dev)
{
	char path[64];
	FILE *f;
	int v = -1;

	snprintf(path, sizeof(path), "/proc/sys/net/ipv4/conf/%s/rp_filter", dev);
	f = fopen(path, "r");
	if (!f)
		return -1;
	if (fscanf(f, "%d", &v) != 1)
		v = -1;
	fclose(f);
	return v;
}

/*
 * Probe replies come from the probe target, whose unmarked reverse path
 * usually points elsewhere (or at a blackhole): rp_filter drops them.
 * Checked whenever a probed device becomes usable or changes name.
 */
static void check_rp_filter(const struct snap *old, const struct snap *cur)
{
	for (size_t d = 0; d < cur->cfg->n_devices; d++) {
		const char *dev = cur->netdev[d];
		int all, v;

		if (!cur->ifs[d].fam[0].usable || !config_dev_probed(cur->cfg, d))
			continue;
		if (old->cfg == cur->cfg && old->ifs[d].fam[0].usable &&
		    !strcmp(old->netdev[d], dev))
			continue;
		all = read_rp_filter("all");
		v = read_rp_filter(dev);
		if (all > v)
			v = all;
		if (v > 0)
			warn("%s: rp_filter is %d, probe replies may be dropped; set "
			     "net.ipv4.conf.%s.rp_filter=0 and conf.all.rp_filter=0", dev, v, dev);
	}
}

static void log_sync(const char *why, const struct sync_stats *st, bool failed)
{
	if (st->route_set || st->route_del || st->nh_set || st->nh_del ||
	    st->rule_add || st->rule_del || st->errors || failed)
		info("sync (%s): %u routes set, %u deleted, %u nexthops set, %u deleted, "
		     "%u rules added, %u deleted%s", why, st->route_set, st->route_del,
		     st->nh_set, st->nh_del, st->rule_add, st->rule_del,
		     st->errors || failed ? ", with errors" : "");
	else
		debug("sync (%s): nothing to do", why);
}

/* Links or gateways may have changed unseen: re-dump them. */
static int refresh_live(void)
{
	if (!rb.live.resync)
		return 0;
	info("resyncing link and gateway state");
	if (live_dump(&rb.live, &rb.nl)) {
		rb.live.resync = true;
		return -1;
	}
	return 0;
}

/* The kernel may differ from rb.applied unseen: a full sync, soon. */
static void failed(void)
{
	int ms = rb.certain ? RETRY_FIRST_MS : RETRY_MS;

	rb.certain = false;
	warn("will retry in %d seconds", ms / 1000);
	uloop_timeout_set(&rb.retry, ms);
}

/* rb.spare was applied: it becomes rb.applied. */
static void promote(void)
{
	struct snap old = rb.applied;

	rb.applied = rb.spare;
	if (old.cfg == rb.cfg) {
		rb.spare = old;
	} else {
		/* an older config's, or none: the next sync allocates anew */
		config_free(old.cfg);
		snap_free(&old);
		rb.spare = (struct snap){ 0 };
	}
}

/*
 * Bring the kernel to rb.spare (filled). Full if asked, or if the last
 * sync failed; prev stays the last successful world until one succeeds.
 */
static void sync_to(const char *why, bool full)
{
	const struct snap *s = &rb.spare;
	struct world prev = world_of(&rb.applied), want = world_of(s);
	struct sync_stats st = { 0 };
	int ret;

	log_changes(&rb.applied, s);
	check_rp_filter(&rb.applied, s);
	ret = sync_apply(rb.sync, &rb.nl, &prev, &want, full || !rb.certain || !prev.cfg, &st);
	log_sync(why, &st, ret);
	rb.live.dirty = false;
	rb.live.poked = false;

	/* probes follow links, not health: dead members keep being probed */
	for (size_t d = 0; d < s->cfg->n_devices; d++)
		probes_set_link(rb.probes, d, s->netdev[d],
				s->ifs[d].fam[0].usable || s->ifs[d].fam[1].usable);

	if (ret) {
		failed();
	} else {
		rb.certain = true;
		promote();
		uloop_timeout_cancel(&rb.retry);
	}
}

/*
 * Sync rb.cfg to the current links, netifd and probes. lazy: skip if
 * nothing the desired state depends on changed and the kernel wasn't
 * poked.
 */
static void sync_now(const char *why, bool full, bool lazy)
{
	if (!rb.cfg)
		return;		/* startup syncs once it's ready */
	if (refresh_live() || (!rb.spare.cfg && snap_alloc(&rb.spare, rb.cfg))) {
		failed();
		return;
	}
	snap_fill(&rb.spare);
	if (lazy && !full && rb.certain && rb.applied.cfg == rb.cfg &&
	    !rb.live.dirty && !rb.live.poked && snap_eq(&rb.applied, &rb.spare)) {
		debug("sync (%s): nothing to do", why);
		return;
	}
	sync_to(why, full);
}

/*
 * Take cfg into use (rb.probes already follow it). The old one goes,
 * unless it is still the applied one.
 */
static void use_config(struct config *cfg)
{
	snap_free(&rb.spare);
	if (rb.cfg != rb.applied.cfg)
		config_free(rb.cfg);
	rb.cfg = cfg;
}

/* A netifd mapping or a probe verdict changed. */
static void netifd_changed(void)
{
	sync_now("netifd", false, true);
}

static void probes_changed(void)
{
	sync_now("probe", false, true);
}

static void retry_cb(struct uloop_timeout *t)
{
	sync_now("retry", true, false);
}

static void reload(void)
{
	struct probes *old_probes = rb.probes;
	struct config *cfg;

	info("reloading %s", rb.cfg_path);
	cfg = config_load(rb.cfg_path, rb.cfg);
	if (!cfg) {
		err("reload failed, keeping the old config");
		return;
	}
	/*
	 * Syncs observe prev's and want's protos only: a failed sync may have
	 * left the current config's behind, about to be neither.
	 */
	if (rb.cfg->rt_proto != cfg->rt_proto &&
	    (!rb.applied.cfg || rb.applied.cfg->rt_proto != rb.cfg->rt_proto))
		sync_flush(&rb.nl, rb.cfg->rt_proto);
	if (sync_check_nhids(rb.sync, &rb.nl, cfg, rb.applied.cfg)) {
		err("reload failed, keeping the old config");
		config_free(cfg);
		return;
	}

	/* the old probes point into the old config, which use_config() frees */
	rb.probes = probes_new(cfg, probes_changed);
	if (!rb.probes) {
		err("out of memory");
		rb.probes = old_probes;
		config_free(cfg);
		return;
	}
	probes_free(old_probes);
	use_config(cfg);

	if (cfg->gw_table != rb.live.gw_table || cfg->rt_proto != rb.live.own_proto) {
		rb.live.gw_table = cfg->gw_table;
		rb.live.own_proto = cfg->rt_proto;
		rb.live.resync = true;
	}
	sync_now("reload", false, false);
}

static void ev_cb(struct uloop_fd *fd, unsigned events)
{
	bool full = false;

	if (nl_event_read(&rb.nl, live_event_cb, &rb.live) == -ENOBUFS) {
		warn("netlink: event socket overflowed");
		rb.live.resync = true;
		full = true;
	}
	/*
	 * After a failure the pending full sync sees all of it: soon, not at
	 * once, or a sync that keeps failing would keep poking itself.
	 */
	if (!rb.certain && rb.retry.pending) {
		if (uloop_timeout_remaining64(&rb.retry) > RETRY_FIRST_MS)
			uloop_timeout_set(&rb.retry, RETRY_FIRST_MS);
		return;
	}
	if (rb.live.resync || rb.live.dirty || rb.live.poked)
		sync_now("event", full, false);
}

static void sig_cb(struct uloop_fd *fd, unsigned events)
{
	struct signalfd_siginfo si;

	while (read(fd->fd, &si, sizeof(si)) == sizeof(si)) {
		switch (si.ssi_signo) {
		case SIGHUP:
			reload();
			break;
		case SIGINT:
		case SIGTERM:
			info("caught signal %u, exiting", si.ssi_signo);
			uloop_end();
			break;
		}
	}
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s [-c config] [-v]\n"
		"  -c path   config file (default " DEFAULT_CONFIG ")\n"
		"  -v        more verbose logging\n"
		"  -q        less verbose logging\n",
		prog);
}

int main(int argc, char **argv)
{
	sigset_t mask;
	int opt, ret = 1;

	rb.cfg_path = DEFAULT_CONFIG;
	while ((opt = getopt(argc, argv, "c:vqh")) != -1) {
		switch (opt) {
		case 'c':
			rb.cfg_path = optarg;
			break;
		case 'v':
			if (log_level < L_DEBUG)
				log_level++;
			break;
		case 'q':
			if (log_level > L_ERR)
				log_level--;
			break;
		default:
			usage(argv[0]);
			return opt == 'h' ? 0 : 1;
		}
	}

	setvbuf(stderr, NULL, _IOLBF, 0);

	sigemptyset(&mask);
	sigaddset(&mask, SIGHUP);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	if (sigprocmask(SIG_BLOCK, &mask, NULL)) {
		err("sigprocmask: %s", strerror(errno));
		return 1;
	}
	rb.sig_fd.fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
	if (rb.sig_fd.fd < 0) {
		err("signalfd: %s", strerror(errno));
		return 1;
	}

	uloop_init();
	rb.sync = sync_new();
	if (!rb.sync) {
		err("out of memory");
		return 1;
	}

	{
		struct config *cfg = config_load(rb.cfg_path, NULL);

		if (!cfg)
			return 1;
		if (nl_open(&rb.nl)) {
			config_free(cfg);
			return 1;
		}
		/* events queue up on the socket from here on, nothing is missed */
		live_init(&rb.live, cfg);
		if (sync_check_nhids(rb.sync, &rb.nl, cfg, NULL) || live_dump(&rb.live, &rb.nl)) {
			config_free(cfg);
			goto out;
		}

		/* the probes point into cfg: free them first on failure */
		netifd_init(netifd_changed);
		rb.probes = probes_new(cfg, probes_changed);
		if (!rb.probes) {
			config_free(cfg);
			goto out;
		}
		rb.certain = true;
		rb.retry.cb = retry_cb;
		use_config(cfg);
		/* prev is empty: a full reconcile, in place */
		sync_now("startup", true, false);
	}

	rb.ev_fd.fd = nl_event_fd(&rb.nl);
	rb.ev_fd.cb = ev_cb;
	rb.sig_fd.cb = sig_cb;
	uloop_fd_add(&rb.ev_fd, ULOOP_READ);
	uloop_fd_add(&rb.sig_fd, ULOOP_READ);

	info("running");
	uloop_run();

	/* a failed sync may have left rb.cfg's proto behind too */
	ret = sync_flush(&rb.nl, rb.cfg->rt_proto) ? 1 : 0;
	if (rb.applied.cfg && rb.applied.cfg->rt_proto != rb.cfg->rt_proto &&
	    sync_flush(&rb.nl, rb.applied.cfg->rt_proto))
		ret = 1;

out:
	probes_free(rb.probes);
	netifd_done();
	uloop_done();
	nl_close(&rb.nl);
	live_free(&rb.live);
	snap_free(&rb.spare);
	if (rb.cfg != rb.applied.cfg)
		config_free(rb.cfg);
	{
		struct config *cfg = rb.applied.cfg;

		snap_free(&rb.applied);
		config_free(cfg);
	}
	close(rb.sig_fd.fd);
	sync_free(rb.sync);
	return ret;
}
