#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
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
#define REPAIR_DELAY_MS	(30 * 1000)

int log_level = L_INFO;

/* Everything one rendering is computed from; see struct world. */
struct snap {
	struct config *cfg;
	struct ifview *ifs;
	const char **netdev;
	bool *member_up;
};

static struct {
	const char *cfg_path;
	struct snap synced;	/* what the kernel was last brought to */
	struct live live;
	struct nl nl;
	struct probes *probes;		/* for synced.cfg, or the config being loaded */
	struct uloop_fd ev_fd;
	struct uloop_fd sig_fd;
	struct uloop_timeout repair;
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
	return (struct world){ s->cfg, s->ifs, s->netdev, s->member_up };
}

/* Call before freeing s->cfg. */
static void snap_release(struct snap *s)
{
	if (s->netdev)
		for (size_t d = 0; d < s->cfg->n_devices; d++)
			free((char *)s->netdev[d]);
	free(s->ifs);
	free(s->netdev);
	free(s->member_up);
	s->ifs = NULL;
	s->netdev = NULL;
	s->member_up = NULL;
}

/*
 * Fill in what each device resolves to and which members are healthy.
 * netifd names are copied: they only live until its next change callback.
 */
static int snap_sources(struct snap *s)
{
	const struct config *cfg = s->cfg;
	size_t m = 0;

	for (size_t d = 0; d < cfg->n_devices; d++) {
		const char *l3 = netifd_l3dev(cfg->devices[d].spec);

		s->netdev[d] = strdup(l3 ? l3 : cfg->devices[d].spec);
		if (!s->netdev[d])
			return -1;
	}
	for (size_t g = 0; g < cfg->n_groups; g++)
		for (size_t i = 0; i < cfg->groups[g].n_members; i++)
			s->member_up[m++] = probe_up(rb.probes, g, i);
	return 0;
}

static int snap_take(struct snap *s, struct config *cfg)
{
	size_t n_members = cfg_member_index(cfg, cfg->n_groups, 0);

	s->cfg = cfg;
	s->ifs = calloc(cfg->n_devices + 1, sizeof(*s->ifs));
	s->netdev = calloc(cfg->n_devices + 1, sizeof(*s->netdev));
	s->member_up = calloc(n_members + 1, sizeof(*s->member_up));
	if (!s->ifs || !s->netdev || !s->member_up || snap_sources(s)) {
		err("out of memory");
		snap_release(s);
		return -1;
	}

	live_resolve(&rb.live, cfg, s->netdev, s->ifs);
	return 0;
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

/*
 * A device usable before and after whose link went down in between: the
 * kernel flushed its nexthops and the routes on them behind our back.
 */
static int snap_flapped(const struct snap *old, const struct snap *cur)
{
	for (size_t d = 0; d < cur->cfg->n_devices; d++)
		for (int f = 0; f < 2; f++)
			if (old->ifs[d].fam[f].usable && cur->ifs[d].fam[f].usable &&
			    old->ifs[d].fam[f].downs != cur->ifs[d].fam[f].downs)
				return d;
	return -1;
}

static const char *fam_name(int f)
{
	return f ? "v6" : "v4";
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

static int find_group(const struct config *cfg, const char *name)
{
	for (size_t g = 0; cfg && g < cfg->n_groups; g++)
		if (!strcmp(cfg->groups[g].name, name))
			return g;
	return -1;
}

static int find_device(const struct config *cfg, const char *spec)
{
	for (size_t d = 0; cfg && d < cfg->n_devices; d++)
		if (!strcmp(cfg->devices[d].spec, spec))
			return d;
	return -1;
}

static void log_changes(const struct snap *old, const struct snap *cur)
{
	const struct config *cfg = cur->cfg;

	for (size_t d = 0; d < cfg->n_devices; d++) {
		int od = find_device(old->cfg, cfg->devices[d].spec);

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
		int og = find_group(old->cfg, cfg->groups[g].name);

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

static bool device_probed(const struct config *cfg, size_t d)
{
	for (size_t g = 0; g < cfg->n_groups; g++) {
		const struct cfg_group *grp = &cfg->groups[g];

		if (!grp->has_probe[0] && !grp->has_probe[1])
			continue;
		for (size_t m = 0; m < grp->n_members; m++)
			if (grp->members[m].dev == d)
				return true;
	}
	return false;
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

		if (!cur->ifs[d].fam[0].usable || !device_probed(cur->cfg, d))
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

static void log_sync(const char *why, const struct sync_stats *st)
{
	if (st->route_set || st->route_del || st->nh_set || st->nh_del ||
	    st->rule_add || st->rule_del || st->errors)
		info("sync (%s): %u routes set, %u deleted, %u nexthops set, %u deleted, "
		     "%u rules added, %u deleted%s", why, st->route_set, st->route_del,
		     st->nh_set, st->nh_del, st->rule_add, st->rule_del,
		     st->errors ? ", with errors" : "");
	else
		debug("sync (%s): nothing to do", why);
}

/* Bring the kernel to s, which is taken over. */
static void apply(const char *why, struct snap *s)
{
	struct world old = world_of(&rb.synced), new = world_of(s);
	struct sync_stats st;

	log_changes(&rb.synced, s);
	check_rp_filter(&rb.synced, s);
	sync_apply(&rb.nl, &old, &new, &st);
	log_sync(why, &st);

	snap_release(&rb.synced);
	if (rb.synced.cfg != s->cfg)
		config_free(rb.synced.cfg);
	rb.synced = *s;

	/* probes follow links, not health: dead members keep being probed */
	for (size_t d = 0; d < s->cfg->n_devices; d++)
		probes_set_link(rb.probes, d, s->netdev[d],
				s->ifs[d].fam[0].usable || s->ifs[d].fam[1].usable);

	if (st.errors) {
		warn("will retry in %d seconds", REPAIR_DELAY_MS / 1000);
		uloop_timeout_set(&rb.repair, REPAIR_DELAY_MS);
	}
}

/* Re-set everything; existing identical state is a no-op for the kernel. */
static unsigned reassert(const char *why)
{
	struct world empty = {}, cur = world_of(&rb.synced);
	struct sync_stats st;

	sync_apply(&rb.nl, &empty, &cur, &st);
	log_sync(why, &st);
	return st.errors;
}

static void reconcile_live(const char *why)
{
	struct snap s;
	int flap;

	if (rb.live.resync) {
		info("resyncing link and gateway state");
		live_dump(&rb.live, &rb.nl);
	}
	if (!rb.live.dirty)
		return;
	rb.live.dirty = false;

	if (snap_take(&s, rb.synced.cfg))
		return;

	flap = snap_flapped(&rb.synced, &s);
	if (flap < 0 && snap_eq(&rb.synced, &s)) {
		snap_release(&s);
		return;
	}

	apply(why, &s);
	if (flap >= 0) {
		info("link flap on %s, re-syncing", rb.synced.netdev[flap]);
		if (reassert("link flap")) {
			warn("will retry in %d seconds", REPAIR_DELAY_MS / 1000);
			uloop_timeout_set(&rb.repair, REPAIR_DELAY_MS);
		}
	}
}

/* A netifd mapping or a probe verdict changed. */
static void netifd_changed(void)
{
	rb.live.dirty = true;
	reconcile_live("netifd");
}

static void probes_changed(void)
{
	rb.live.dirty = true;
	reconcile_live("probe");
}

static void repair_cb(struct uloop_timeout *t)
{
	unsigned errors = reassert("repair");

	if (errors) {
		warn("repair: still %u errors, retrying in %d seconds",
		     errors, REPAIR_DELAY_MS / 1000);
		uloop_timeout_set(t, REPAIR_DELAY_MS);
	} else {
		info("repair: done");
	}
}

static bool nhids_moved(const struct config *a, const struct config *b)
{
	return a->nexthop_id != b->nexthop_id || cfg_nhid_end(a) != cfg_nhid_end(b);
}

static void reload(void)
{
	struct probes *old_probes;
	struct config *cfg;
	struct snap s;

	info("reloading %s", rb.cfg_path);
	cfg = config_load(rb.cfg_path);
	if (!cfg || (nhids_moved(cfg, rb.synced.cfg) && sync_check_nhids(&rb.nl, cfg))) {
		err("reload failed, keeping the old config");
		config_free(cfg);
		return;
	}

	/* the old probes point into the old config, which apply() frees */
	old_probes = rb.probes;
	rb.probes = probes_new(cfg, probes_changed);
	if (!rb.probes) {
		err("out of memory");
		rb.probes = old_probes;
		config_free(cfg);
		return;
	}

	if (cfg->gw_table != rb.live.gw_table || cfg->rt_proto != rb.live.own_proto) {
		rb.live.gw_table = cfg->gw_table;
		rb.live.own_proto = cfg->rt_proto;
		rb.live.resync = true;
	}
	if (rb.live.resync)
		live_dump(&rb.live, &rb.nl);
	rb.live.dirty = false;

	if (snap_take(&s, cfg)) {
		probes_free(rb.probes);
		rb.probes = old_probes;
		config_free(cfg);
		return;
	}

	probes_free(old_probes);
	apply("reload", &s);
}

static void ev_cb(struct uloop_fd *fd, unsigned events)
{
	if (nl_event_read(&rb.nl, live_event_cb, &rb.live) == -ENOBUFS) {
		warn("netlink: event socket overflowed");
		rb.live.resync = true;
	}
	reconcile_live("link event");
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

	{
		struct config *cfg = config_load(rb.cfg_path);
		struct snap s;

		if (!cfg)
			return 1;
		if (nl_open(&rb.nl)) {
			config_free(cfg);
			return 1;
		}
		/* events queue up on the socket from here on, nothing is missed */
		live_init(&rb.live, cfg);
		if (sync_check_nhids(&rb.nl, cfg)) {
			config_free(cfg);
			goto out;
		}
		sync_flush(&rb.nl, cfg->rt_proto);
		if (live_dump(&rb.live, &rb.nl)) {
			config_free(cfg);
			goto out;
		}
		rb.live.dirty = false;

		/* the probes point into cfg: free them first on failure */
		netifd_init(netifd_changed);
		rb.probes = probes_new(cfg, probes_changed);
		if (!rb.probes || snap_take(&s, cfg)) {
			probes_free(rb.probes);
			rb.probes = NULL;
			config_free(cfg);
			goto out;
		}
		apply("startup", &s);
	}

	rb.repair.cb = repair_cb;
	rb.ev_fd.fd = nl_event_fd(&rb.nl);
	rb.ev_fd.cb = ev_cb;
	rb.sig_fd.cb = sig_cb;
	uloop_fd_add(&rb.ev_fd, ULOOP_READ);
	uloop_fd_add(&rb.sig_fd, ULOOP_READ);

	info("running");
	uloop_run();

	ret = sync_flush(&rb.nl, rb.synced.cfg->rt_proto) ? 1 : 0;

out:
	probes_free(rb.probes);
	netifd_done();
	uloop_done();
	nl_close(&rb.nl);
	live_free(&rb.live);
	if (rb.synced.cfg)
		snap_release(&rb.synced);
	config_free(rb.synced.cfg);
	close(rb.sig_fd.fd);
	return ret;
}
