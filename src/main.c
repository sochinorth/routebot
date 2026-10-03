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
#include "nl.h"
#include "sync.h"

#define DEFAULT_CONFIG	"/etc/config/routebot"
#define REPAIR_DELAY_MS	(30 * 1000)

int log_level = L_INFO;

static struct {
	const char *cfg_path;
	struct config *cfg;
	struct ifview *synced;	/* what the kernel was last brought to for cfg */
	struct live live;
	struct nl nl;
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

static void log_iface_changes(const struct config *old_cfg, const struct ifview *old,
			      const struct config *cfg, const struct ifview *cur)
{
	for (size_t i = 0; i < cfg->n_ifaces; i++) {
		for (int f = 0; f < 2; f++) {
			const struct ifrender *r = &cur[i].fam[f];
			char gw[INET6_ADDRSTRLEN];

			/* only compare against the same interface by position if it's the same one */
			if (old_cfg && i < old_cfg->n_ifaces &&
			    !strcmp(old_cfg->ifaces[i].name, cfg->ifaces[i].name) &&
			    ifrender_eq(&old[i].fam[f], r))
				continue;

			if (!r->usable)
				info("%s: %s blackholed", cfg->ifaces[i].name, f ? "v6" : "v4");
			else if (r->has_gw)
				info("%s: %s via %s dev %s", cfg->ifaces[i].name, f ? "v6" : "v4",
				     inet_ntop(f ? AF_INET6 : AF_INET, r->gw, gw, sizeof(gw)),
				     cfg->ifaces[i].device);
			else
				info("%s: %s dev %s", cfg->ifaces[i].name, f ? "v6" : "v4",
				     cfg->ifaces[i].device);
		}
	}
}

static void apply(const char *why, struct config *cfg, struct ifview *view)
{
	struct world old = { rb.cfg, rb.synced }, new = { cfg, view };
	struct sync_stats st;

	log_iface_changes(rb.cfg, rb.synced, cfg, view);
	sync_apply(&rb.nl, &old, &new, &st);

	if (st.route_set || st.route_del || st.rule_add || st.rule_del || st.errors)
		info("sync (%s): %u routes set, %u deleted, %u rules added, %u deleted%s",
		     why, st.route_set, st.route_del, st.rule_add, st.rule_del,
		     st.errors ? ", with errors" : "");
	else
		debug("sync (%s): nothing to do", why);

	if (rb.cfg != cfg)
		config_free(rb.cfg);
	if (rb.synced != view)
		free(rb.synced);
	rb.cfg = cfg;
	rb.synced = view;

	if (st.errors) {
		warn("will retry in %d seconds", REPAIR_DELAY_MS / 1000);
		uloop_timeout_set(&rb.repair, REPAIR_DELAY_MS);
	}
}

static struct ifview *resolve(const struct config *cfg)
{
	struct ifview *v = calloc(cfg->n_ifaces + 1, sizeof(*v));

	if (v)
		live_resolve(&rb.live, cfg, v);
	return v;
}

static void reconcile_live(const char *why)
{
	struct ifview *v;
	size_t i;

	if (rb.live.resync) {
		info("resyncing link and gateway state");
		live_dump(&rb.live, &rb.nl);
	}
	if (!rb.live.dirty)
		return;
	rb.live.dirty = false;

	v = resolve(rb.cfg);
	if (!v) {
		err("out of memory");
		return;
	}

	for (i = 0; i < rb.cfg->n_ifaces; i++)
		if (!ifrender_eq(&v[i].fam[0], &rb.synced[i].fam[0]) ||
		    !ifrender_eq(&v[i].fam[1], &rb.synced[i].fam[1]))
			break;
	if (i == rb.cfg->n_ifaces) {
		free(v);
		return;
	}

	apply(why, rb.cfg, v);
}

static void repair_cb(struct uloop_timeout *t)
{
	struct world empty = {}, cur = { rb.cfg, rb.synced };
	struct sync_stats st;

	/* re-set everything; existing identical state is a no-op for the kernel */
	sync_apply(&rb.nl, &empty, &cur, &st);
	if (st.errors) {
		warn("repair: still %u errors, retrying in %d seconds",
		     st.errors, REPAIR_DELAY_MS / 1000);
		uloop_timeout_set(t, REPAIR_DELAY_MS);
	} else {
		info("repair: done");
	}
}

static void reload(void)
{
	struct config *cfg;
	struct ifview *v;

	info("reloading %s", rb.cfg_path);
	cfg = config_load(rb.cfg_path);
	if (!cfg) {
		err("reload failed, keeping the old config");
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

	v = resolve(cfg);
	if (!v) {
		err("out of memory");
		config_free(cfg);
		return;
	}

	apply("reload", cfg, v);
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

	rb.cfg = NULL;
	{
		struct config *cfg = config_load(rb.cfg_path);
		struct ifview *v;

		if (!cfg)
			return 1;
		if (nl_open(&rb.nl)) {
			config_free(cfg);
			return 1;
		}

		/* events queue up on the socket from here on, nothing is missed */
		live_init(&rb.live, cfg);
		sync_flush(&rb.nl, cfg->rt_proto);
		if (live_dump(&rb.live, &rb.nl)) {
			config_free(cfg);
			goto out;
		}
		rb.live.dirty = false;

		v = resolve(cfg);
		if (!v) {
			config_free(cfg);
			goto out;
		}
		rb.synced = NULL;
		apply("startup", cfg, v);
	}

	uloop_init();
	rb.repair.cb = repair_cb;
	rb.ev_fd.fd = nl_event_fd(&rb.nl);
	rb.ev_fd.cb = ev_cb;
	rb.sig_fd.cb = sig_cb;
	uloop_fd_add(&rb.ev_fd, ULOOP_READ);
	uloop_fd_add(&rb.sig_fd, ULOOP_READ);

	info("running");
	uloop_run();
	uloop_done();

	ret = sync_flush(&rb.nl, rb.cfg->rt_proto) ? 1 : 0;

out:
	nl_close(&rb.nl);
	live_free(&rb.live);
	config_free(rb.cfg);
	free(rb.synced);
	close(rb.sig_fd.fd);
	return ret;
}
