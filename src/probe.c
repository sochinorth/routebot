#include <errno.h>
#include <net/if.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <libubox/uloop.h>

#include "log.h"
#include "probe.h"

/* <linux/icmp.h> clashes with <netinet/ip_icmp.h> on some libcs */
#ifndef ICMP_FILTER
#define ICMP_FILTER 1
#endif
#ifndef SOL_RAW
#define SOL_RAW 255
#endif

#define PAYLOAD_LEN	16
#define RECV_LEN	512

struct probes;
struct pmember;

/* One raw socket: member x family. */
struct psock {
	struct uloop_fd ufd;	/* fd < 0: closed or failed to bind */
	struct pmember *m;
	int fam;		/* 0 = v4, 1 = v6 */
	uint16_t id, seq;
	bool outstanding;
	uint8_t losses, wins;
	bool up;
};

struct pmember {
	struct pgroup *g;
	size_t idx;
	char netdev[IFNAMSIZ];	/* "" = unresolved */
	bool usable;
	bool up;		/* combined verdict */
	struct psock s[2];
};

struct pgroup {
	struct probes *p;
	const struct cfg_group *cg;
	struct uloop_timeout tick;
	struct pmember *members;	/* NULL if the group has no probes */
};

struct probes {
	const struct config *cfg;
	void (*changed)(void);
	struct uloop_timeout notify;
	bool noperm;		/* no CAP_NET_RAW: probes disabled, all up */
	struct pgroup *groups;
};

static uint16_t next_id;

static uint16_t csum(const void *data, size_t len)
{
	const uint8_t *b = data;
	uint32_t sum = 0;

	for (; len > 1; b += 2, len -= 2)
		sum += (uint32_t)b[0] << 8 | b[1];
	if (len)
		sum += (uint32_t)b[0] << 8;
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return htons(~sum & 0xffff);
}

static void notify_cb(struct uloop_timeout *t)
{
	struct probes *p = container_of(t, struct probes, notify);

	p->changed();
}

static bool sock_active(const struct psock *s)
{
	const struct pmember *m = s->m;

	return m->g->cg->has_probe[s->fam] && m->usable && m->netdev[0] &&
	       !m->g->p->noperm;
}

/* Recompute the combined verdict; report flips unless quiet. */
static void member_eval(struct pmember *m, bool quiet)
{
	const struct cfg_group *cg = m->g->cg;
	bool up = true;

	for (int f = 0; f < 2; f++)
		if (cg->has_probe[f] && !m->s[f].up)
			up = false;
	if (up == m->up)
		return;
	m->up = up;
	if (quiet)
		debug("%s: member %s probe reset", cg->name, m->netdev);
	else
		info("%s: member %s probe %s", cg->name, m->netdev, up ? "up" : "down");
	uloop_timeout_set(&m->g->p->notify, 0);
}

static void sock_result(struct psock *s, bool ok)
{
	uint8_t need = s->m->g->cg->probe_count ? s->m->g->cg->probe_count : 1;

	if (ok) {
		s->losses = 0;
		if (!s->up && ++s->wins >= need) {
			s->up = true;
			s->wins = 0;
		}
	} else {
		s->wins = 0;
		if (s->up && ++s->losses >= need) {
			s->up = false;
			s->losses = 0;
		}
	}
	member_eval(s->m, false);
}

static void sock_close(struct psock *s)
{
	if (s->ufd.fd >= 0) {
		uloop_fd_delete(&s->ufd);
		close(s->ufd.fd);
		s->ufd.fd = -1;
	}
}

static void sock_reset(struct psock *s)
{
	s->outstanding = false;
	s->losses = s->wins = 0;
	s->up = true;
}

static bool reply_ok(const struct psock *s, const uint8_t *buf, ssize_t len,
		     const struct sockaddr_storage *from)
{
	const struct cfg_group *cg = s->m->g->cg;

	if (s->fam == 0) {
		const struct sockaddr_in *sin = (const void *)from;
		const struct icmphdr *ic;
		size_t hl;

		if (len < (ssize_t)sizeof(struct iphdr))
			return false;
		hl = (buf[0] & 0x0f) * 4;
		if (len < (ssize_t)(hl + sizeof(*ic)) || from->ss_family != AF_INET ||
		    memcmp(&sin->sin_addr, cg->probe[0], 4))
			return false;
		ic = (const void *)(buf + hl);
		return ic->type == ICMP_ECHOREPLY && ic->code == 0 &&
		       ntohs(ic->un.echo.id) == s->id &&
		       ntohs(ic->un.echo.sequence) == s->seq;
	} else {
		const struct sockaddr_in6 *sin6 = (const void *)from;
		const struct icmp6_hdr *ic = (const void *)buf;

		if (len < (ssize_t)sizeof(*ic) || from->ss_family != AF_INET6 ||
		    memcmp(&sin6->sin6_addr, cg->probe[1], 16))
			return false;
		return ic->icmp6_type == ICMP6_ECHO_REPLY && ic->icmp6_code == 0 &&
		       ntohs(ic->icmp6_id) == s->id && ntohs(ic->icmp6_seq) == s->seq;
	}
}

static void sock_cb(struct uloop_fd *fd, unsigned events)
{
	struct psock *s = container_of(fd, struct psock, ufd);
	uint8_t buf[RECV_LEN] __attribute__((aligned(4)));

	for (;;) {
		struct sockaddr_storage from;
		socklen_t flen = sizeof(from);
		ssize_t n = recvfrom(fd->fd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &flen);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno != EAGAIN && errno != EWOULDBLOCK)
				debug("probe recv on %s: %s", s->m->netdev, strerror(errno));
			return;
		}
		if (s->outstanding && reply_ok(s, buf, n, &from)) {
			s->outstanding = false;
			sock_result(s, true);
		}
	}
}

static int sock_setup(struct psock *s, int fd)
{
	const struct config *cfg = s->m->g->p->cfg;
	const char *dev = s->m->netdev;
	uint32_t mark = cfg->probe_mark;

	if (setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)))
		return -1;
	if (s->fam == 0) {
		uint32_t mask = ~(1U << ICMP_ECHOREPLY);

		if (setsockopt(fd, SOL_RAW, ICMP_FILTER, &mask, sizeof(mask)))
			return -1;
	} else {
		struct icmp6_filter flt;

		ICMP6_FILTER_SETBLOCKALL(&flt);
		ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &flt);
		if (setsockopt(fd, IPPROTO_ICMPV6, ICMP6_FILTER, &flt, sizeof(flt)))
			return -1;
	}
	return setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, dev, strlen(dev) + 1);
}

static void sock_open(struct psock *s, bool *warned)
{
	struct probes *p = s->m->g->p;
	int fd;

	sock_close(s);
	if (!sock_active(s))
		return;

	fd = s->fam ? socket(AF_INET6, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_ICMPV6)
		    : socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_ICMP);
	if (fd < 0) {
		if (errno == EPERM || errno == EACCES) {
			err("cannot open raw ICMP socket (%s), probes disabled", strerror(errno));
			p->noperm = true;
			return;
		}
		goto fail;
	}
	if (sock_setup(s, fd)) {
		/* typically ENODEV: leave it failing, losses accumulate */
		int e = errno;

		close(fd);
		errno = e;
		goto fail;
	}
	s->id = ++next_id;
	s->seq = 0;
	s->ufd.fd = fd;
	s->ufd.cb = sock_cb;
	uloop_fd_add(&s->ufd, ULOOP_READ);
	return;

fail:
	if (!*warned)
		warn("%s: probe socket for %s: %s", s->m->g->cg->name, s->m->netdev,
		     strerror(errno));
	*warned = true;
}

static void sock_send(struct psock *s)
{
	const struct cfg_group *cg = s->m->g->cg;
	uint8_t pkt[sizeof(struct icmp6_hdr) + PAYLOAD_LEN] = { 0 };
	struct sockaddr_storage to = { 0 };
	socklen_t tlen;

	s->seq++;
	s->outstanding = true;
	if (s->ufd.fd < 0)
		return;

	if (s->fam == 0) {
		struct sockaddr_in *sin = (void *)&to;
		struct icmphdr *ic = (void *)pkt;

		ic->type = ICMP_ECHO;
		ic->un.echo.id = htons(s->id);
		ic->un.echo.sequence = htons(s->seq);
		ic->checksum = csum(pkt, sizeof(pkt));
		sin->sin_family = AF_INET;
		memcpy(&sin->sin_addr, cg->probe[0], 4);
		tlen = sizeof(*sin);
	} else {
		struct sockaddr_in6 *sin6 = (void *)&to;
		struct icmp6_hdr *ic = (void *)pkt;

		/* the kernel fills in the ICMPv6 checksum */
		ic->icmp6_type = ICMP6_ECHO_REQUEST;
		ic->icmp6_id = htons(s->id);
		ic->icmp6_seq = htons(s->seq);
		sin6->sin6_family = AF_INET6;
		memcpy(&sin6->sin6_addr, cg->probe[1], 16);
		tlen = sizeof(*sin6);
	}
	if (sendto(s->ufd.fd, pkt, sizeof(pkt), 0, (struct sockaddr *)&to, tlen) < 0)
		debug("%s: probe send on %s: %s", cg->name, s->m->netdev, strerror(errno));
}

static void tick_cb(struct uloop_timeout *t)
{
	struct pgroup *g = container_of(t, struct pgroup, tick);

	uloop_timeout_set(t, g->cg->probe_interval_ms ? g->cg->probe_interval_ms : 1000);
	for (size_t i = 0; i < g->cg->n_members; i++) {
		for (int f = 0; f < 2; f++) {
			struct psock *s = &g->members[i].s[f];

			if (!sock_active(s))
				continue;
			if (s->outstanding)
				sock_result(s, false);
			sock_send(s);
		}
	}
}

struct probes *probes_new(const struct config *cfg, void (*changed)(void))
{
	struct probes *p = calloc(1, sizeof(*p));

	if (!p)
		return NULL;
	p->cfg = cfg;
	p->changed = changed;
	p->notify.cb = notify_cb;
	p->groups = calloc(cfg->n_groups ? cfg->n_groups : 1, sizeof(*p->groups));
	if (!p->groups)
		goto fail;

	for (size_t gi = 0; gi < cfg->n_groups; gi++) {
		struct pgroup *g = &p->groups[gi];

		g->p = p;
		g->cg = &cfg->groups[gi];
		g->tick.cb = tick_cb;
		if (!g->cg->has_probe[0] && !g->cg->has_probe[1])
			continue;
		g->members = calloc(g->cg->n_members ? g->cg->n_members : 1, sizeof(*g->members));
		if (!g->members)
			goto fail;
		for (size_t i = 0; i < g->cg->n_members; i++) {
			struct pmember *m = &g->members[i];

			m->g = g;
			m->idx = i;
			m->up = true;
			for (int f = 0; f < 2; f++) {
				m->s[f].m = m;
				m->s[f].fam = f;
				m->s[f].ufd.fd = -1;
				sock_reset(&m->s[f]);
			}
		}
		uloop_timeout_set(&g->tick, g->cg->probe_interval_ms ? g->cg->probe_interval_ms : 1000);
	}
	return p;

fail:
	err("out of memory");
	probes_free(p);
	return NULL;
}

void probes_free(struct probes *p)
{
	if (!p)
		return;
	uloop_timeout_cancel(&p->notify);
	for (size_t gi = 0; p->groups && gi < p->cfg->n_groups; gi++) {
		struct pgroup *g = &p->groups[gi];

		uloop_timeout_cancel(&g->tick);
		for (size_t i = 0; g->members && i < g->cg->n_members; i++)
			for (int f = 0; f < 2; f++)
				sock_close(&g->members[i].s[f]);
		free(g->members);
	}
	free(p->groups);
	free(p);
}

void probes_set_link(struct probes *p, size_t dev, const char *netdev, bool usable)
{
	if (!netdev)
		netdev = "";

	for (size_t gi = 0; gi < p->cfg->n_groups; gi++) {
		struct pgroup *g = &p->groups[gi];

		if (!g->members)
			continue;
		for (size_t i = 0; i < g->cg->n_members; i++) {
			struct pmember *m = &g->members[i];
			bool warned = false;
			bool renamed = strcmp(m->netdev, netdev) != 0;

			if (g->cg->members[i].dev != dev || (!renamed && m->usable == usable))
				continue;

			m->usable = usable;
			snprintf(m->netdev, sizeof(m->netdev), "%s", netdev);
			/* back to optimistic: a returning link is used and re-judged */
			for (int f = 0; f < 2; f++) {
				sock_close(&m->s[f]);
				sock_reset(&m->s[f]);
			}
			member_eval(m, true);
			for (int f = 0; f < 2; f++)
				sock_open(&m->s[f], &warned);
		}
	}
}

bool probe_up(const struct probes *p, size_t group, size_t member)
{
	const struct pgroup *g = &p->groups[group];

	return !g->members || p->noperm || g->members[member].up;
}
