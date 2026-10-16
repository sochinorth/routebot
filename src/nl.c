#include <arpa/inet.h>
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include <linux/fib_rules.h>
#include <linux/filter.h>
#include <linux/netlink.h>
#include <linux/nexthop.h>
#include <linux/rtnetlink.h>

#include "cidr.h"
#include "log.h"
#include "nl.h"

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

#define BATCH_LIMIT	(32 * 1024)
#define RCVBUF_SIZE	(4 * 1024 * 1024)
#define RECV_BUF_SIZE	(64 * 1024)
#define MAX_LOGGED_ERRORS 16

/* USER_HZ, the unit of nexthop group timers both ways */
#define NH_HZ 100

/*
 * The batch is sent when a message takes it past BATCH_LIMIT, after that
 * message was written: the buffer needs room for one more of the largest
 * we build, a resilient group of MAX_NH_GROUP members (328 bytes; routes
 * and rules stay under 100).
 */
#define MSG_MAX	512
#define ATTR_SIZE(payload)	MNL_ALIGN(MNL_ATTR_HDRLEN + (payload))
_Static_assert(MSG_MAX >= NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(struct nhmsg)) +
               ATTR_SIZE(4) +						/* NHA_ID */
               ATTR_SIZE(MAX_NH_GROUP * sizeof(struct nexthop_grp)) +	/* NHA_GROUP */
               ATTR_SIZE(2) +						/* NHA_GROUP_TYPE */
               MNL_ATTR_HDRLEN + ATTR_SIZE(2) + 2 * ATTR_SIZE(4),	/* NHA_RES_GROUP */
               "MSG_MAX too small for a full resilient group");

/*
 * RECV_BUF_SIZE: one datagram per recv. Dump skbs are at most 32 KB (the
 * kernel caps what it learns from our buffer size at SKB_WITH_OVERHEAD(32
 * KB)) unless one message needs more (min_dump_alloc); notifications and
 * error replies are single messages. Pages never written to cost nothing.
 */
static char recv_buf[RECV_BUF_SIZE] __attribute__((aligned(4)));

/* Error replies, drained while a dump's datagram in recv_buf is processed. */
static char err_buf[8192] __attribute__((aligned(4)));

static void set_rcvbuf(struct mnl_socket *s)
{
	int fd = mnl_socket_get_fd(s), size = RCVBUF_SIZE;

	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &size, sizeof(size)))
		setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
}

/*
 * Every route we install shows up as a multicast notification; with big
 * prefix lists that would flood the event socket for nothing. Only default
 * routes matter to us (gateway learning), so drop everything else in-kernel.
 */
static int attach_event_filter(struct mnl_socket *s)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	const unsigned type_lo = offsetof(struct nlmsghdr, nlmsg_type);
#else
	const unsigned type_lo = offsetof(struct nlmsghdr, nlmsg_type) + 1;
#endif
	struct sock_filter code[] = {
		BPF_STMT(BPF_LD | BPF_B | BPF_ABS, type_lo),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, RTM_NEWROUTE, 1, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, RTM_DELROUTE, 0, 3),
		BPF_STMT(BPF_LD | BPF_B | BPF_ABS,
		         NLMSG_HDRLEN + offsetof(struct rtmsg, rtm_dst_len)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0),
		BPF_STMT(BPF_RET | BPF_K, 0),
		BPF_STMT(BPF_RET | BPF_K, 0xffffffff),
	};
	struct sock_fprog prog = {
		.len = sizeof(code) / sizeof(code[0]),
		.filter = code,
	};

	return setsockopt(mnl_socket_get_fd(s), SOL_SOCKET, SO_ATTACH_FILTER,
	                  &prog, sizeof(prog));
}

int nl_open(struct nl *nl)
{
	/* bit n-1 is group n: RTNLGRP_NEXTHOP (32) still fits the bind mask */
	unsigned groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR |
	                  RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE | RTMGRP_IPV4_RULE |
	                  1u << (RTNLGRP_IPV6_RULE - 1) | 1u << (RTNLGRP_NEXTHOP - 1);
	int one = 1;

	memset(nl, 0, sizeof(*nl));

	nl->req = mnl_socket_open2(NETLINK_ROUTE, SOCK_CLOEXEC);
	if (!nl->req || mnl_socket_bind(nl->req, 0, MNL_SOCKET_AUTOPID) < 0)
		goto fail;
	set_rcvbuf(nl->req);
	/* both optional: nicer error messages, kernel-side dump filtering */
	mnl_socket_setsockopt(nl->req, NETLINK_EXT_ACK, &one, sizeof(one));
	mnl_socket_setsockopt(nl->req, NETLINK_GET_STRICT_CHK, &one, sizeof(one));

	nl->dump = mnl_socket_open2(NETLINK_ROUTE, SOCK_CLOEXEC);
	if (!nl->dump || mnl_socket_bind(nl->dump, 0, MNL_SOCKET_AUTOPID) < 0)
		goto fail;
	set_rcvbuf(nl->dump);
	mnl_socket_setsockopt(nl->dump, NETLINK_EXT_ACK, &one, sizeof(one));
	mnl_socket_setsockopt(nl->dump, NETLINK_GET_STRICT_CHK, &one, sizeof(one));

	nl->ev = mnl_socket_open2(NETLINK_ROUTE, SOCK_NONBLOCK | SOCK_CLOEXEC);
	if (!nl->ev)
		goto fail;
	if (attach_event_filter(nl->ev))
		warn("netlink: can't attach event filter: %s", strerror(errno));
	set_rcvbuf(nl->ev);
	if (mnl_socket_bind(nl->ev, groups, MNL_SOCKET_AUTOPID) < 0)
		goto fail;

	nl->batch_buf = malloc(BATCH_LIMIT + MSG_MAX);
	if (!nl->batch_buf)
		goto fail;
	nl->batch = mnl_nlmsg_batch_start(nl->batch_buf, BATCH_LIMIT);
	if (!nl->batch)
		goto fail;

	return 0;

fail:
	err("netlink: open failed: %s", strerror(errno));
	nl_close(nl);
	return -1;
}

void nl_close(struct nl *nl)
{
	if (nl->batch)
		mnl_nlmsg_batch_stop(nl->batch);
	free(nl->batch_buf);
	free(nl->refused);
	if (nl->req)
		mnl_socket_close(nl->req);
	if (nl->dump)
		mnl_socket_close(nl->dump);
	if (nl->ev)
		mnl_socket_close(nl->ev);
	memset(nl, 0, sizeof(*nl));
}

int nl_dump(struct nl *nl, struct nlmsghdr *req, mnl_cb_t cb, void *data)
{
	uint32_t seq = ++nl->seq;
	ssize_t n;
	int ret;

	req->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req->nlmsg_seq = seq;

	if (mnl_socket_sendto(nl->dump, req, req->nlmsg_len) < 0)
		return -errno;

	do {
		n = mnl_socket_recvfrom(nl->dump, recv_buf, sizeof(recv_buf));
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		ret = mnl_cb_run(recv_buf, n, seq, mnl_socket_get_portid(nl->dump), cb, data);
		if (ret < 0)
			return -errno;
	} while (ret != MNL_CB_STOP);

	return 0;
}

int nl_dump_nexthops(struct nl *nl, mnl_cb_t cb, void *data)
{
	char buf[128] __attribute__((aligned(4)));
	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
	struct nhmsg *nhm;

	/* a kernel without nexthop objects answers -EOPNOTSUPP itself */
	nlh->nlmsg_type = RTM_GETNEXTHOP;
	/* strict checking: everything but the family must be zero */
	nhm = mnl_nlmsg_put_extra_header(nlh, sizeof(*nhm));
	nhm->nh_family = AF_UNSPEC;
	return nl_dump(nl, nlh, cb, data);
}

int nl_dump_routes(struct nl *nl, uint8_t family, uint32_t table, uint8_t proto,
                   mnl_cb_t cb, void *data)
{
	char buf[128] __attribute__((aligned(4)));
	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
	struct rtmsg *rtm;

	/* with NETLINK_GET_STRICT_CHK the kernel filters by table and protocol */
	nlh->nlmsg_type = RTM_GETROUTE;
	rtm = mnl_nlmsg_put_extra_header(nlh, sizeof(*rtm));
	rtm->rtm_family = family;
	rtm->rtm_protocol = proto;
	if (table) {
		rtm->rtm_table = table < 256 ? table : RT_TABLE_UNSPEC;
		mnl_attr_put_u32(nlh, RTA_TABLE, table);
	}
	return nl_dump(nl, nlh, cb, data);
}

int nl_dump_rules(struct nl *nl, mnl_cb_t cb, void *data)
{
	char buf[128] __attribute__((aligned(4)));
	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
	struct fib_rule_hdr *frh;

	nlh->nlmsg_type = RTM_GETRULE;
	frh = mnl_nlmsg_put_extra_header(nlh, sizeof(*frh));
	frh->family = AF_UNSPEC;
	return nl_dump(nl, nlh, cb, data);
}

/* --- parsing --- */

#define PARSE_MAX 64

/* attributes by type; any of PARSE_MAX or above sets other */
struct ptb {
	const struct nlattr *tb[PARSE_MAX];
	bool other;
};

static int ptb_cb(const struct nlattr *a, void *data)
{
	struct ptb *t = data;
	unsigned type = mnl_attr_get_type(a);

	if (type < PARSE_MAX)
		t->tb[type] = a;
	else
		t->other = true;
	return MNL_CB_OK;
}

/* false if any attribute is malformed */
static bool ptb_parse(const struct nlmsghdr *nlh, size_t hdrlen, struct ptb *t)
{
	memset(t, 0, sizeof(*t));
	return mnl_nlmsg_get_payload_len(nlh) >= hdrlen &&
	       mnl_attr_parse(nlh, hdrlen, ptb_cb, t) >= MNL_CB_STOP;
}

static bool ptb_u32(const struct ptb *t, unsigned type, uint32_t *v)
{
	if (!t->tb[type])
		return true;
	if (mnl_attr_get_payload_len(t->tb[type]) < 4)
		return false;
	*v = mnl_attr_get_u32(t->tb[type]);
	return true;
}

/* an address of exactly alen bytes, absent is fine */
static bool ptb_addr(const struct ptb *t, unsigned type, size_t alen, uint8_t *out, bool *has)
{
	if (!t->tb[type])
		return true;
	if (mnl_attr_get_payload_len(t->tb[type]) != alen)
		return false;
	memcpy(out, mnl_attr_get_payload(t->tb[type]), alen);
	if (has)
		*has = true;
	return true;
}

int nl_parse_route(const struct nlmsghdr *nlh, struct route_spec *r)
{
	const struct rtmsg *rtm = mnl_nlmsg_get_payload(nlh);
	struct ptb t;
	size_t alen;

	memset(r, 0, sizeof(*r));
	if (!ptb_parse(nlh, sizeof(*rtm), &t))
		return -1;
	if ((rtm->rtm_family != AF_INET && rtm->rtm_family != AF_INET6) ||
	    (rtm->rtm_flags & RTM_F_CLONED))
		return -1;
	alen = family_alen(rtm->rtm_family);

	r->family = rtm->rtm_family;
	r->plen = rtm->rtm_dst_len;
	r->type = rtm->rtm_type;
	r->proto = rtm->rtm_protocol;
	r->table = rtm->rtm_table;
	r->tos = rtm->rtm_tos;
	r->src_len = rtm->rtm_src_len;
	if (r->plen > alen * 8 || r->src_len > alen * 8 ||
	    !ptb_u32(&t, RTA_TABLE, &r->table) ||
	    !ptb_u32(&t, RTA_PRIORITY, &r->metric) ||
	    !ptb_u32(&t, RTA_NH_ID, &r->nh_id) ||
	    !ptb_addr(&t, RTA_DST, alen, r->dst, NULL) ||
	    !ptb_addr(&t, RTA_SRC, alen, r->src, NULL))
		return -1;

	/* nexthop details only for plain unicast routes (nhid: compat dump) */
	if (r->type != RTN_UNICAST || r->nh_id)
		return 0;
	if (t.tb[RTA_MULTIPATH]) {
		r->multipath = true;
		return 0;
	}
	if (!ptb_u32(&t, RTA_OIF, (uint32_t *)&r->oif) ||
	    !ptb_addr(&t, RTA_GATEWAY, alen, r->gw, &r->has_gw))
		return -1;
	return 0;
}

/* NHA_GROUP entries: weight is 0-based, weight_high (was resvd1) on 6.12+ */
static int parse_group(const struct nlattr *a, struct nexthop_spec *out)
{
	const uint8_t *p = mnl_attr_get_payload(a);
	size_t len = mnl_attr_get_payload_len(a);

	if (!len || len % 8 || len / 8 > MAX_NH_GROUP)
		return -1;
	for (size_t i = 0; i < len / 8; i++, p += 8) {
		unsigned w = 1 + p[4] + (p[5] << 8);

		memcpy(&out->grp[i].id, p, 4);
		out->grp[i].weight = w <= UINT16_MAX ? w : UINT16_MAX;
	}
	out->n_grp = len / 8;
	return 0;
}

/* clock_t (USER_HZ) to seconds, rounded */
static uint32_t nh_secs(const struct nlattr *a)
{
	return a && mnl_attr_get_payload_len(a) >= 4 ?
	       (mnl_attr_get_u32(a) + NH_HZ / 2) / NH_HZ : 0;
}

int nl_parse_nexthop(const struct nlmsghdr *nlh, struct nexthop_spec *out)
{
	const struct nhmsg *nhm = mnl_nlmsg_get_payload(nlh);
	struct ptb t, res;

	memset(out, 0, sizeof(*out));
	if (!ptb_parse(nlh, sizeof(*nhm), &t) || !t.tb[NHA_ID] ||
	    !ptb_u32(&t, NHA_ID, &out->id))
		return -1;
	out->family = nhm->nh_family;
	out->proto = nhm->nh_protocol;

	if (t.tb[NHA_GROUP]) {
		out->family = AF_UNSPEC;
		if (parse_group(t.tb[NHA_GROUP], out))
			return -1;
		if (!t.tb[NHA_GROUP_TYPE] ||
		    mnl_attr_get_payload_len(t.tb[NHA_GROUP_TYPE]) < 2 ||
		    mnl_attr_get_u16(t.tb[NHA_GROUP_TYPE]) != NEXTHOP_GRP_TYPE_RES)
			return 0;
		memset(&res, 0, sizeof(res));
		if (!t.tb[NHA_RES_GROUP] ||
		    mnl_attr_parse_nested(t.tb[NHA_RES_GROUP], ptb_cb, &res) < MNL_CB_STOP)
			return -1;
		if (res.tb[NHA_RES_GROUP_BUCKETS] &&
		    mnl_attr_get_payload_len(res.tb[NHA_RES_GROUP_BUCKETS]) >= 2)
			out->buckets = mnl_attr_get_u16(res.tb[NHA_RES_GROUP_BUCKETS]);
		out->timer_idle = nh_secs(res.tb[NHA_RES_GROUP_IDLE_TIMER]);
		out->timer_busy = nh_secs(res.tb[NHA_RES_GROUP_UNBALANCED_TIMER]);
		return 0;
	}

	if (out->family != AF_INET && out->family != AF_INET6)
		return -1;
	if (t.tb[NHA_BLACKHOLE]) {
		out->blackhole = true;
		return 0;
	}
	if (!ptb_u32(&t, NHA_OIF, (uint32_t *)&out->oif) ||
	    !ptb_addr(&t, NHA_GATEWAY, family_alen(out->family), out->gw, &out->has_gw))
		return -1;
	return 0;
}

int nl_parse_rule(const struct nlmsghdr *nlh, struct rule_spec *out)
{
	const struct fib_rule_hdr *frh = mnl_nlmsg_get_payload(nlh);
	static const unsigned plain[] = {
		FRA_PRIORITY, FRA_FWMARK, FRA_FWMASK, FRA_TABLE, FRA_PROTOCOL, FRA_PAD,
	};
	struct ptb t;
	bool odd;

	memset(out, 0, sizeof(*out));
	if (!ptb_parse(nlh, sizeof(*frh), &t) ||
	    (frh->family != AF_INET && frh->family != AF_INET6))
		return -1;

	out->family = frh->family;
	out->table = frh->table;
	if (t.tb[FRA_PROTOCOL] && mnl_attr_get_payload_len(t.tb[FRA_PROTOCOL]) >= 1)
		out->proto = mnl_attr_get_u8(t.tb[FRA_PROTOCOL]);
	if (!ptb_u32(&t, FRA_PRIORITY, &out->prio) ||
	    !ptb_u32(&t, FRA_FWMARK, &out->mark) ||
	    !ptb_u32(&t, FRA_FWMASK, &out->mask) ||
	    !ptb_u32(&t, FRA_TABLE, &out->table))
		return -1;

	/* the kernel always reports the suppressors, -1 when unset */
	odd = frh->action != FR_ACT_TO_TBL || frh->dst_len || frh->src_len ||
	      frh->tos || (frh->flags & ~FIB_RULE_PERMANENT) || t.other;
	for (unsigned i = 0; i < PARSE_MAX && !odd; i++) {
		uint32_t v = 0;

		if (!t.tb[i])
			continue;
		if (i == FRA_SUPPRESS_PREFIXLEN || i == FRA_SUPPRESS_IFGROUP) {
			odd = !ptb_u32(&t, i, &v) || v != UINT32_MAX;
			continue;
		}
		odd = true;
		for (unsigned j = 0; j < sizeof(plain) / sizeof(plain[0]); j++)
			if (plain[j] == i)
				odd = false;
	}
	return odd;
}

/* --- batched writes --- */

static bool error_expected(uint16_t type, int error)
{
	switch (type) {
	case RTM_DELROUTE:
		return error == ESRCH || error == ENOENT;
	case RTM_DELRULE:
		return error == ENOENT;
	case RTM_NEWRULE:
		return error == EEXIST;
	case RTM_DELNEXTHOP:
		/* the kernel flushes nexthops itself when their device goes down */
		return error == ENOENT;
	}
	return false;
}

static void describe_req(const struct nlmsghdr *req, bool capped, char *buf, size_t len)
{
	const char *op;
	struct ptb t = {};

	switch (req->nlmsg_type) {
	case RTM_NEWROUTE: op = "route set"; break;
	case RTM_DELROUTE: op = "route del"; break;
	case RTM_NEWRULE: op = "rule add"; break;
	case RTM_DELRULE: op = "rule del"; break;
	case RTM_NEWNEXTHOP: op = "nexthop set"; break;
	case RTM_DELNEXTHOP: op = "nexthop del"; break;
	default:
		snprintf(buf, len, "msg type %u", req->nlmsg_type);
		return;
	}

	if (capped) {
		snprintf(buf, len, "%s (seq %u)", op, req->nlmsg_seq);
		return;
	}

	if (req->nlmsg_type == RTM_NEWROUTE || req->nlmsg_type == RTM_DELROUTE) {
		const struct rtmsg *rtm = mnl_nlmsg_get_payload(req);
		char addr[INET6_ADDRSTRLEN] = "default";

		mnl_attr_parse(req, sizeof(*rtm), ptb_cb, &t);
		if (t.tb[RTA_DST])
			inet_ntop(rtm->rtm_family, mnl_attr_get_payload(t.tb[RTA_DST]),
			          addr, sizeof(addr));
		snprintf(buf, len, "%s %s/%u table %u", op, addr, rtm->rtm_dst_len,
		         t.tb[RTA_TABLE] ? mnl_attr_get_u32(t.tb[RTA_TABLE]) : rtm->rtm_table);
		if (t.tb[RTA_NH_ID]) {
			size_t n = strlen(buf);

			snprintf(buf + n, len - n, " nhid %u", mnl_attr_get_u32(t.tb[RTA_NH_ID]));
		}
	} else if (req->nlmsg_type == RTM_NEWNEXTHOP || req->nlmsg_type == RTM_DELNEXTHOP) {
		const struct nhmsg *nhm = mnl_nlmsg_get_payload(req);

		mnl_attr_parse(req, sizeof(*nhm), ptb_cb, &t);
		snprintf(buf, len, "%s id %u", op,
		         t.tb[NHA_ID] ? mnl_attr_get_u32(t.tb[NHA_ID]) : 0);
		if (t.tb[NHA_GROUP]) {
			size_t n = strlen(buf);

			snprintf(buf + n, len - n, " group of %zu",
			         mnl_attr_get_payload_len(t.tb[NHA_GROUP]) /
			         sizeof(struct nexthop_grp));
		}
	} else {
		const struct fib_rule_hdr *frh = mnl_nlmsg_get_payload(req);

		mnl_attr_parse(req, sizeof(*frh), ptb_cb, &t);
		snprintf(buf, len, "%s %s prio %u", op,
		         frh->family == AF_INET6 ? "v6" : "v4",
		         t.tb[FRA_PRIORITY] ? mnl_attr_get_u32(t.tb[FRA_PRIORITY]) : 0);
	}
}

/* What req was about, for nl->refused. */
static void note_refused(struct nl *nl, const struct nlmsghdr *req, int error)
{
	struct ptb t = {};
	struct nl_refused *r;

	if (nl->n_refused == nl->cap_refused) {
		unsigned cap = nl->cap_refused ? 2 * nl->cap_refused : 32;
		struct nl_refused *nr = realloc(nl->refused, cap * sizeof(*nr));

		/* unknown then: an error that says nothing of what failed */
		if (!nr)
			return;
		nl->refused = nr;
		nl->cap_refused = cap;
	}
	r = &nl->refused[nl->n_refused++];

	memset(r, 0, sizeof(*r));
	r->type = req->nlmsg_type;
	r->error = error;
	if (req->nlmsg_type == RTM_NEWNEXTHOP || req->nlmsg_type == RTM_DELNEXTHOP) {
		const struct nhmsg *nhm = mnl_nlmsg_get_payload(req);

		r->family = nhm->nh_family;
		mnl_attr_parse(req, sizeof(*nhm), ptb_cb, &t);
		ptb_u32(&t, NHA_ID, &r->id);
	} else if (req->nlmsg_type == RTM_NEWROUTE || req->nlmsg_type == RTM_DELROUTE) {
		const struct rtmsg *rtm = mnl_nlmsg_get_payload(req);

		r->family = rtm->rtm_family;
		r->table = rtm->rtm_table;
		mnl_attr_parse(req, sizeof(*rtm), ptb_cb, &t);
		ptb_u32(&t, RTA_TABLE, &r->table);
		ptb_u32(&t, RTA_PRIORITY, &r->metric);
	}
}

static void handle_error(struct nl *nl, const struct nlmsghdr *nlh)
{
	const struct nlmsgerr *e = mnl_nlmsg_get_payload(nlh);
	bool capped = nlh->nlmsg_flags & NLM_F_CAPPED;
	const char *ext = NULL;
	char desc[128];
	int error = -e->error;

	if (!error)
		return;
	if (error_expected(e->msg.nlmsg_type, error)) {
		nl->n_expected++;
		return;
	}

	if (!capped)
		note_refused(nl, &e->msg, error);
	if (nl->n_errors++ >= MAX_LOGGED_ERRORS)
		return;

	if (nlh->nlmsg_flags & NLM_F_ACK_TLVS) {
		struct ptb t = {};
		size_t off = sizeof(*e);

		if (!capped)
			off += e->msg.nlmsg_len - sizeof(e->msg);
		mnl_attr_parse(nlh, off, ptb_cb, &t);
		if (t.tb[NLMSGERR_ATTR_MSG])
			ext = mnl_attr_get_str(t.tb[NLMSGERR_ATTR_MSG]);
	}

	describe_req(&e->msg, capped, desc, sizeof(desc));
	warn("netlink: %s: %s%s%s%s", desc, strerror(error),
	     ext ? " (" : "", ext ? ext : "", ext ? ")" : "");
}

static void drain_errors(struct nl *nl)
{
	int fd = mnl_socket_get_fd(nl->req);

	for (;;) {
		const struct nlmsghdr *nlh;
		ssize_t n = recv(fd, err_buf, sizeof(err_buf), MSG_DONTWAIT);
		int len;

		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno == ENOBUFS) {
				/* error replies were lost, can't say which */
				nl->n_errors++;
				warn("netlink: error replies overflowed");
				continue;
			}
			return;
		}

		len = n;
		for (nlh = (const struct nlmsghdr *)err_buf; mnl_nlmsg_ok(nlh, len);
		     nlh = mnl_nlmsg_next(nlh, &len))
			if (nlh->nlmsg_type == NLMSG_ERROR)
				handle_error(nl, nlh);
	}
}

static void batch_send(struct nl *nl)
{
	size_t size = mnl_nlmsg_batch_size(nl->batch);

	if (!size)
		return;
	if (mnl_socket_sendto(nl->req, mnl_nlmsg_batch_head(nl->batch), size) < 0) {
		nl->n_errors++;
		err("netlink: batch send failed: %s", strerror(errno));
	}
	drain_errors(nl);
}

static struct nlmsghdr *batch_put(struct nl *nl, uint16_t type, uint16_t flags)
{
	struct nlmsghdr *nlh = mnl_nlmsg_put_header(mnl_nlmsg_batch_current(nl->batch));

	nlh->nlmsg_type = type;
	nlh->nlmsg_flags = NLM_F_REQUEST | flags;
	nlh->nlmsg_seq = ++nl->seq;
	return nlh;
}

static void batch_next(struct nl *nl)
{
	if (!mnl_nlmsg_batch_next(nl->batch)) {
		/* last message didn't fit: send the rest, reset() moves it to the front */
		batch_send(nl);
		mnl_nlmsg_batch_reset(nl->batch);
	}
}

void nl_batch_begin(struct nl *nl)
{
	nl->n_errors = nl->n_expected = nl->n_refused = 0;
	mnl_nlmsg_batch_reset(nl->batch);
}

unsigned nl_batch_end(struct nl *nl)
{
	batch_send(nl);
	mnl_nlmsg_batch_reset(nl->batch);

	if (nl->n_errors > MAX_LOGGED_ERRORS)
		warn("netlink: %u more errors not shown", nl->n_errors - MAX_LOGGED_ERRORS);
	return nl->n_errors;
}

void nl_route(struct nl *nl, enum nl_op op, const struct route_spec *r)
{
	size_t alen = family_alen(r->family);
	struct nlmsghdr *nlh = batch_put(nl, op == NL_DEL ? RTM_DELROUTE : RTM_NEWROUTE,
	                                 op == NL_DEL ? 0 : NLM_F_CREATE | NLM_F_REPLACE);
	struct rtmsg *rtm = mnl_nlmsg_put_extra_header(nlh, sizeof(*rtm));

	rtm->rtm_family = r->family;
	rtm->rtm_dst_len = r->plen;
	rtm->rtm_src_len = r->src_len;
	rtm->rtm_tos = r->tos;
	rtm->rtm_table = r->table < 256 ? r->table : RT_TABLE_UNSPEC;
	rtm->rtm_protocol = r->proto;
	rtm->rtm_type = op == NL_DEL ? RTN_UNSPEC : r->type;
	rtm->rtm_scope = op == NL_DEL ? RT_SCOPE_NOWHERE :
	                 r->type == RTN_UNICAST && !r->has_gw && !r->nh_id ? RT_SCOPE_LINK :
	                 RT_SCOPE_UNIVERSE;

	mnl_attr_put_u32(nlh, RTA_TABLE, r->table);
	if (r->plen)
		mnl_attr_put(nlh, RTA_DST, alen, r->dst);
	if (r->src_len)
		mnl_attr_put(nlh, RTA_SRC, alen, r->src);
	if (r->metric)
		mnl_attr_put_u32(nlh, RTA_PRIORITY, r->metric);
	if (op != NL_DEL && r->type == RTN_UNICAST) {
		if (r->nh_id) {
			mnl_attr_put_u32(nlh, RTA_NH_ID, r->nh_id);
		} else {
			mnl_attr_put_u32(nlh, RTA_OIF, r->oif);
			if (r->has_gw)
				mnl_attr_put(nlh, RTA_GATEWAY, alen, r->gw);
		}
	}
	batch_next(nl);
}

void nl_rule(struct nl *nl, enum nl_op op, const struct rule_spec *r)
{
	struct nlmsghdr *nlh;
	struct fib_rule_hdr *frh;

	nlh = batch_put(nl, op == NL_DEL ? RTM_DELRULE : RTM_NEWRULE,
			op == NL_DEL ? 0 : NLM_F_CREATE | NLM_F_EXCL);
	frh = mnl_nlmsg_put_extra_header(nlh, sizeof(*frh));
	frh->family = r->family;
	frh->action = FR_ACT_TO_TBL;
	frh->table = r->table < 256 ? r->table : RT_TABLE_UNSPEC;

	mnl_attr_put_u32(nlh, FRA_PRIORITY, r->prio);
	mnl_attr_put_u32(nlh, FRA_FWMARK, r->mark);
	mnl_attr_put_u32(nlh, FRA_FWMASK, r->mask);
	mnl_attr_put_u32(nlh, FRA_TABLE, r->table);
	mnl_attr_put_u8(nlh, FRA_PROTOCOL, r->proto);

	batch_next(nl);
}

/* at most MAX_NH_GROUP * 8 bytes of NHA_GROUP: far below BATCH_LIMIT */
static void put_res_group(struct nlmsghdr *nlh, const struct nexthop_spec *n)
{
	struct nexthop_grp grp[MAX_NH_GROUP] = {};
	unsigned i, cnt = n->n_grp < MAX_NH_GROUP ? n->n_grp : MAX_NH_GROUP;
	struct nlattr *nest;

	for (i = 0; i < cnt; i++) {
		grp[i].id = n->grp[i].id;
		grp[i].weight = n->grp[i].weight - 1;
	}
	mnl_attr_put(nlh, NHA_GROUP, cnt * sizeof(grp[0]), grp);
	mnl_attr_put_u16(nlh, NHA_GROUP_TYPE, NEXTHOP_GRP_TYPE_RES);

	nest = mnl_attr_nest_start(nlh, NHA_RES_GROUP);
	mnl_attr_put_u16(nlh, NHA_RES_GROUP_BUCKETS, n->buckets);
	mnl_attr_put_u32(nlh, NHA_RES_GROUP_IDLE_TIMER, n->timer_idle * NH_HZ);
	mnl_attr_put_u32(nlh, NHA_RES_GROUP_UNBALANCED_TIMER, n->timer_busy * NH_HZ);
	mnl_attr_nest_end(nlh, nest);
}

void nl_nexthop(struct nl *nl, enum nl_op op, const struct nexthop_spec *n)
{
	struct nlmsghdr *nlh;
	struct nhmsg *nhm;

	nlh = batch_put(nl, op == NL_DEL ? RTM_DELNEXTHOP : RTM_NEWNEXTHOP,
			op == NL_DEL ? 0 : op == NL_REPLACE ? NLM_F_REPLACE :
			NLM_F_CREATE | NLM_F_REPLACE);
	nhm = mnl_nlmsg_put_extra_header(nlh, sizeof(*nhm));
	mnl_attr_put_u32(nlh, NHA_ID, n->id);

	/* deletes take a zeroed header and NHA_ID only */
	if (op != NL_DEL) {
		nhm->nh_protocol = n->proto;
		if (n->n_grp) {
			put_res_group(nlh, n);
		} else if (n->blackhole) {
			nhm->nh_family = n->family;
			mnl_attr_put(nlh, NHA_BLACKHOLE, 0, NULL);
		} else {
			nhm->nh_family = n->family;
			mnl_attr_put_u32(nlh, NHA_OIF, n->oif);
			if (n->has_gw)
				mnl_attr_put(nlh, NHA_GATEWAY,
				             n->family == AF_INET ? 4 : 16, n->gw);
		}
	}

	batch_next(nl);
}

/* --- events --- */

int nl_event_fd(struct nl *nl)
{
	return mnl_socket_get_fd(nl->ev);
}

int nl_event_read(struct nl *nl, mnl_cb_t cb, void *data)
{
	int fd = mnl_socket_get_fd(nl->ev);
	bool lost = false;

	for (;;) {
		ssize_t n = recv(fd, recv_buf, sizeof(recv_buf), 0);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno == ENOBUFS) {
				lost = true;
				continue;
			}
			if (errno != EAGAIN)
				err("netlink: event read: %s", strerror(errno));
			break;
		}
		mnl_cb_run(recv_buf, n, 0, 0, cb, data);
	}

	return lost ? -ENOBUFS : 0;
}
