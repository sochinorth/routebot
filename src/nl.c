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

#include "log.h"
#include "nl.h"

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

#define BATCH_LIMIT	(32 * 1024)
#define RCVBUF_SIZE	(4 * 1024 * 1024)
#define RECV_BUF_SIZE	(64 * 1024)
#define MAX_LOGGED_ERRORS 16

static char recv_buf[RECV_BUF_SIZE] __attribute__((aligned(4)));

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
	unsigned groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR |
			  RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE;
	int one = 1;

	memset(nl, 0, sizeof(*nl));

	nl->req = mnl_socket_open2(NETLINK_ROUTE, SOCK_CLOEXEC);
	if (!nl->req || mnl_socket_bind(nl->req, 0, MNL_SOCKET_AUTOPID) < 0)
		goto fail;
	nl->portid = mnl_socket_get_portid(nl->req);
	set_rcvbuf(nl->req);
	/* both optional: nicer error messages, kernel-side dump filtering */
	mnl_socket_setsockopt(nl->req, NETLINK_EXT_ACK, &one, sizeof(one));
	mnl_socket_setsockopt(nl->req, NETLINK_GET_STRICT_CHK, &one, sizeof(one));

	nl->ev = mnl_socket_open2(NETLINK_ROUTE, SOCK_NONBLOCK | SOCK_CLOEXEC);
	if (!nl->ev)
		goto fail;
	if (attach_event_filter(nl->ev))
		warn("netlink: can't attach event filter: %s", strerror(errno));
	set_rcvbuf(nl->ev);
	if (mnl_socket_bind(nl->ev, groups, MNL_SOCKET_AUTOPID) < 0)
		goto fail;

	nl->batch_buf = malloc(BATCH_LIMIT * 2);
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
	if (nl->req)
		mnl_socket_close(nl->req);
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

	if (mnl_socket_sendto(nl->req, req, req->nlmsg_len) < 0)
		return -errno;

	do {
		n = mnl_socket_recvfrom(nl->req, recv_buf, sizeof(recv_buf));
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		ret = mnl_cb_run(recv_buf, n, seq, nl->portid, cb, data);
		if (ret < 0) {
			/* stray error replies from earlier batches have a different seq */
			if (errno == EPROTO || errno == ESRCH)
				continue;
			return -errno;
		}
	} while (ret != MNL_CB_STOP);

	return 0;
}

int nl_dump_nexthops(struct nl *nl, mnl_cb_t cb, void *data)
{
	char buf[128] __attribute__((aligned(4)));
	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
	struct nhmsg *nhm;
	int ret;

	nlh->nlmsg_type = RTM_GETNEXTHOP;
	/* strict checking: everything but the family must be zero */
	nhm = mnl_nlmsg_put_extra_header(nlh, sizeof(*nhm));
	nhm->nh_family = AF_UNSPEC;

	ret = nl_dump(nl, nlh, cb, data);
	/* no nexthop objects in this kernel */
	if (ret == -EINVAL)
		ret = -EOPNOTSUPP;
	return ret;
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

struct attr_tb {
	const struct nlattr *tb[32];
};

static int attr_collect(const struct nlattr *a, void *data)
{
	struct attr_tb *t = data;
	unsigned type = mnl_attr_get_type(a);

	if (type < 32)
		t->tb[type] = a;
	return MNL_CB_OK;
}

static void describe_req(const struct nlmsghdr *req, bool capped, char *buf, size_t len)
{
	const char *op;
	struct attr_tb t = {};

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

		mnl_attr_parse(req, sizeof(*rtm), attr_collect, &t);
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

		mnl_attr_parse(req, sizeof(*nhm), attr_collect, &t);
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

		mnl_attr_parse(req, sizeof(*frh), attr_collect, &t);
		snprintf(buf, len, "%s %s prio %u", op,
			 frh->family == AF_INET6 ? "v6" : "v4",
			 t.tb[FRA_PRIORITY] ? mnl_attr_get_u32(t.tb[FRA_PRIORITY]) : 0);
	}
}

static void handle_error(struct nl *nl, const struct nlmsghdr *nlh)
{
	const struct nlmsgerr *e = mnl_nlmsg_get_payload(nlh);
	bool capped = nlh->nlmsg_flags & NLM_F_CAPPED;
	const char *ext = NULL;
	char desc[128];
	int error = -e->error;

	if (!error || error_expected(e->msg.nlmsg_type, error))
		return;

	if (nl->n_errors++ >= MAX_LOGGED_ERRORS)
		return;

	if (nlh->nlmsg_flags & NLM_F_ACK_TLVS) {
		struct attr_tb t = {};
		size_t off = sizeof(*e);

		if (!capped)
			off += e->msg.nlmsg_len - sizeof(e->msg);
		mnl_attr_parse(nlh, off, attr_collect, &t);
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
		ssize_t n = recv(fd, recv_buf, sizeof(recv_buf), MSG_DONTWAIT);
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
		for (nlh = (const struct nlmsghdr *)recv_buf; mnl_nlmsg_ok(nlh, len);
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
	nl->n_errors = 0;
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
	size_t alen = r->family == AF_INET ? 4 : 16;
	struct nlmsghdr *nlh;
	struct rtmsg *rtm;

	nlh = batch_put(nl, op == NL_DEL ? RTM_DELROUTE : RTM_NEWROUTE,
			op == NL_DEL ? 0 : NLM_F_CREATE | NLM_F_REPLACE);
	rtm = mnl_nlmsg_put_extra_header(nlh, sizeof(*rtm));
	rtm->rtm_family = r->family;
	rtm->rtm_dst_len = r->plen;
	rtm->rtm_table = r->table < 256 ? r->table : RT_TABLE_UNSPEC;
	rtm->rtm_protocol = r->proto;

	if (op == NL_DEL) {
		rtm->rtm_scope = RT_SCOPE_NOWHERE;
		rtm->rtm_type = RTN_UNSPEC;
	} else {
		rtm->rtm_type = r->type;
		rtm->rtm_scope = (r->type == RTN_UNICAST && !r->has_gw && !r->nh_id) ?
				 RT_SCOPE_LINK : RT_SCOPE_UNIVERSE;
	}

	mnl_attr_put_u32(nlh, RTA_TABLE, r->table);
	if (r->plen)
		mnl_attr_put(nlh, RTA_DST, alen, r->dst);
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

/* USER_HZ, which is what the kernel takes for nexthop group timers */
#define NH_HZ 100

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
			op == NL_DEL ? 0 : NLM_F_CREATE | NLM_F_REPLACE);
	nhm = mnl_nlmsg_put_extra_header(nlh, sizeof(*nhm));
	mnl_attr_put_u32(nlh, NHA_ID, n->id);

	/* deletes take a zeroed header and NHA_ID only */
	if (op != NL_DEL) {
		nhm->nh_protocol = n->proto;
		if (n->n_grp) {
			put_res_group(nlh, n);
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
