#ifndef ROUTEBOT_NL_H
#define ROUTEBOT_NL_H

#include <stdbool.h>
#include <stdint.h>

#include <libmnl/libmnl.h>

/* A request the kernel refused (an unexpected error), as far as it says. */
struct nl_refused {
	uint16_t type;		/* RTM_NEWNEXTHOP, RTM_NEWROUTE, ... */
	uint8_t family;		/* the request's */
	uint32_t id;		/* nexthops: NHA_ID */
	uint32_t table;		/* routes: the table */
	uint32_t metric;	/* routes: RTA_PRIORITY, 0 if none */
	int error;		/* errno */
};

struct nl {
	struct mnl_socket *req;		/* writes, blocking */
	/*
	 * Dumps, blocking: their own socket, so that a dump's callback may
	 * queue writes (sent on req when the batch fills) between datagrams.
	 */
	struct mnl_socket *dump;
	struct mnl_socket *ev;		/* multicast events, non-blocking */
	uint32_t seq;

	char *batch_buf;
	struct mnl_nlmsg_batch *batch;
	unsigned n_errors;		/* unexpected errors since nl_batch_begin() */
	unsigned n_expected;		/* expected ones: nothing to delete, rule exists */
	/* the n_errors whose request came back whole (all, memory allowing) */
	struct nl_refused *refused;
	unsigned n_refused, cap_refused;
};

struct route_spec {
	uint8_t family;
	uint8_t plen;
	uint8_t type;		/* RTN_UNICAST or RTN_BLACKHOLE */
	uint8_t proto;
	bool has_gw;
	uint32_t table;
	uint32_t nh_id;		/* RTN_UNICAST via a nexthop object; oif/gw unused */
	uint32_t metric;	/* 0 = kernel default */
	int oif;
	uint8_t dst[16];
	uint8_t gw[16];
};

/*
 * Everything the kernel matches a route delete on that tells two routes of
 * one protocol apart: v4 by table, dst, tos and metric, v6 by table, dst,
 * source prefix and metric (a v6 multipath route goes as a whole). Type,
 * scope and nexthops are left out, so they match anything; where two routes
 * still share a key, each delete takes one.
 */
struct route_key {
	uint8_t family;
	uint8_t dst_len;
	uint8_t src_len;	/* v6 only */
	uint8_t tos;		/* v4 only */
	uint32_t table;
	uint32_t metric;	/* 0 = any (v4: the lowest first) */
	uint8_t dst[16];
	uint8_t src[16];
};

/*
 * A route as the kernel reports it: spec plus the key parts routebot never
 * sets itself (v4 tos, v6 source prefix), which leftovers may carry.
 */
struct kroute {
	struct route_spec r;	/* type as reported: a route on a group that holds
				   the blackhole nexthop is RTN_BLACKHOLE with nh_id */
	uint8_t tos;		/* v4 only */
	uint8_t src_len;	/* v6 only */
	uint8_t src[16];
	bool multipath;		/* RTA_MULTIPATH without RTA_NH_ID: oif/gw unset */
};

/* The key a delete of k matches on; metric is k's own (never "any"). */
void kroute_key(const struct kroute *k, struct route_key *out);

#define MAX_NH_GROUP 32

struct nh_grp_entry {
	uint32_t id;
	uint16_t weight;	/* 1..256 */
};

/*
 * A nexthop object: either a single nexthop (n_grp == 0, family set, oif +
 * optional gateway, or a blackhole) or a resilient group (n_grp > 0, sent
 * as AF_UNSPEC).
 */
struct nexthop_spec {
	uint32_t id;
	uint8_t family;
	uint8_t proto;
	bool blackhole;
	int oif;
	bool has_gw;
	uint8_t gw[16];

	uint16_t n_grp;
	struct nh_grp_entry grp[MAX_NH_GROUP];
	uint16_t buckets;
	uint32_t timer_idle;	/* seconds */
	uint32_t timer_busy;	/* seconds, 0 = never force */
};

struct rule_spec {
	uint8_t family;
	uint8_t proto;
	uint32_t prio;
	uint32_t mark;
	uint32_t mask;
	uint32_t table;
};

enum nl_op {
	NL_SET,		/* create or replace in place */
	NL_DEL,
	NL_REPLACE,	/* nexthops: replace in place, fail (ENOENT) if gone */
};

/*
 * Parse kernel messages (dump replies or notifications) into specs.
 * nl_parse_route: v4/v6 only, RTM_F_CLONED and malformed messages rejected
 * (-1); table from RTA_TABLE, metric 0 if absent; nh_id from RTA_NH_ID;
 * oif and gateway only for RTN_UNICAST without nh_id or multipath (else 0).
 * nl_parse_nexthop: id, proto, family; blackhole; oif and gateway; a group's
 * members (weights 1..256 as in nh_grp_entry), and, for a resilient group,
 * buckets and timers in seconds; any other group type has buckets 0. A group
 * is reported with family AF_UNSPEC. Groups over MAX_NH_GROUP: -1, with id
 * and proto still filled (id 0: no NHA_ID at all).
 * nl_parse_rule: family, proto (FRA_PROTOCOL, 0 if absent), prio, mark,
 * mask, table. Returns 0 for a plain FR_ACT_TO_TBL rule without other
 * selectors, 1 for any other rule (iif, oif, src, dst, invert, goto, ...),
 * with the fields filled as far as they go, -1 for malformed or non-v4/v6.
 */
int nl_parse_route(const struct nlmsghdr *nlh, struct kroute *out);
int nl_parse_nexthop(const struct nlmsghdr *nlh, struct nexthop_spec *out);
int nl_parse_rule(const struct nlmsghdr *nlh, struct rule_spec *out);

int nl_open(struct nl *nl);
void nl_close(struct nl *nl);

/*
 * Run a dump. req is built by the caller (type, family header, filter
 * attributes); flags and seq are filled in here. cb gets every message.
 * Returns 0 or -errno.
 */
int nl_dump(struct nl *nl, struct nlmsghdr *req, mnl_cb_t cb, void *data);

/*
 * Dump all nexthop objects. cb gets each RTM_NEWNEXTHOP message.
 * Returns 0, -errno, or -EOPNOTSUPP if the kernel lacks nexthop objects.
 */
int nl_dump_nexthops(struct nl *nl, mnl_cb_t cb, void *data);

/*
 * Dump routes, filtered in the kernel (NETLINK_GET_STRICT_CHK): family
 * (AF_UNSPEC = both), table (0 = every table), proto (0 = any). cb gets
 * each RTM_NEWROUTE message, RTM_F_CLONED ones included (use nl_parse_route
 * and skip what it rejects). Returns 0 or -errno.
 */
int nl_dump_routes(struct nl *nl, uint8_t family, uint32_t table, uint8_t proto,
                   mnl_cb_t cb, void *data);

/* Dump all v4 and v6 rules. cb gets each RTM_NEWRULE message. Returns 0 or -errno. */
int nl_dump_rules(struct nl *nl, mnl_cb_t cb, void *data);

/*
 * Writes are queued into a batch and sent in large sendmsg() chunks.
 * Requests go without NLM_F_ACK: rtnetlink handles them synchronously
 * inside sendmsg(), so any errors are already queued when it returns and
 * get drained right after each chunk.
 */
void nl_batch_begin(struct nl *nl);
void nl_route(struct nl *nl, enum nl_op op, const struct route_spec *r);
/*
 * By full key, with protocol proto: NL_DEL deletes the route, NL_SET
 * replaces it with a blackhole of the same key (make-before-break for
 * routes routebot has no spec of, e.g. leftovers with a tos or source).
 */
void nl_route_key(struct nl *nl, enum nl_op op, const struct route_key *k, uint8_t proto);
void nl_rule(struct nl *nl, enum nl_op op, const struct rule_spec *r);
/* NL_SET creates or replaces in place, NL_REPLACE only replaces; on delete only id matters. */
void nl_nexthop(struct nl *nl, enum nl_op op, const struct nexthop_spec *n);
/* Returns the number of unexpected errors in this batch. */
unsigned nl_batch_end(struct nl *nl);

/*
 * Event socket: links, v4 and v6 addresses, v4 and v6 routes (default
 * routes only, filtered in the kernel by BPF), v4 and v6 rules, nexthops.
 * nl_event_read returns -ENOBUFS when events were lost, 0 otherwise.
 */
int nl_event_fd(struct nl *nl);
int nl_event_read(struct nl *nl, mnl_cb_t cb, void *data);

#endif
