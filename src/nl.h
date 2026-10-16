#ifndef ROUTEBOT_NL_H
#define ROUTEBOT_NL_H

#include <stdbool.h>
#include <stdint.h>

#include <libmnl/libmnl.h>

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
	/* ids of the nexthop sets among n_errors, but ENOENT (memory allowing) */
	uint32_t *refused;
	unsigned n_refused, cap_refused;
};

/*
 * A route. tos (v4) and a source prefix (v6) routebot never sets, but
 * leftovers may carry them: they are part of a route's key, which a delete
 * matches on along with family, table, dst and metric.
 */
struct route_spec {
	uint8_t family;
	uint8_t plen;
	uint8_t type;		/* RTN_UNICAST or RTN_BLACKHOLE; as reported, a route on a
				   group that holds the blackhole nexthop is RTN_BLACKHOLE */
	uint8_t proto;
	bool has_gw;
	uint8_t tos;		/* v4 only */
	uint8_t src_len;	/* v6 only */
	bool multipath;		/* reported RTA_MULTIPATH without RTA_NH_ID: oif/gw unset */
	uint32_t table;
	uint32_t nh_id;		/* RTN_UNICAST via a nexthop object; oif/gw unused */
	uint32_t metric;	/* 0 = kernel default */
	int oif;
	uint8_t dst[16];
	uint8_t src[16];
	uint8_t gw[16];
};

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
int nl_parse_route(const struct nlmsghdr *nlh, struct route_spec *out);
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
 * Dump every v4 and v6 object of type RTM_GETNEXTHOP, RTM_GETRULE or
 * RTM_GETROUTE; cb gets each message. Routes are filtered in the kernel
 * (NETLINK_GET_STRICT_CHK) by table (0 = every table) and proto (0 = any),
 * RTM_F_CLONED ones included (nl_parse_route rejects them). Returns 0 or
 * -errno, -EOPNOTSUPP for nexthops if the kernel lacks nexthop objects.
 */
int nl_dump_type(struct nl *nl, uint16_t type, uint32_t table, uint8_t proto, mnl_cb_t cb,
                 void *data);

/*
 * Writes are queued into a batch and sent in large sendmsg() chunks.
 * Requests go without NLM_F_ACK: rtnetlink handles them synchronously
 * inside sendmsg(), so any errors are already queued when it returns and
 * get drained right after each chunk.
 */
void nl_batch_begin(struct nl *nl);
/* A delete matches r's key and proto, any type and scope. */
void nl_route(struct nl *nl, enum nl_op op, const struct route_spec *r);
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
