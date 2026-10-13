#ifndef ROUTEBOT_NL_H
#define ROUTEBOT_NL_H

#include <stdbool.h>
#include <stdint.h>

#include <libmnl/libmnl.h>

struct nl {
	struct mnl_socket *req;		/* dumps and writes, blocking */
	struct mnl_socket *ev;		/* multicast events, non-blocking */
	uint32_t portid;
	uint32_t seq;

	char *batch_buf;
	struct mnl_nlmsg_batch *batch;
	unsigned n_errors;		/* unexpected errors since nl_batch_begin() */
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

#define MAX_NH_GROUP 32

struct nh_grp_entry {
	uint32_t id;
	uint16_t weight;	/* 1..256 */
};

/*
 * A nexthop object: either a single device nexthop (n_grp == 0, family set,
 * oif + optional gateway) or a resilient group (n_grp > 0, family AF_UNSPEC).
 */
struct nexthop_spec {
	uint32_t id;
	uint8_t family;
	uint8_t proto;
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
};

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
 * Writes are queued into a batch and sent in large sendmsg() chunks.
 * Requests go without NLM_F_ACK: rtnetlink handles them synchronously
 * inside sendmsg(), so any errors are already queued when it returns and
 * get drained right after each chunk.
 */
void nl_batch_begin(struct nl *nl);
void nl_route(struct nl *nl, enum nl_op op, const struct route_spec *r);
void nl_rule(struct nl *nl, enum nl_op op, const struct rule_spec *r);
/* NL_SET creates or replaces in place; on delete only id matters. */
void nl_nexthop(struct nl *nl, enum nl_op op, const struct nexthop_spec *n);
/* Returns the number of unexpected errors in this batch. */
unsigned nl_batch_end(struct nl *nl);

/* Event socket: returns -ENOBUFS when events were lost, 0 otherwise. */
int nl_event_fd(struct nl *nl);
int nl_event_read(struct nl *nl, mnl_cb_t cb, void *data);

#endif
