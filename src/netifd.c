#include <stddef.h>

#include "netifd.h"

#ifdef WITH_UBUS

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <libubox/blobmsg.h>
#include <libubox/uloop.h>
#include <libubus.h>

#include "log.h"

#define RETRY_MS	3000
#define DEBOUNCE_MS	200
#define INVOKE_TIMEOUT_MS 3000

struct ent {
	char *name;
	char *l3dev;	/* "" while the interface has no L3 device */
};

struct map {
	struct ent *e;	/* sorted by name */
	size_t n;
};

static struct {
	void (*changed)(void);
	struct ubus_context *ctx;
	struct ubus_context *dead;	/* lost, freed from the next timer run */
	struct ubus_event_handler ev_iface;
	struct ubus_event_handler ev_obj;
	struct uloop_timeout connect;	/* (re)connect retries, deferred free */
	struct uloop_timeout dump;	/* debounced / retried dump */
	struct map map;
	bool warned;
} nd;

static void map_free(struct map *m)
{
	for (size_t i = 0; i < m->n; i++) {
		free(m->e[i].name);
		free(m->e[i].l3dev);
	}
	free(m->e);
	m->e = NULL;
	m->n = 0;
}

static int ent_cmp(const void *a, const void *b)
{
	return strcmp(((const struct ent *)a)->name, ((const struct ent *)b)->name);
}

static bool map_eq(const struct map *a, const struct map *b)
{
	if (a->n != b->n)
		return false;
	for (size_t i = 0; i < a->n; i++)
		if (strcmp(a->e[i].name, b->e[i].name) ||
		    strcmp(a->e[i].l3dev, b->e[i].l3dev))
			return false;
	return true;
}

/* takes ownership of m */
static void map_set(struct map *m)
{
	if (map_eq(&nd.map, m)) {
		map_free(m);
		return;
	}
	map_free(&nd.map);
	nd.map = *m;
	for (size_t i = 0; i < nd.map.n; i++)
		debug("netifd: %s -> %s", nd.map.e[i].name,
		      *nd.map.e[i].l3dev ? nd.map.e[i].l3dev : "(none)");
	if (nd.changed)
		nd.changed();
}

static int map_add(struct map *m, const char *name, const char *l3dev)
{
	struct ent *e = realloc(m->e, (m->n + 1) * sizeof(*e));

	if (!e)
		return -1;
	m->e = e;
	e = &m->e[m->n];
	e->name = strdup(name);
	e->l3dev = strdup(l3dev);
	if (!e->name || !e->l3dev) {
		free(e->name);
		free(e->l3dev);
		return -1;
	}
	m->n++;
	return 0;
}

enum { D_IFACES, __D_MAX };
static const struct blobmsg_policy dump_policy[__D_MAX] = {
	[D_IFACES] = { "interface", BLOBMSG_TYPE_ARRAY },
};

enum { I_NAME, I_L3DEV, __I_MAX };
static const struct blobmsg_policy iface_policy[__I_MAX] = {
	[I_NAME] = { "interface", BLOBMSG_TYPE_STRING },
	[I_L3DEV] = { "l3_device", BLOBMSG_TYPE_STRING },
};

struct dump_req {
	struct map m;
	bool ok;
};

static void dump_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct dump_req *d = req->priv;
	struct blob_attr *tb[__D_MAX], *cur;
	size_t rem;

	if (!msg)
		return;
	blobmsg_parse(dump_policy, __D_MAX, tb, blob_data(msg), blob_len(msg));
	if (!tb[D_IFACES])
		return;

	map_free(&d->m);
	d->ok = true;
	blobmsg_for_each_attr(cur, tb[D_IFACES], rem) {
		struct blob_attr *it[__I_MAX];

		if (blobmsg_type(cur) != BLOBMSG_TYPE_TABLE)
			continue;
		blobmsg_parse(iface_policy, __I_MAX, it, blobmsg_data(cur),
		              blobmsg_data_len(cur));
		if (!it[I_NAME])
			continue;
		if (map_add(&d->m, blobmsg_get_string(it[I_NAME]),
		            it[I_L3DEV] ? blobmsg_get_string(it[I_L3DEV]) : "")) {
			err("out of memory");
			d->ok = false;
			return;
		}
	}
}

static void dump(void)
{
	struct dump_req d = {};
	uint32_t id;
	int ret;

	if (!nd.ctx)
		return;
	ret = ubus_lookup_id(nd.ctx, "network.interface", &id);
	if (ret) {
		/* netifd not (yet) there; ubus.object.add will tell us */
		debug("netifd: lookup network.interface: %s", ubus_strerror(ret));
		return;
	}
	ret = ubus_invoke(nd.ctx, id, "dump", NULL, dump_cb, &d, INVOKE_TIMEOUT_MS);
	/* the connection may have died during the nested loop */
	if (!nd.ctx) {
		map_free(&d.m);
		return;
	}
	if (ret || !d.ok) {
		warn("netifd: network.interface dump failed: %s, retrying",
		     ret ? ubus_strerror(ret) : "bad reply");
		map_free(&d.m);
		uloop_timeout_set(&nd.dump, RETRY_MS);
		return;
	}

	if (d.m.n > 1)
		qsort(d.m.e, d.m.n, sizeof(*d.m.e), ent_cmp);
	map_set(&d.m);
}

static void dump_timer_cb(struct uloop_timeout *t)
{
	dump();
}

static void schedule_dump(void)
{
	uloop_timeout_set(&nd.dump, DEBOUNCE_MS);
}

static void iface_ev_cb(struct ubus_context *ctx, struct ubus_event_handler *ev,
			const char *type, struct blob_attr *msg)
{
	debug("netifd: event %s", type);
	schedule_dump();
}

enum { O_PATH, __O_MAX };
static const struct blobmsg_policy obj_policy[__O_MAX] = {
	[O_PATH] = { "path", BLOBMSG_TYPE_STRING },
};

static void obj_ev_cb(struct ubus_context *ctx, struct ubus_event_handler *ev,
                      const char *type, struct blob_attr *msg)
{
	struct blob_attr *tb[__O_MAX];

	blobmsg_parse(obj_policy, __O_MAX, tb, blob_data(msg), blob_len(msg));
	if (tb[O_PATH] && !strcmp(blobmsg_get_string(tb[O_PATH]), "network.interface")) {
		debug("netifd: network.interface (re)appeared");
		schedule_dump();
	}
}

static void connection_lost(struct ubus_context *ctx)
{
	struct map empty = {};

	warn("ubus: connection lost, reconnecting");
	/* we're inside libubus here; free the context from the timer */
	uloop_fd_delete(&ctx->sock);
	nd.dead = ctx;
	nd.ctx = NULL;
	nd.warned = true;
	uloop_timeout_cancel(&nd.dump);
	uloop_timeout_set(&nd.connect, RETRY_MS);
	map_set(&empty);
}

static int register_ev(struct ubus_event_handler *ev, ubus_event_handler_t cb,
                       const char *pattern)
{
	int ret;

	memset(ev, 0, sizeof(*ev));
	ev->cb = cb;
	ret = ubus_register_event_handler(nd.ctx, ev, pattern);
	if (ret)
		err("ubus: register %s handler: %s", pattern, ubus_strerror(ret));
	return ret;
}

static void connect_cb(struct uloop_timeout *t)
{
	if (nd.dead) {
		ubus_free(nd.dead);
		nd.dead = NULL;
	}

	/* ROUTEBOT_UBUS_SOCKET: testing only, NULL means the default socket */
	nd.ctx = ubus_connect(getenv("ROUTEBOT_UBUS_SOCKET"));
	if (!nd.ctx) {
		if (!nd.warned)
			warn("ubus: cannot connect, retrying every %d seconds",
			     RETRY_MS / 1000);
		nd.warned = true;
		uloop_timeout_set(t, RETRY_MS);
		return;
	}
	nd.ctx->connection_lost = connection_lost;
	ubus_add_uloop(nd.ctx);

	if (register_ev(&nd.ev_obj, obj_ev_cb, "ubus.object.add") ||
	    register_ev(&nd.ev_iface, iface_ev_cb, "network.interface")) {
		ubus_free(nd.ctx);
		nd.ctx = NULL;
		uloop_timeout_set(t, RETRY_MS);
		return;
	}
	if (nd.warned)
		info("ubus: connected");
	nd.warned = false;

	/* handlers first, so no change between them and the dump is missed */
	dump();
}

/*
 * Needs uloop_init() done. Connects and dumps synchronously so the mapping
 * is there before the first config resolve; changed() is only called for
 * later changes, never from here.
 */
void netifd_init(void (*changed)(void))
{
	nd.connect.cb = connect_cb;
	nd.dump.cb = dump_timer_cb;
	connect_cb(&nd.connect);
	nd.changed = changed;
}

void netifd_done(void)
{
	uloop_timeout_cancel(&nd.connect);
	uloop_timeout_cancel(&nd.dump);
	if (nd.ctx)
		ubus_free(nd.ctx);
	if (nd.dead)
		ubus_free(nd.dead);
	nd.ctx = nd.dead = NULL;
	map_free(&nd.map);
	nd.changed = NULL;
}

const char *netifd_l3dev(const char *spec)
{
	struct ent key = { .name = (char *)spec }, *e;

	if (!nd.map.n)
		return NULL;
	e = bsearch(&key, nd.map.e, nd.map.n, sizeof(*e), ent_cmp);
	return e ? e->l3dev : NULL;
}

#else

void netifd_init(void (*changed)(void))
{
}

void netifd_done(void)
{
}

const char *netifd_l3dev(const char *spec)
{
	return NULL;
}

#endif
