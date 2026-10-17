#ifndef ROUTEBOT_NETIFD_H
#define ROUTEBOT_NETIFD_H

/*
 * Resolve netifd logical interfaces (e.g. "wan") to their L3 device
 * (e.g. "pppoe-wan") over ubus, tracking changes. Without WITH_UBUS every
 * spec is treated as a kernel netdev name.
 */

/* changed() is called (from the uloop) whenever the mapping changes. */
void netifd_init(void (*changed)(void));
void netifd_done(void);

/*
 * NULL: not a netifd interface, use spec as a netdev name.
 * "":   a netifd interface that currently has no L3 device (down).
 * else: the L3 device name.
 */
const char *netifd_l3dev(const char *spec);

#endif
