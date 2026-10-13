#ifndef ROUTEBOT_PROBE_H
#define ROUTEBOT_PROBE_H

#include <stdbool.h>
#include <stddef.h>

#include "config.h"

/*
 * Per-group ICMP health checks, pinned to each member device: raw sockets
 * bound to the device (SO_BINDTODEVICE) and marked with probe_mark so the
 * lookup lands in the probe table. Verdicts start optimistic (up).
 */
struct probes;

/* changed() is called (from the uloop) whenever any verdict flips. */
struct probes *probes_new(const struct config *cfg, void (*changed)(void));
void probes_free(struct probes *p);

/*
 * Tell the prober what device d currently resolves to and whether its link is
 * usable. Probing of d pauses while unusable; a netdev change rebinds sockets.
 */
void probes_set_link(struct probes *p, size_t dev, const char *netdev, bool usable);

/* Verdict for member m of group g; always true for groups without probes. */
bool probe_up(const struct probes *p, size_t group, size_t member);

#endif
