# routebot

A small policy-routing daemon for OpenWrt and plain Linux. It routes traffic
through groups of interfaces by fwmark or by destination CIDR lists, and keeps
those routes in sync as links go up and down, gateways change, health probes
fail and config gets reloaded.

A group bundles one or more devices into a resilient ECMP nexthop group.
Members that are down or fail their probes drop out; when no member is left,
the group's traffic is blackholed instead of leaking out another uplink.
Its routes point at the group either way: mostly only the group changes.

Needs kernel 5.13 or newer (resilient nexthop groups).

## What it sets up

Using the example config below, with all members up:

```
$ ip rule
10000:  from all fwmark 0/0xff000000 lookup 10000 proto 233
10001:  from all fwmark 0xfe000000/0xff000000 lookup 10001 proto 233
10002:  from all fwmark 0x10000000/0xff000000 lookup 10002 proto 233
10003:  from all fwmark 0xaa000000/0xff000000 lookup 10003 proto 233
10004:  from all fwmark 0x20000000/0xff000000 lookup 10004 proto 233

$ ip route show table 10004
default nhid 10012 proto 233
	nexthop dev vpn_mullvad_se1 weight 1
	nexthop dev vpn_mullvad_se2 weight 2
	nexthop dev vpn_mullvad_se3 weight 1
blackhole default proto 233 metric 4294967295

$ ip route show table 10000
1.0.0.0/24 nhid 10004 dev vpn_warp_dme proto 233
1.1.1.0/24 nhid 10004 dev vpn_warp_dme proto 233
...

$ ip nexthop show proto 233
id 10012 group 10010/10014,2/10018 type resilient buckets 512 idle_timer 120 unbalanced_timer 600 ...
id 10010 dev vpn_mullvad_se1 scope host proto 233
...
id 10000 blackhole proto 233
id 10001 blackhole proto 233
```

With `pppoe-wan` down, group `wan` holds the blackhole instead of its member,
and its routes drop the traffic:

```
$ ip route show table 10003
blackhole default nhid 10008 dev lo proto 233
blackhole default proto 233 metric 4294967295

$ ip nexthop show id 10008
id 10008 group 10000 type resilient buckets 1024 idle_timer 120 unbalanced_timer 600 ...
```

| | table | rule prio | matches |
|---|---|---|---|
| CIDR lists | `table_id` | `rule_prio` | unmarked traffic |
| probes | `table_id + 1` | `rule_prio + 1` | `probe_mark` |
| group N | `table_id + 1 + N` | `rule_prio + 1 + N` | the group's `fwmark` |

N is the group's 1-based position in the config. Every rule is gated on a
distinct fwmark, so their order doesn't matter.

- **Unmarked traffic** looks up the CIDR table. Addresses not in any list fall
  through to the next rule, normally `main`.
- **Marked traffic** goes to its group's table, which holds a default route
  through the group, and behind it a blackhole default with the highest
  metric there is. The kernel deletes a group whose last member's link goes
  down, and every route on it, before routebot hears of it: marked traffic
  is dropped then rather than falling through to `main`, until routebot
  puts the group back (CIDR traffic does fall through for that moment).
- **Probe traffic** only comes from routebot itself (see Probes).

Groups are nexthop objects over one nexthop per member device and family.
Ids start at `nexthop_id` and come in blocks of four: the blackhole nexthops
get `nexthop_id + f`, device d gets `nexthop_id + 2 + 4d + f` and group g
gets `nexthop_id + 4 + 4g + f`, with d and g 0-based in order of first
appearance and f the family (0 = v4, 1 = v6). Each id depends only on its own
position, so adding or removing a group at the end doesn't renumber the rest.

Every group exists at all times, per family: with its usable members, or
with the blackhole nexthop of its family when none is left (the kernel
allows a blackhole only on its own). Routes point at the group whatever its
members, so a member leaving or joining, and a group coming back, is a
single group replace with no route rewritten. When the last member's link
goes down the kernel deletes the group behind routebot's back, with its
routes: so a group left with none of its members (going dark, or on to
other members) is set again with its routes, gone or not. A link that went
down and came back before routebot looked has everything re-sent.

Everything is applied for both IPv4 and IPv6. Every rule, route and nexthop is
tagged with `rt_proto`, so routebot can clean up after itself. On exit it
removes all of it, and on startup it removes anything left behind by a crash.
It refuses to start if a nexthop id in its range (`nexthop_id` to the
last device or group) belongs to someone else.

## Configuration

routebot reads `/etc/config/routebot` in UCI format. Use `-c` to point it at
another file.

```
config routebot
	option fwmask      '0xff000000'  # routebot's slice of the fwmark
	option table_id    '10000'       # CIDR table; +1 probes; +1+N group N
	option rule_prio   '10000'       # CIDR rule; +1 probes; +1+N group N
	option gw_table    'main'        # where gateways are learned from
	option rt_proto    '233'         # protocol tag on everything routebot owns
	option nexthop_id  '10000'       # nexthop ids: from this on (>= 1)
	option probe_mark  '0xfe'        # fwmark reserved for probes
	option buckets     '1024'        # resilient group defaults,
	option timer_idle  '120'         #   overridable per group (seconds)
	option timer_busy  '600'         #   0 = never force

config group 'vpn_warp_dme'          # N = 1; device is the section name
	option fwmark '0x10'             # shifted into fwmask -> 0x10000000

config group 'wan'                   # N = 2
	list device 'wan'                # netifd interface -> pppoe-wan
	option fwmark '0xaa'

config group 'vpn_mullvad_se'        # N = 3
	list device 'vpn_mullvad_se1'
	list device 'vpn_mullvad_se2:2'  # weight 2
	list device 'vpn_mullvad_se3'
	option fwmark '0x20'
	option probe          '10.64.0.1'
	option probe6         'fc00:bbbb:bbbb:bb01::1'
	option probe_timer    '1'        # seconds, fractions allowed
	option probe_count    '3'
	option buckets        '512'

config rule 'as13335_warp'
	option group 'vpn_warp_dme'
	list cidrset '/tmp/routebot/as13335.lst'

config rule 'misc'
	option group 'vpn_mullvad_se'
	list cidrset '/etc/routebot.d/misc/*'
```

**Groups**
- `device` entries name a netifd interface or a Linux device, optionally with
  a `:weight` (1..256, default 1). A netifd interface (`wan`) is followed to
  its current L3 device (`pppoe-wan`) over ubus; any other name is taken as a
  Linux device. Without any entry, the section name is the device.
- A device may belong to several groups.
- `fwmark` is optional. Without it, the group gets no table or rule of its own
  and can only be used as a target for rules.
- A member is usable while its link is up with carrier, it has a gateway (or
  is point-to-point / no-ARP), and its probes pass.

**Gateways**
- routebot learns gateways from the default routes in `gw_table`. On a group
  with a single device, set `option gateway` / `gateway6` to pin one instead.
- Point-to-point and no-ARP links (wg, tun, ppp) work without a gateway. Any
  other member is left out until it has one.

**Probes**
- With `probe` / `probe6` set, routebot pings that address through each member
  separately every `probe_timer` (default 1s, at least 0.1s), which is also
  the reply timeout. `probe_count` (default 3) losses in a row take a member
  out; the same number of replies brings it back.
- With only `probe` set, its verdict applies to both families.
- Probes start out optimistic: after startup or a reload every member counts
  as up until it fails `probe_count` times.
- Probes are bound to their member device and marked with `probe_mark`, which
  selects the probe table: one default route per probed device, kept whether
  the member is healthy or not. Dead members keep being probed, even while the
  group is blackholed.
- Set `rp_filter` to 0 on member devices. Strict mode (1) drops the replies,
  and so does loose mode (2) when the probe address is covered by a
  blackholed CIDR list. routebot warns about it.

**Failover and stickiness**
- Each group hashes flows into `buckets` buckets spread across its members.
  When a member drops out, only its buckets move; flows on the others stay.
- When a member comes back, buckets idle for `timer_idle` seconds move back to
  it. Buckets still busy after `timer_busy` seconds move anyway, breaking the
  flows in them. Keep `timer_busy` above `timer_idle`, or 0 to never force.
- `buckets` can't be changed in place: changing it re-creates the group on
  reload. Its prefix routes become plain blackholes first and point at the
  group again after, so its traffic is dropped meanwhile, never leaked.
- Which flow lands in which bucket is the kernel's multipath hash.
  `net.ipv4.fib_multipath_hash_policy=0` (the default, L3) keeps each
  client-destination pair on one exit. Policy 3 with
  `net.ipv4.fib_multipath_hash_fields=0x0001` (source IP only) pins each
  client to one exit. IPv6 has the same knobs under `net.ipv6`.

**Rules**
- `group` names the group the rule's CIDRs are routed through.
- `cidrset` entries are globs. A glob that matches no files is not an error.
- If a CIDR appears in more than one rule, the first rule in the file wins,
  with a warning.

**List files** contain one CIDR per line, IPv4 or IPv6. A `#` starts a comment.
Host bits are masked off, and invalid lines are skipped with a warning.

```
# generated by some script
1.0.0.0/24
1.1.1.0/24   # trailing comments are fine
2606:4700::/32
```

### Upgrading from 0.1

- `config interface` is now `config group`; use `list device` for its
  devices (`option device` still works).
- Rules take `option group` instead of `option iface`.
- `iface_prio` is gone: the CIDR rule moved to `rule_prio`, groups follow at
  `rule_prio + 2`. Default `rule_prio` is now 10000.
- Group tables moved from `table_id + N` to `table_id + 1 + N`.

routebot refuses the old options with an error naming the replacement.

## Running

```
routebot [-c config] [-v] [-q]
```

| Signal | Effect |
|---|---|
| `SIGHUP` | Reload the config and list files, and apply only what changed. If the new config is invalid, the old one stays in place. |
| `SIGTERM`, `SIGINT` | Remove everything routebot installed, then exit. |

On OpenWrt use `service routebot start|reload|stop`. Changing the UCI config
triggers a reload automatically.

Each sync logs what it touched, e.g. a member failing its probes:

```
routebot: info: vpn_mullvad_se: member vpn_mullvad_se2 probe down
routebot: info: vpn_mullvad_se: v4 via vpn_mullvad_se1, vpn_mullvad_se3
routebot: info: sync (probe): 0 routes set, 0 deleted, 1 nexthops set, 0 deleted, 0 rules added, 0 deleted
```

## Building

routebot depends on [libubox](https://git.openwrt.org/project/libubox.git),
[libuci](https://git.openwrt.org/project/uci.git),
[libubus](https://git.openwrt.org/project/ubus.git) and
[libmnl](https://netfilter.org/projects/libmnl/). Configure with
`-DWITH_UBUS=OFF` to build without libubus; device names are then always
Linux devices.

### OpenWrt (SDK)

```
echo "src-link routebot /path/to/routebot/openwrt" >> feeds.conf
./scripts/feeds update -a
./scripts/feeds install routebot
make package/routebot/compile
```

### Generic Linux

```
cmake -B build -DCMAKE_PREFIX_PATH=/where/libubox/uci/ubus/are/installed
cmake --build build
```

## Testing

`tests/netns.sh` runs an end-to-end test in a throwaway network namespace. It
needs no root, only unprivileged user namespaces.

```
sh tests/netns.sh build/routebot
```

`tests/gate.sh` is what every change has to pass: a clean ASan+UBSan build
(warnings counted), unit tests (`tests/unit/test_*.c`, run by
ctest), `tests/netns.sh` on the sanitized build with leaks fatal, a clean
release build benchmarked against `tests/bench/baseline.json`, and a clean
cross build with the OpenWrt SDK. Point `HOSTDEPS` and `OPENWRT_SDK` at the
host libraries and the SDK.

### Benchmark

```
tests/bench/bench.sh build-release/routebot out.json
python3 -I tests/bench/compare.py tests/bench/baseline.json out.json
```

`bench.sh` runs an optimized, unsanitized build in a network namespace
against a synthetic but realistic setup, and measures memory and the cost of
each unit of work. `genlists.py` generates the lists, the same bytes every
time: rule `big` (group `pool`, 3 veths with weights 1,2,1, gateways from
main, 512 buckets) with ~150k IPv4 and ~20k IPv6 prefixes in 3 files, rule
`asn` (group `warp`, a NOARP dummy) with 4.5k prefixes of which 5% are also
in `big`, rule `misc` (group `wan`, a veth) over 10 files of 500, and group
`pool2` (2 dummies) without rules. The lists carry duplicates, host bits,
invalid lines, comments and stray whitespace. There are no probes: they need
far ends and are timing-dependent. A private `ubusd` stands in for OpenWrt's,
without netifd.

Memory (VmRSS, RssAnon, VmHWM, and the live heap) is sampled at `startup`,
`after_events`, `after_reload` (one no-op reload), `after_10_reloads`, at
the `end`, at `exit` (VmHWM and heap only) and after `restart_dirty`. Units,
each repeated `BENCH_N` times (50), report allocations, bytes allocated and
CPU per unit:

| unit | what happens |
|---|---|
| `startup` | exec until idle after "running" (once) |
| `restart_dirty` | the same, after a routebot with everything installed was killed with SIGKILL: the flush, then a full install (once); the state must equal a clean start's |
| `link_noop` | an unrelated dummy link is created and deleted |
| `member_flip` | a `pool` member loses its default routes and gets them back: group replace, no prefix route touched |
| `blackhole_flip` | `wan` loses its default routes and gets them back: its groups hold the blackhole meanwhile; its ~5k prefixes are set again going there, left alone coming back |
| `link_flap` | a `pool` member goes down and up in one batch: every route, nexthop and rule is re-sent |
| `reload_noop` | SIGHUP, nothing changed |
| `reload_small` | SIGHUP after a misc file changed by 100 lines each way |

Allocations are counted by `mallocstat.c`, an `LD_PRELOAD` shim given to
routebot alone (it drops itself from the environment at start) that keeps its
counters in a shared file. After each step the bench waits until routebot is
idle: counters and CPU time unchanged for 300 ms, routebot in `epoll_wait`,
no signal pending and no unread netlink data. `shutdown` (SIGTERM at the
`end` until exit: the flush) reports allocations, CPU from the shim's record
at exit, and wall time; nothing may be left behind. `validate.sh`
cross-checks the shim against glibc's mtrace and strace and lists the big
allocations with file:line.

`compare.py` fails on a broken run, a different workload, or a regression of
more than 10% in memory (per phase) or in allocations or bytes per unit,
ignoring regressions below 64 KiB, 2 allocations or 1 KiB per unit. CPU and
wall time are shown, never gated: they are noisy. The numbers come from
glibc on the build host, not musl on a router: absolute RSS differs there
(glibc's `qsort` allocates a temporary copy of the array, musl's doesn't, and
the allocators retain memory differently), so compare runs with each other,
not with a router.

## License

MIT
