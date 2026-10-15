# routebot

A small policy-routing daemon for OpenWrt and plain Linux. It routes traffic
through groups of interfaces by fwmark or by destination CIDR lists, and keeps
those routes in sync as links go up and down, gateways change, health probes
fail and config gets reloaded.

A group bundles one or more devices into a resilient ECMP nexthop group.
Members that are down or fail their probes drop out; when no member is left,
the group's traffic is blackholed instead of leaking out another uplink.

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
default nhid 10011 proto 233
	nexthop dev vpn_mullvad_se1 weight 1
	nexthop dev vpn_mullvad_se2 weight 2
	nexthop dev vpn_mullvad_se3 weight 1

$ ip route show table 10000
1.0.0.0/24 nhid 10003 dev vpn_warp_dme proto 233
1.1.1.0/24 nhid 10003 dev vpn_warp_dme proto 233
...

$ ip nexthop show proto 233
id 10011 group 10009/10013,2/10017 type resilient buckets 512 idle_timer 120 unbalanced_timer 600 ...
id 10009 dev vpn_mullvad_se1 scope host proto 233
...
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
- **Marked traffic** goes to its group's table, which holds a single default
  route through the group.
- **Probe traffic** only comes from routebot itself (see Probes).

Groups are nexthop objects over one nexthop per member device and family.
Ids come in blocks of four: device d gets `nexthop_id + 1 + 4d + f` and group
g gets `nexthop_id + 3 + 4g + f`, with d and g 0-based in order of first
appearance and f the family (0 = v4, 1 = v6). Each id depends only on its own
position, so adding or removing a group at the end doesn't renumber the rest.
Routes point at the group, so a member leaving or joining is a single group
replace with no route rewritten.

Everything is applied for both IPv4 and IPv6. Every rule, route and nexthop is
tagged with `rt_proto`, so routebot can clean up after itself. On exit it
removes all of it, and on startup it removes anything left behind by a crash.
It refuses to start if a nexthop id in its range belongs to someone else.

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
	option nexthop_id  '10000'       # base for nexthop object ids
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
- `buckets` can't be changed in place: changing it recreates the group, and
  its routes, on reload.
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

## License

MIT
