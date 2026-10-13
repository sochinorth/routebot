# routebot

A small policy-routing daemon for OpenWrt and plain Linux. It routes traffic
to specific interfaces by fwmark or by destination CIDR lists, and keeps those
routes in sync as interfaces go up and down, gateways change and config gets
reloaded.

If an interface is down, routebot blackholes its traffic instead of letting it
leak out another uplink.

## What it sets up

Using the example config below, with all members up:

```
$ ip rule
10000:  from all fwmark 0/0xff000000 lookup 10000 proto 233
10001:  from all fwmark 0xfe000000/0xff000000 lookup 10001 proto 233
10002:  from all fwmark 0x10000000/0xff000000 lookup 10002 proto 233
...

$ ip route show table 10002
default nhid 10001 proto 233
```

- **Unmarked traffic** looks up the CIDR table (`table_id`, rule at
  `rule_prio`). Addresses not in any list fall through to the next rule,
  normally `main`.
- **Probe traffic** (`probe_mark`) uses the probe table (`table_id + 1`, rule
  at `rule_prio + 1`), which routebot uses to health-check each member.
- **Marked traffic** goes to its group's table (`table_id + 1 + N`, rule at
  `rule_prio + 1 + N`, N being the group's 1-based position), which holds a
  single default route through the group.

Each group is a resilient ECMP nexthop group over its member devices. A member
drops out while its link is down or its probes fail; when no member is usable,
the group's routes become blackholes instead of leaking out another uplink.
Resilient groups need kernel 5.13 or newer.

Everything is applied for both IPv4 and IPv6. Every rule, route and nexthop is
tagged with `rt_proto`, so routebot can clean up after itself. On exit it
removes all of it, and on startup it removes anything left behind by a crash.

## Configuration

routebot reads `/etc/config/routebot` in UCI format. Use `-c` to point it at
another file.

```
config routebot
	option fwmask      '0xff000000'  # routebot's slice of the fwmark
	option table_id    '10000'       # CIDR table; +1 probe; +1+N group N
	option rule_prio   '10000'       # CIDR rule; +1 probe; +1+N group N
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
	option device 'pppoe-wan'
	option fwmark '0xaa'

config group 'vpn_mullvad_se'        # N = 3
	list device 'vpn_mullvad_se1'
	list device 'vpn_mullvad_se2:2'  # weight 2
	list device 'vpn_mullvad_se3'
	option fwmark '0x20'
	option probe          '10.64.0.1'
	option probe6         'fc00:bbbb:bbbb:bb01::1'
	option probe_interval '1'        # seconds, fractions allowed
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
  Linux device. Without any entry, the section name is the device. A device
  may belong to several groups.
- `fwmark` is optional. Without it, the group gets no rule of its own and can
  only be used as a target for rules.
- `buckets`, `timer_idle` and `timer_busy` tune the resilient group (see
  `ip-nexthop(8)`); `timer_busy` should exceed `timer_idle`.

**Gateways**
- routebot learns gateways from the default routes in `gw_table`. On a group
  with a single device, set `option gateway` / `gateway6` to pin one instead.
- Point-to-point and no-ARP links (wg, tun, ppp) work without a gateway. Any
  other member is left out until it has one.

**Probes**
- With `probe` / `probe6` set, routebot pings that address through each member
  separately every `probe_interval` (default 1s, at least 0.1s).
  `probe_count` (default 3) consecutive losses take a member out, the same
  number of replies in a row bring it back.
- Set `rp_filter` to 0 on member devices. Strict mode (1) drops the replies,
  and so does loose mode (2) when the probe address is covered by a
  blackholed CIDR list.

**Multipath hashing** decides which member a flow uses.
`net.ipv4.fib_multipath_hash_policy=0` (the default, L3) keeps each
client-destination pair on one exit. Policy 3 with
`net.ipv4.fib_multipath_hash_fields=0x0001` (source IP only) pins each client
to one exit. IPv6 has the same knobs under `net.ipv6`.

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
cmake -B build -DCMAKE_PREFIX_PATH=/where/libubox/and/uci/are/installed
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
