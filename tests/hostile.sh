#!/bin/sh
# A kernel that refuses some of routebot's nexthops, end to end: what
# can't be had is left out, the rest keeps being followed and repaired at
# once, never via main.
# usage: tests/hostile.sh path/to/routebot
set -eu

. "$(dirname "$0")/lib.sh"

RB=$(realpath "$1")
RES="type resilient buckets 1024 idle_timer 120 unbalanced_timer 600 proto 233"

# --- topology ---
ip link set lo up
for d in vpn0 vpn1 vpn6; do
	ip link add $d type dummy
	ip link set $d arp off up		# NOARP: usable without a gateway
done
# the kernel takes no IPv6 nexthop on vpn6
sysctl -qw net.ipv6.conf.vpn6.disable_ipv6=1
# gw0's pinned gateway isn't on-link until it gets an address there
ip link add gw0 type veth peer name gwp
ip link set gwp up
ip link set gw0 up
# main has defaults: anything that falls through gets out via wan0
ip link add wan0 type veth peer name wanp
ip addr add 192.0.2.2/24 dev wan0
ip -6 addr add 2001:db8::2/64 dev wan0 nodad
ip link set wanp up
ip link set wan0 up
ip route add default via 192.0.2.1 dev wan0
ip -6 route add default via 2001:db8::1 dev wan0

mkdir -p "$T/g6" "$T/g6b" "$T/pin" "$T/vpn0"
printf '6.0.0.0/24\n2001:db8:60::/48\n' > "$T/g6/x.lst"
printf '2001:db8:61::/48\n' > "$T/g6b/x.lst"
printf '7.0.0.0/24\n' > "$T/pin/x.lst"
printf '8.0.0.0/24\n2001:db8:80::/48\n' > "$T/vpn0/x.lst"

# devices vpn6, vpn1, gw0, vpn0 get 10002, 10006, 10010, 10014;
# groups g6, g6b, pin, vpn0 get 10004, 10008, 10012, 10016 (+1 for v6)
# and tables 10002..10005
cat > "$T/config" <<EOF
config routebot
	option fwmask '0xff000000'

config group 'g6'
	list device 'vpn6'
	option fwmark '0x16'

config group 'g6b'
	list device 'vpn6'
	list device 'vpn1'
	option fwmark '0x17'

config group 'pin'
	list device 'gw0'
	option gateway '198.51.100.1'
	option fwmark '0x18'

config group 'vpn0'
	list device 'vpn0'
	option fwmark '0x12'

config rule 'to_g6'
	option group 'g6'
	list cidrset '$T/g6/*'

config rule 'to_g6b'
	option group 'g6b'
	list cidrset '$T/g6b/*'

config rule 'to_pin'
	option group 'pin'
	list cidrset '$T/pin/*'

config rule 'to_vpn0'
	option group 'vpn0'
	list cidrset '$T/vpn0/*'
EOF

# where 'ip route get ARGS' goes and out of which device
goes_dev() {
	_want=$1; shift
	_got=$(via_dev "$@")
	if [ "$_got" = "$_want" ]; then pass "'ip route get $*' goes to $_want"
	else fail "'ip route get $*' goes to $_got, not $_want"; fi
}

# group vpn0's state, with its only member up
vpn0_ok() {
	has "8.0.0.0/24 nhid 10016 dev vpn0 proto 233" ip route show table 10000
	has "2001:db8:80::/48 nhid 10017 proto 233 metric 1024 pref medium" ip -6 route show table 10000
	has "default nhid 10016 dev vpn0 proto 233" ip route show table 10005
	has "id 10016 group 10014 $RES" nh
	goes_dev "table 10000 dev vpn0" 8.0.0.1
}

# vpn0 goes down and up unseen: the kernel takes its nexthops, its groups
# and their routes; repaired at once, not by a retry seconds later
vpn0_flap() {
	frozen sh -c 'ip link set vpn0 down; ip link set vpn0 up'
	WAIT_TRIES=20 wait_log "vpn0: kernel lost its v4 group, restoring"
	WAIT_TRIES=20 wait_log "sync (event)"
	not_logged "will retry"
	vpn0_ok
}

echo "== R1: refused nexthops are left out, at startup"
start
# vpn6 has no IPv6: its v6 member can't be, g6 holds the v6 blackhole,
# g6b vpn1 alone; gw0's gateway isn't on-link: pin holds the v4 blackhole
wait_log "netlink: nexthop set id 10003: "
wait_log "vpn6: kernel refused its v6 nexthop, left out"
wait_log "netlink: nexthop set id 10010: "
wait_log "gw0: kernel refused its v4 nexthop, left out"
not_logged "will retry"
has "id 10002 dev vpn6 scope host proto 233" nh
has "id 10004 group 10002 $RES" nh
has "id 10005 group 10001 $RES" nh
has "id 10008 group 10002/10006 $RES" nh
has "id 10009 group 10007 $RES" nh
has "id 10012 group 10000 $RES" nh
has "6.0.0.0/24 nhid 10004 dev vpn6 proto 233" ip route show table 10000
has "blackhole 2001:db8:60::/48 nhid 10005 proto 233 metric 1024 pref medium" ip -6 route show table 10000
has "blackhole 7.0.0.0/24 nhid 10012 dev lo proto 233" ip route show table 10000
goes blackhole 2001:db8:60::1
goes blackhole 2001:db8:ffff::1 mark 0x16000000
goes_out vpn1 2001:db8:61::1
goes_out vpn1 2001:db8:ffff::1 mark 0x17000000
goes blackhole 7.0.0.1
goes blackhole 7.7.7.7 mark 0x18000000
vpn0_ok
# a refusal is not a failure: no retry of it
mark; sleep 2.5
not_logged "will retry"
not_logged "sync (retry)"
same_as_fresh "refused nexthops left out"

echo "== R1: the pinned gateway becomes on-link -> its member is in"
mark; ip addr add 198.51.100.2/24 dev gw0
# (the group was logged "via gw0" all along: that is what's wanted)
WAIT_TRIES=20 wait_log "sync (event)"
not_logged "gw0: kernel refused"
has "id 10010 via 198.51.100.1 dev gw0 scope link proto 233" nh
has "id 10012 group 10010 $RES" nh
has "7.0.0.0/24 nhid 10012 via 198.51.100.1 dev gw0 proto 233" ip route show table 10000
goes_dev "table 10000 dev gw0" 7.0.0.1
goes_dev "table 10004 dev gw0" 7.7.7.7 mark 0x18000000
same_as_fresh "pinned gateway on-link"

echo "== R2: a member refused all along, another group's member flaps -> repaired at once"
vpn0_flap
same_as_fresh "vpn0 flap beside a refused member"

stop
flush
empty kstate

if grep -q "ERROR: AddressSanitizer\|runtime error:" "$LOG"; then
	fail "sanitizer reports"; grep -A5 "Sanitizer\|runtime error" "$LOG"
fi

echo
[ -n "${SHOW_LOG:-}" ] && { echo "--- log"; cat "$LOG"; }
[ "$FAILS" = 0 ] && echo "all passed" || { echo "$FAILS failed"; echo "--- log"; cat "$LOG"; exit 1; }
