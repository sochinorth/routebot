#!/bin/sh
# The flush, end to end: whatever a crash could leave behind with routebot's
# proto (and more: tos, v6 source prefixes, multipath, metrics, duplicate
# keys, more than a chunk of routes), removed on startup and nothing of
# anyone else's touched; then routebot's own state, removed on exit.
# usage: tests/flush.sh path/to/routebot
set -eu

. "$(dirname "$0")/lib.sh"

RB=$(realpath "$1")
NTOS=1100	# more than FLUSH_CHUNK, dumped before the rest

ip link set lo up
ip link add vpn0 type dummy
ip link set vpn0 arp off up
ip link add d0 type dummy
ip link add d1 type dummy
ip link set d0 up
ip link set d1 up
ip addr add 192.0.2.2/24 dev d0
ip addr add 198.51.100.2/24 dev d1
ip -6 addr add 2001:db8:f::2/64 dev d0 nodad
ip -6 addr add 2001:db8:e::2/64 dev d1 nodad

# --- someone else's, with keys like ours: must survive ---
ip route add blackhole 172.16.1.0/24 table 300 proto 234 metric 5
ip -6 route add blackhole 2001:db8:10::/48 from 2001:db8:99::/48 table 300 proto 234 metric 1

# --- what a crashed routebot (or anyone with proto 233) left behind ---
i=0
while [ $i -lt $NTOS ]; do
	echo "route add blackhole 10.$((i / 256)).$((i % 256)).0/24 tos 0x10 table 300 proto 233"
	i=$((i + 1))
done > "$T/tos.batch"
ip -batch "$T/tos.batch"
for i in 1 2 3 4 5 6 7 8 9 10; do
	ip route add blackhole 172.16.$i.0/24 table 300 proto 233
done
ip route append blackhole 172.16.1.0/24 table 300 proto 233 metric 5	# after the foreign one
ip route add blackhole 172.16.1.0/24 table 300 proto 233 metric 9
ip route add blackhole 172.16.2.0/24 tos 0x10 table 300 proto 233 metric 5
ip route add 10.250.0.0/24 table 301 proto 233 nexthop via 192.0.2.1 nexthop via 198.51.100.1
ip route add 10.251.0.0/24 table 301 proto 233 via 192.0.2.1
ip route append 10.251.0.0/24 table 301 proto 233 via 198.51.100.1	# same key twice
for i in 1 2 3 4 5; do
	ip -6 route add blackhole 2001:db8:$i::/48 table 300 proto 233
done
ip -6 route add blackhole 2001:db8:10::/48 from 2001:db8:99::/48 table 300 proto 233
ip -6 route add blackhole ::/0 from 2001:db8:98::/48 table 300 proto 233
ip -6 route add 2001:db8:11::/48 from 2001:db8:97::/48 dev d0 table 300 proto 233
ip -6 route append 2001:db8:11::/48 from 2001:db8:97::/48 dev d1 table 300 proto 233
ip -6 route add 2001:db8:20::/48 table 301 proto 233 nexthop via 2001:db8:f::1 nexthop via 2001:db8:e::1
ip -6 route add blackhole 2001:db8:30::/48 table 301 proto 233 metric 7
ip -6 route add blackhole 2001:db8:30::/48 table 301 proto 233 metric 9
ip -6 route add blackhole 2001:db8:30::/48 table 301 proto 233
ip nexthop add id 20001 dev vpn0 proto 233
ip nexthop add id 20003 group 20001 proto 233
ip route add 192.168.7.0/24 nhid 20001 table 301 proto 233	# on the member
ip route add 192.168.8.0/24 nhid 20003 table 301 proto 233	# on the group
ip rule add fwmark 0x5 table 300 proto 233
ip -6 rule add fwmark 0x5 table 300 proto 233

# routes (multipath counts once): all but the one on the group go one by one
nroutes() { ip "$@" route show table all proto 233 | grep -c '^[^[:space:]]' || true; }
N4=$(nroutes -4) N6=$(nroutes -6)
EXPECT=$((NTOS + 10 + 3 + 1 + 2 + 1 + 5 + 4 + 1 + 3))
if [ "$((N4 + N6 - 1))" = "$EXPECT" ]; then pass "left behind: $N4 v4 + $N6 v6 routes"
else fail "left behind: $N4 v4 + $N6 v6 routes, expected $((EXPECT + 1))"; fi

cat > "$T/config" <<EOF
config routebot
	option fwmask '0xff000000'

config group 'vpn0'
	option fwmark '0x12'
EOF

foreign() {
	has "blackhole 172.16.1.0/24 proto 234 metric 5" ip route show table 300
	has "blackhole 2001:db8:10::/48 from 2001:db8:99::/48 dev lo proto 234 metric 1 pref medium" \
		ip -6 route show table 300
}

echo "== startup flush: everything left behind goes, counted right"
start
wait_log "flush: removed 2 rules, 2 nexthops and the routes on them, $EXPECT other routes with proto 233"
not_logged "left"
not_logged "(with errors)"
empty ip route show table 300 proto 233
empty ip route show table 301 proto 233
empty ip -6 route show table 300 proto 233
empty ip -6 route show table 301 proto 233
hasnt "id 20001 dev vpn0 scope host proto 233" ip nexthop show
hasnt "id 20003 group 20001 proto 233" ip nexthop show
hasnt "32765:	from all fwmark 0x5 lookup 300 proto 233" ip rule
hasnt "32765:	from all fwmark 0x5 lookup 300 proto 233" ip -6 rule
foreign

echo "== exit flush: routebot's own state goes"
has "default nhid 10003 dev vpn0 proto 233" ip route show table 10002
# what the exit flush has to delete one by one: routes not on a group (none)
mark
stop
grep -qF "flush: removed 4 rules, 4 nexthops and the routes on them, 0 other routes with proto 233" "$LOG" &&
	pass "exit flush counted" || fail "exit flush miscounted: $(grep 'flush:' "$LOG" | tail -n 1)"
not_logged "left"
empty kstate
foreign

if grep -q "ERROR: AddressSanitizer\|runtime error:" "$LOG"; then
	fail "sanitizer reports"; grep -A5 "Sanitizer\|runtime error" "$LOG"
fi

echo
[ -n "${SHOW_LOG:-}" ] && { echo "--- log"; cat "$LOG"; }
[ "$FAILS" = 0 ] && echo "all passed" || { echo "$FAILS failed"; echo "--- log"; cat "$LOG"; exit 1; }
