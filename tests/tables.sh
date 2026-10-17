#!/bin/sh
# Layout changes: table_id and rule_prio moves, the old and the new tables
# overlapping (the new CIDR table is an old group table, or a new group
# table the old CIDR table), on reload and at startup over a crash's
# leftovers, under load: traffic may be dropped meanwhile, but no listed or
# marked traffic may go out of another group's uplink, nor via main.
# usage: tests/tables.sh path/to/routebot
set -eu

. "$(dirname "$0")/lib.sh"

RB=$(realpath "$1")
N=${TABLES_N:-50000}	# prefixes per group and family 4

# --- topology: an uplink per group, main's defaults via a third ---
ip link set lo up
for d in vpn0 vpn1; do
	ip link add $d type dummy
	ip link set $d arp off up
done
ip link add wan0 type veth peer name wanp
ip addr add 192.0.2.2/24 dev wan0
ip -6 addr add 2001:db8::2/64 dev wan0 nodad
ip link set wanp up
ip link set wan0 up
ip route add default via 192.0.2.1 dev wan0
ip -6 route add default via 2001:db8::1 dev wan0

mkdir -p "$T/a" "$T/b"
for g in a:21 b:22; do
	awk -v p="${g#*:}" -v n="$N" 'BEGIN { for (i = 0; i < n; i++) printf "%d.%d.%d.0/24\n", p, i / 256, i % 256 }' \
		> "$T/${g%%:*}/big.lst"
done
printf '2001:db8:a1::/48\n' > "$T/a/v6.lst"
printf '2001:db8:b1::/48\n' > "$T/b/v6.lst"
LAST=$(((N - 1) / 256)).$(((N - 1) % 256))

# write_config TABLE_ID RULE_PRIO: groups a (vpn0) and b (vpn1), tables
# TABLE_ID + 2 and + 3
write_config() {
	cat > "$T/config" <<EOF
config routebot
	option fwmask '0xff000000'
	option table_id '$1'
	option rule_prio '$2'

config group 'a'
	list device 'vpn0'
	option fwmark '0x12'

config group 'b'
	list device 'vpn1'
	option fwmark '0x13'

config rule 'to_a'
	option group 'a'
	list cidrset '$T/a/*'

config rule 'to_b'
	option group 'b'
	list cidrset '$T/b/*'
EOF
}

sample_groups() {
	sample_start "21.0.0.1=vpn0" "21.$LAST.1=vpn0" "22.0.0.1=vpn1" "22.$LAST.1=vpn1" \
		"2001:db8:a1::1=vpn0" "2001:db8:b1::1=vpn1" \
		"7.7.7.7 mark 0x12000000=vpn0" "7.7.7.7 mark 0x13000000=vpn1" \
		"2001:db8:ffff::1 mark 0x12000000=vpn0" "2001:db8:ffff::1 mark 0x13000000=vpn1"
}

# where it all goes with table_id $1 when routebot is done
settled() {
	goes "table $1" "21.$LAST.1"
	goes "table $1" "22.0.0.1"
	goes "table $(($1 + 2))" 7.7.7.7 mark 0x12000000
	goes "table $(($1 + 3))" 7.7.7.7 mark 0x13000000
	goes_out vpn1 2001:db8:b1::1
	goes_out vpn0 2001:db8:ffff::1 mark 0x12000000
	goes_out vpn1 2001:db8:ffff::1 mark 0x13000000
	if [ "$(ip route show table "$1" | grep -c '^2[12]\.')" = $((2 * N)) ]; then
		pass "table $1: $((2 * N)) v4 prefixes"
	else fail "table $1: $(ip route show table "$1" | grep -c '^2[12]\.') v4 prefixes, not $((2 * N))"; fi
}

for SHIFT in 2 -2; do
	for PRIO in same moved; do
		_t=$((10000 + SHIFT))
		_p=10000
		[ $PRIO = moved ] && _p=$((10000 + SHIFT))
		echo "== R3: reload, table_id 10000 -> $_t, rule_prio 10000 -> $_p"
		[ -n "$PID" ] && { stop; flush; }
		write_config 10000 10000
		start
		settled 10000
		sample_groups
		write_config $_t $_p
		hup; WAIT_TRIES=600 wait_log "sync (reload)"
		sample_stop "table_id $_t, rule_prio $_p, on reload"
		not_logged "with errors"
		settled $_t
		same_as_fresh "table_id $_t, rule_prio $_p, on reload"
	done
done

for SHIFT in 2 -2; do
	_t=$((10000 + SHIFT))
	echo "== R3/R5: startup over a crash's leftovers, table_id 10000 -> $_t"
	[ -n "$PID" ] && { stop; flush; }
	write_config 10000 10000
	start
	kill -KILL "$PID"; wait "$PID" 2>/dev/null || true; PID=
	write_config $_t 10000
	sample_groups
	WAIT_TRIES=600 start
	sample_stop "table_id $_t, at startup"
	not_logged "with errors"
	settled $_t
	same_as_fresh "table_id $_t, at startup"
done
stop
flush
empty kstate

if grep -q "ERROR: AddressSanitizer\|runtime error:" "$LOG"; then
	fail "sanitizer reports"; grep -A5 "Sanitizer\|runtime error" "$LOG"
fi

echo
[ -n "${SHOW_LOG:-}" ] && { echo "--- log"; cat "$LOG"; }
[ "$FAILS" = 0 ] && echo "all passed" || { echo "$FAILS failed"; echo "--- log"; tail -n 200 "$LOG"; exit 1; }
