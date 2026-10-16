#!/bin/sh
# Memory and per-unit-of-work cost benchmark, in a throwaway network
# namespace (no root needed). See "Benchmark" in README.md.
# usage: tests/bench/bench.sh path/to/routebot [out.json]
#
# env: BENCH_N (repetitions per unit, default 50), BENCH_QUIET_MS (idle
# window, default 300), HOSTDEPS (for ubusd), CC (to build the shim),
# MALLOCSTAT_SO (a prebuilt shim instead).
set -eu

. "$(dirname "$0")/../lib.sh"

HERE=$(cd "$(dirname "$0")" && pwd)
RB=$(realpath "$1")
OUT=$(realpath -m "${2:-bench.json}")
N=${BENCH_N:-50}
QUIET_MS=${BENCH_QUIET_MS:-300}
HOSTDEPS=${HOSTDEPS:-/home/sochinorth/routebot/.hostdeps}
WAIT_TRIES=600
PY="python3 -I"
SNAPS=$T/snaps.jsonl
CNT=$T/mallocstat
CHECKS=$T/checks
: > "$SNAPS"
: > "$CHECKS"

say() { echo "bench: $*"; }
now() { date +%s%N; }
# snap LABEL [WALL_S]
snap() { $PY "$HERE/rbstat.py" snap "$1" "${PID:-0}" "$CNT" "$SNAPS" ${2:+--wall "$2"}; }
# quiesce LABEL [SINCE_NS]
quiesce() {
	$PY "$HERE/rbstat.py" quiesce "$1" "$PID" "$CNT" "$SNAPS" \
		--since "${2:-0}" --window "$QUIET_MS" --timeout 120 ||
		{ fail "routebot never went idle ($1)"; finish; }
}
# checks are logged to $CHECKS, only failures are shown
expect() { wait_log "$1" >> "$CHECKS"; }

. "$HERE/setup.sh"

UNITS="link_noop member_flip blackhole_flip link_flap reload_noop reload_small"
PHASES="startup after_events after_reload after_10_reloads end exit restart_dirty"

finish() {
	_ok=false
	[ "$FAILS" = 0 ] && _ok=true
	$PY - "$T/meta.json" <<EOF
import json, sys
m = json.load(open("$L/manifest.json"))
json.dump({
	"ok": $( [ "$_ok" = true ] && echo True || echo False ),
	"n": $N, "quiet_ms": $QUIET_MS, "ubus": $( [ "$UBUS" = true ] && echo True || echo False ),
	"units": "$UNITS".split(), "phases": "$PHASES".split(),
	"binary": "$RB", "binary_sha256": "$(sha256sum "$RB" | cut -d' ' -f1)",
	"kernel": "$(uname -r)", "machine": "$(uname -m)",
	"libc": "$(getconf GNU_LIBC_VERSION 2>/dev/null || echo unknown)",
	"date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
	"exit_status": "${EXIT_STATUS:-none}",
	"routes_installed": {"v4": ${GOT4:-0}, "v6": ${GOT6:-0}},
	"workload": {"sha256": m["sha256"], "lines": m["lines"], "routes": m["routes"]["total"],
		     "conflicts": m["conflicts"]},
	"log_samples": json.load(open("$T/samples.json")) if __import__("os").path.exists("$T/samples.json") else {},
}, open(sys.argv[1], "w"))
EOF
	$PY "$HERE/rbstat.py" report "$SNAPS" "$T/meta.json" "$OUT"
	if [ "$FAILS" != 0 ]; then
		grep -A20 '^FAIL' "$CHECKS" || true
		echo "--- log (tail)"; tail -n 40 "$LOG"
		say "$FAILS checks failed, results in $OUT (ok: false)"
		exit 1
	fi
	say "results in $OUT"
	exit 0
}

# first sync line (or line with $2) after the mark, for the record
SAMPLES=
sample() {
	_l=$(tail -n +"$((MARK + 1))" "$LOG" | grep -m1 "${2:-sync (}" | sed 's/^routebot: [a-z]*: //; s/"/\\"/g' || true)
	SAMPLES="$SAMPLES${SAMPLES:+, }\"$1\": \"$_l\""
	echo "{ $SAMPLES }" > "$T/samples.json"
}

# --- startup ---
say "startup ($V4 v4 + $V6 v6 routes)"
RB_ENV="env LD_PRELOAD=$SHIM MALLOCSTAT_FILE=$CNT ROUTEBOT_UBUS_SOCKET=$T/ubus.sock"
RB_ARGS=	# the init script's log level
SINCE=$(now)
start >> "$CHECKS"
[ -n "$PID" ] && kill -0 "$PID" 2>/dev/null || { fail "routebot didn't start"; finish; }
quiesce startup "$SINCE"
sample startup
[ -s "$CNT" ] || { fail "no allocation counters: shim not loaded?"; finish; }
GOT4=$(ip -4 route show table 10000 | grep -c ' proto 233' || true)
GOT6=$(ip -6 route show table 10000 | grep -c ' proto 233' || true)
[ "$GOT4" = "$V4" ] && [ "$GOT6" = "$V6" ] && pass "routes: $GOT4 v4, $GOT6 v6" >> "$CHECKS" ||
	fail "routes: $GOT4 v4, $GOT6 v6, want $V4 and $V6"
# the first 10 conflicts are logged one by one, the rest as a count
_c=$(grep -c "claimed by rule 'big' (pool) and rule 'asn' (warp)" "$LOG" || true)
_m=$(sed -n 's/.* \([0-9][0-9]*\) more prefixes claimed by several rules.*/\1/p' "$LOG" | head -n 1)
_c=$((_c + ${_m:-0}))
[ "$_c" = "$CONFLICTS" ] && pass "conflicts: $_c" >> "$CHECKS" || fail "conflicts: $_c, want $CONFLICTS"
grep -q "invalid CIDR" "$LOG" && pass "invalid lines warned" >> "$CHECKS" || fail "no invalid line warning"
grep -q "has host bits set" "$LOG" && pass "host bits warned" >> "$CHECKS" || fail "no host bits warning"
grep -q "ubus: cannot connect" "$LOG" && [ "$UBUS" = true ] && fail "ubus not connected"
[ "$FAILS" = 0 ] || finish
# what a clean start installs, for restart_dirty
kstate > "$T/state.clean"

# --- units ---
# run_unit NAME: repeats unit_NAME N times between a begin and end snapshot
run_unit() {
	say "$1 x $N"
	quiesce "unit:$1:begin"
	_i=0
	while [ "$_i" -lt "$N" ]; do
		"unit_$1" "$_i"
		[ "$FAILS" = 0 ] || finish
		_i=$((_i + 1))
	done
}

# an unrelated link comes and goes: events, nothing to do
unit_link_noop() {
	S=$(now); ip link add rbz0 type dummy; quiesce unit:link_noop "$S"
	S=$(now); ip link del rbz0; quiesce unit:link_noop "$S"
}

# p2 loses its gateways and gets them back: pool's groups are replaced
unit_member_flip() {
	S=$(now)
	frozen sh -c 'ip route del default via 10.1.2.1 dev p2;
		ip -6 route del default via 2001:db8:1:2::1 dev p2'
	expect "sync (link event): 0 routes set, 0 deleted, 2 nexthops set, 2 deleted, 0 rules added, 0 deleted"
	[ "$1" = 0 ] && sample member_flip_out
	quiesce unit:member_flip "$S"
	S=$(now)
	frozen sh -c 'ip route add default via 10.1.2.1 dev p2 metric 102;
		ip -6 route add default via 2001:db8:1:2::1 dev p2 metric 102'
	expect "sync (link event): 0 routes set, 0 deleted, 4 nexthops set, 0 deleted, 0 rules added, 0 deleted"
	[ "$1" = 0 ] && sample member_flip_in
	quiesce unit:member_flip "$S"
}

# wan0 loses its gateways: wan is blackholed, its prefixes rewritten twice
unit_blackhole_flip() {
	S=$(now)
	frozen sh -c 'ip route del default via 192.0.2.1 dev wan0;
		ip -6 route del default via 2001:db8::1 dev wan0'
	expect "sync (link event): $((MISC + 2)) routes set, 0 deleted, 0 nexthops set, 4 deleted, 0 rules added, 0 deleted"
	[ "$1" = 0 ] && sample blackhole_flip_out
	quiesce unit:blackhole_flip "$S"
	S=$(now)
	frozen sh -c 'ip route add default via 192.0.2.1 dev wan0 metric 10;
		ip -6 route add default via 2001:db8::1 dev wan0 metric 10'
	expect "sync (link event): $((MISC + 2)) routes set, 0 deleted, 4 nexthops set, 0 deleted, 0 rules added, 0 deleted"
	[ "$1" = 0 ] && sample blackhole_flip_in
	quiesce unit:blackhole_flip "$S"
}

# p2 goes down and comes back in one batch, which also takes its v6 address
# and default routes; the kernel deleted its nexthops, dropping them from
# pool. Everything is re-sent here ("sync (link flap)").
unit_link_flap() {
	S=$(now)
	frozen sh -c 'ip link set p2 down; ip link set p2 up
		ip -6 addr add 2001:db8:1:2::2/64 dev p2 nodad
		ip route add default via 10.1.2.1 dev p2 metric 102
		ip -6 route add default via 2001:db8:1:2::1 dev p2 metric 102'
	expect "link flap on p2, re-syncing"
	expect "sync (link "
	[ "$1" = 0 ] && sample link_flap
	quiesce unit:link_flap "$S"
	# p2 (10013, 10014) is back in pool (10011, 10012)
	for _g in "10011 group 10009/10013,2/10017" "10012 group 10010/10014,2/10018"; do
		ip nexthop show id "${_g%% *}" | grep -q "^id $_g " ||
			fail "link_flap: want id $_g, got: $(ip nexthop show id "${_g%% *}" 2>&1)"
	done
}

reload_noop() {
	S=$(now); hup
	expect "config: 4 groups"
	quiesce "$1" "$S"
	if tail -n +"$((MARK + 1))" "$LOG" | grep -q "sync (reload)"; then
		fail "no-op reload synced something"
	fi
}

unit_reload_noop() { reload_noop unit:reload_noop; }

# one misc file changes by 100 lines each way, alternating
unit_reload_small() {
	if [ $(($1 % 2)) = 0 ]; then cp "$L/alt/m03.lst" "$L/misc/m03.lst"
	else cp "$T/m03.orig" "$L/misc/m03.lst"; fi
	S=$(now); hup
	expect "sync (reload): 100 routes set, 100 deleted, 0 nexthops set, 0 deleted, 0 rules added, 0 deleted"
	[ "$1" = 0 ] && sample reload_small
	quiesce unit:reload_small "$S"
}

run_unit link_noop
run_unit member_flip
run_unit blackhole_flip
run_unit link_flap
quiesce after_events

say "memory: reloads"
reload_noop after_reload
for _ in 1 2 3 4 5 6 7 8 9; do reload_noop reloads; done
reload_noop after_10_reloads
[ "$FAILS" = 0 ] || finish

run_unit reload_noop
run_unit reload_small
quiesce end

say "shutdown"
S=$(now)
kill -TERM "$PID"
EXIT_STATUS=0
wait "$PID" || EXIT_STATUS=$?
E=$(now)
PID=
snap exit "$(echo "$S $E" | awk '{ printf "%.6f", ($2 - $1) / 1e9 }')"
[ "$EXIT_STATUS" = 0 ] && pass "exit status 0" >> "$CHECKS" || fail "exit status $EXIT_STATUS"
[ -z "$(kstate)" ] && pass "nothing left after exit" >> "$CHECKS" || fail "state left after exit"
[ "$FAILS" = 0 ] || finish

# --- restart_dirty ---
# routebot is killed with everything installed; a new one flushes what it
# left behind and installs it all again: from exec until idle
say "restart_dirty"
cp "$T/m03.orig" "$L/misc/m03.lst"
rb_env() { RB_ENV="env LD_PRELOAD=$SHIM MALLOCSTAT_FILE=$CNT ROUTEBOT_UBUS_SOCKET=$T/ubus.sock"; }
CNT=$T/mallocstat.crashed; rb_env
start >> "$CHECKS"
quiesce restart_crashed
kill -KILL "$PID"
wait "$PID" 2>/dev/null || true
PID=
CNT=$T/mallocstat.dirty; rb_env
SINCE=$(now)
start >> "$CHECKS"
[ -n "$PID" ] && kill -0 "$PID" 2>/dev/null || { fail "routebot didn't start after a crash"; finish; }
quiesce restart_dirty "$SINCE"
expect "flush: removed 10 rules, "
sample restart_dirty_flush "flush: "
kstate > "$T/state.dirty"
if cmp -s "$T/state.clean" "$T/state.dirty"; then
	pass "restart_dirty: same state as a clean start" >> "$CHECKS"
else
	fail "restart_dirty: state differs from a clean start"
	diff "$T/state.clean" "$T/state.dirty" | head -n 20
fi
kill -TERM "$PID"
_st=0
wait "$PID" || _st=$?
PID=
[ "$_st" = 0 ] && pass "restart_dirty: exit status 0" >> "$CHECKS" ||
	fail "restart_dirty: exit status $_st"
[ -z "$(kstate)" ] && pass "restart_dirty: nothing left after exit" >> "$CHECKS" ||
	fail "restart_dirty: state left after exit"
if grep -q "Sanitizer\|runtime error:" "$LOG"; then fail "sanitizer reports"; fi
finish
