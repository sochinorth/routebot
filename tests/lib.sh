# Shared helpers for the end-to-end scripts, sourced (not run) by
# tests/netns.sh, flush.sh, hostile.sh, tables.sh and tests/bench/bench.sh.
#
# Sourcing it re-executes the calling script in a throwaway user + network
# namespace (no root needed), then sets up:
#   T      a temp dir, removed on exit
#   LOG    routebot's log ($T/log)
#   PID    the running routebot, killed on exit (stop sends SIGTERM,
#          which leaves the kernel as it is; flush runs routebot -F)
#   FAILS  failed checks so far
# The caller sets RB (the binary) before calling start.
#
# Knobs (all optional):
#   RB_ENV      words put before "$RB" by start, e.g. "env FOO=1" to scope
#               variables to the routebot process alone
#   RB_ARGS     routebot options before "-c $T/config" (default: -v)
#   WAIT_TRIES  wait_log polls, 0.1s apart (default 50)
#   SOON_TRIES  soon_has/soon_hasnt polls, 0.1s apart (default 15)
#   RB_PROTO    the rt_proto kstate looks for (default 233)
#   on_cleanup  define this function for extra teardown at exit

if [ -z "${RB_IN_NS:-}" ]; then
	exec unshare -rn env RB_IN_NS=1 sh "$0" "$@"
fi

T=$(mktemp -d)
LOG=$T/log
: > "$LOG"
PID=
FAILS=0

cleanup() {
	[ -n "$PID" ] && kill "$PID" 2>/dev/null || true
	command -v on_cleanup >/dev/null && on_cleanup
	rm -rf "$T"
}
trap cleanup EXIT

pass() { echo "ok   $*"; }
fail() { echo "FAIL $*"; FAILS=$((FAILS + 1)); }

# normalized command output: no trailing spaces
out() { "$@" 2>&1 | sed 's/[[:space:]]*$//'; }

has() {
	_line=$1; shift
	if out "$@" | grep -qxF -- "$_line"; then pass "'$*' has '$_line'"
	else fail "'$*' lacks '$_line'"; out "$@" | sed 's/^/     | /'; fi
}

hasnt() {
	_line=$1; shift
	if out "$@" | grep -qxF -- "$_line"; then fail "'$*' still has '$_line'"
	else pass "'$*' lacks '$_line'"; fi
}

empty() {
	if [ -z "$(out "$@")" ]; then pass "'$*' is empty"
	else fail "'$*' not empty"; out "$@" | sed 's/^/     | /'; fi
}

mark() { MARK=$(wc -l < "$LOG"); }

wait_log() {
	for _ in $(seq "${WAIT_TRIES:-50}"); do
		tail -n +"$((MARK + 1))" "$LOG" | grep -qF -- "$1" && { pass "log: $1"; return 0; }
		sleep 0.1
	done
	fail "log never said: $1"
	tail -n 20 "$LOG" | sed 's/^/     | /'
	return 0
}

start() {
	mark
	# shellcheck disable=SC2086 # RB_ENV and RB_ARGS are word lists
	${RB_ENV:-} "$RB" ${RB_ARGS--v} -c "$T/config" >> "$LOG" 2>&1 &
	PID=$!
	wait_log "running"
}

# SIGTERM: routebot exits, leaving the kernel as it is
stop() {
	mark
	kill -TERM "$PID"
	wait "$PID" && pass "exit status 0" || fail "exit status $?"
	PID=
	wait_log "exiting, routes left in place"
}

# routebot -F: removes everything with the config's rt_proto
flush() {
	mark
	# shellcheck disable=SC2086 # RB_ENV and RB_ARGS are word lists
	if timeout 30 ${RB_ENV:-} "$RB" -F ${RB_ARGS--v} -c "$T/config" >> "$LOG" 2>&1
	then pass "flush: exit status 0"; else fail "flush: exit status $?"; fi
}

hup() { mark; kill -HUP "$PID"; }

# nexthops without the ever-changing unbalanced_time
nh() { ip nexthop show | sed 's/ unbalanced_time [0-9]*//'; }

# run link changes while routebot is stopped, so it reads them as one batch
frozen() { kill -STOP "$PID"; "$@"; mark; kill -CONT "$PID"; }

# the log hasn't said $1 since the last mark
not_logged() {
    _said=$(tail -n +"$((MARK + 1))" "$LOG" | grep -F -- "$1" || true)
    if [ -n "$_said" ]; then fail "log said: $1"; echo "$_said" | sed 's/^/     | /'
    else pass "log didn't say: $1"; fi
}

# everything routebot owns in the kernel, in a stable order; RB_PROTO is
# its rt_proto (default 233)
kstate() {
    ip route show table all proto "${RB_PROTO:-233}"
    ip -6 route show table all proto "${RB_PROTO:-233}"
    nh | grep "proto ${RB_PROTO:-233}" || true
    ip rule | grep "proto ${RB_PROTO:-233}" || true
    ip -6 rule | grep "proto ${RB_PROTO:-233}" || true
}

# the kernel holds what a fresh start would install: stop, flush, start
# and compare
same_as_fresh() {
    kstate > "$T/state.now"
    stop
    flush
    start
    kstate > "$T/state.fresh"
    if cmp -s "$T/state.now" "$T/state.fresh"; then pass "$1: same as a fresh start"
    else fail "$1: differs from a fresh start"
        diff -u "$T/state.now" "$T/state.fresh" | sed 's/^/     | /'; fi
}

# poll until 'CMD' has (or lacks) LINE, for up to SOON_TRIES tenths of a
# second (default 15), then check as has/hasnt do
soon_has() {
	_line=$1; shift
	for _ in $(seq "${SOON_TRIES:-15}"); do
		out "$@" | grep -qxF -- "$_line" && break
		sleep 0.1
	done
	has "$_line" "$@"
}
soon_hasnt() {
	_line=$1; shift
	for _ in $(seq "${SOON_TRIES:-15}"); do
		out "$@" | grep -qxF -- "$_line" || break
		sleep 0.1
	done
	hasnt "$_line" "$@"
}

# where 'ip route get ARGS' goes: blackhole, unreachable, main or table N
via() {
	_o=$(ip route get "$@" 2>&1 | head -n 1)
	via_of
}
via_of() {
	case $_o in
	*"Invalid argument"*) echo blackhole ;;
	RTNETLINK*) echo unreachable ;;
	*" table "*) echo "table $(echo "$_o" | sed 's/.* table \([0-9]*\).*/\1/')" ;;
	*) echo main ;;
	esac
}

# the same, followed by " dev DEV" when it gets out somewhere
via_dev() {
	_o=$(ip route get "$@" 2>&1 | head -n 1)
	case $_o in
	*" dev "*) echo "$(via_of) dev $(echo "$_o" | sed 's/.* dev \([^ ]*\).*/\1/')" ;;
	*) via_of ;;
	esac
}

goes() {
	_want=$1; shift
	_got=$(via "$@")
	if [ "$_got" = "$_want" ]; then pass "'ip route get $*' goes to $_want"
	else fail "'ip route get $*' goes to $_got, not $_want"; fi
}

# 'ip route get ARGS' gets out of device DEV (whatever the table: for IPv6
# the kernel may name the table of a cached route on the same nexthop)
goes_out() {
	_want=$1; shift
	_got=$(via_dev "$@")
	case $_got in
	*" dev $_want") pass "'ip route get $*' goes out of $_want" ;;
	*) fail "'ip route get $*' goes to $_got, not out of $_want" ;;
	esac
}

# sample where each 'ip route get ARGS' (one per argument) goes, and out of
# which device, until stopped; "ARGS=DEV1,DEV2" also allows only those
# devices (a blackhole has none, and is always allowed)
sample_start() {
	: > "$T/samples"
	rm -f "$T/stop"
	printf '%s\n' "$@" > "$T/sample.specs"
	(
		while [ ! -e "$T/stop" ]; do
			for _s in "$@"; do
				_a=${_s%%=*}
				# shellcheck disable=SC2086 # each argument is a word list
				echo "$_a: $(via_dev $_a)"
			done
		done >> "$T/samples"
	) &
	SAMPLER=$!
}

# stop sampling: none of it may have gone to main, nor out of a device its
# argument doesn't allow
sample_stop() {
	touch "$T/stop"
	wait "$SAMPLER"
	_n=$(wc -l < "$T/samples")
	_main=$(grep -c ': main\( dev [^ ]*\)\?$' "$T/samples" || true)
	if [ "$_main" = 0 ] && [ "$_n" -gt 0 ]; then
		pass "$1: $_n samples, none via main ($(grep -c ': blackhole$' "$T/samples" || true) blackholed)"
	else
		fail "$1: $_main of $_n samples via main"
		grep ': main\( dev [^ ]*\)\?$' "$T/samples" | sort | uniq -c | sed 's/^/     | /'
	fi
	grep '=' "$T/sample.specs" | while IFS= read -r _s; do
		awk -v a="${_s%%=*}: " -v ok=",${_s#*=}," '
			index($0, a) == 1 {
				n = split(substr($0, length(a) + 1), w, " ")
				for (i = 1; i < n; i++)
					if (w[i] == "dev" && !index(ok, "," w[i + 1] ","))
						print
			}' "$T/samples"
	done > "$T/samples.wrong"
	if [ -s "$T/samples.wrong" ]; then
		fail "$1: $(wc -l < "$T/samples.wrong") of $_n samples out of a device not theirs"
		sort "$T/samples.wrong" | uniq -c | sed 's/^/     | /'
	elif grep -q '=' "$T/sample.specs"; then
		pass "$1: none out of another group's device"
	fi
}
