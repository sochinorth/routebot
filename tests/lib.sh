# Shared helpers for the end-to-end scripts, sourced (not run) by
# tests/netns.sh and tests/bench/bench.sh.
#
# Sourcing it re-executes the calling script in a throwaway user + network
# namespace (no root needed), then sets up:
#   T      a temp dir, removed on exit
#   LOG    routebot's log ($T/log)
#   PID    the running routebot, killed on exit
#   FAILS  failed checks so far
# The caller sets RB (the binary) before calling start.
#
# Knobs (all optional):
#   RB_ENV      words put before "$RB" by start, e.g. "env FOO=1" to scope
#               variables to the routebot process alone
#   RB_ARGS     routebot options before "-c $T/config" (default: -v)
#   WAIT_TRIES  wait_log polls, 0.1s apart (default 50)
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

stop() {
	kill -TERM "$PID"
	wait "$PID" && pass "exit status 0" || fail "exit status $?"
	PID=
}

hup() { mark; kill -HUP "$PID"; }

# nexthops without the ever-changing unbalanced_time
nh() { ip nexthop show | sed 's/ unbalanced_time [0-9]*//'; }

# run link changes while routebot is stopped, so it reads them as one batch
frozen() { kill -STOP "$PID"; "$@"; mark; kill -CONT "$PID"; }

# everything routebot owns in the kernel, in a stable order
kstate() {
    ip route show table all proto 233
    ip -6 route show table all proto 233
    nh | grep 'proto 233' || true
    ip rule | grep 'proto 233' || true
    ip -6 rule | grep 'proto 233' || true
}
