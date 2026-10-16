#!/bin/sh
# Cross-checks the mallocstat shim against independent sources, on the bench
# workload (not part of the gate; run it after touching the shim).
# usage: tests/bench/validate.sh path/to/routebot  (build it with -g for file:line)
#
# Each run is the same lifetime: start, wait until idle, one no-op reload,
# SIGTERM. Then:
#   A  shim counters
#   B  glibc's own mtrace (libc_malloc_debug.so): every malloc/realloc/free
#      it logs, counted independently -> must match A
#   C  shim backtrace mode (allocations >= 64 KiB, with file:line) under
#      strace -e mmap,mremap,munmap,brk -> the big ones must show up as
#      syscalls of the matching size, or as heap (brk) growth
set -eu

. "$(dirname "$0")/../lib.sh"

HERE=$(cd "$(dirname "$0")" && pwd)
RB=$(realpath "$1")
HOSTDEPS=${HOSTDEPS:-/home/sochinorth/routebot/.hostdeps}
WAIT_TRIES=600
PY="python3 -I"
BT_MIN=65536

. "$HERE/setup.sh"

UB="ROUTEBOT_UBUS_SOCKET=$T/ubus.sock"
RB_ARGS=

cat > "$T/mtrace_on.c" <<'EOF'
#include <mcheck.h>
__attribute__((constructor)) static void on(void) { mtrace(); }
EOF
${CC:-cc} -O2 -fPIC -shared -o "$T/mtrace_on.so" "$T/mtrace_on.c"
MDEBUG=$(for d in /usr/lib64 /usr/lib /lib64 /lib /usr/lib/x86_64-linux-gnu; do
	[ -e "$d/libc_malloc_debug.so.0" ] && { echo "$d/libc_malloc_debug.so.0"; break; }; done)
[ -n "$MDEBUG" ] || { echo "no libc_malloc_debug.so.0 (glibc >= 2.34 needed)"; exit 1; }

idle() { $PY "$HERE/rbstat.py" quiesce "$1" "$2" /nonexistent "$T/snaps" --window 300 > /dev/null; }

# lifetime PID_TO_SIGNAL PID_TO_WAIT
lifetime() {
	idle start "$1"
	mark; kill -HUP "$1"; wait_log "config: 4 groups"
	idle reload "$1"
	kill -TERM "$1"
	wait "$2" && pass "exit status 0" || fail "exit status $?"
	PID=
}

echo "== A: shim counters"
RB_ENV="env LD_PRELOAD=$SHIM MALLOCSTAT_FILE=$T/counters $UB"
start
lifetime "$PID" "$PID"

echo "== B: glibc mtrace"
RB_ENV="env LD_PRELOAD=$MDEBUG:$T/mtrace_on.so MALLOC_TRACE=$T/mtrace.log $UB"
start
lifetime "$PID" "$PID"

echo "== C: shim backtraces >= $BT_MIN bytes, under strace"
RB_ENV="strace -f -qq -o $T/strace.log -e trace=execve,mmap,mremap,munmap,brk env LD_PRELOAD=$SHIM
	MALLOCSTAT_FILE=$T/counters_c MALLOCSTAT_BT_MIN=$BT_MIN MALLOCSTAT_BT_FILE=$T/bt.log $UB"
start
SPID=$PID
RBPID=$(pgrep -P "$SPID" | head -n 1)
[ -n "$RBPID" ] || { fail "routebot under strace not found"; exit 1; }
lifetime "$RBPID" "$SPID"

echo "== analysis"
$PY "$HERE/validate.py" "$RB" "$T/counters" "$T/mtrace.log" "$T/counters_c" "$T/bt.log" \
	"$T/strace.log" || fail "cross-checks"

echo
[ "$FAILS" = 0 ] && echo "all passed" || { echo "$FAILS failed"; tail -n 30 "$LOG"; exit 1; }
