#!/bin/sh
# The gate: every change runs this, the same way, from any worktree.
# usage: tests/gate.sh
#
#   1. clean ASan+UBSan debug build (host), warnings counted and shown
#   2. unit tests (tests/unit/test_*.c via ctest), if there are any
#   3. tests/netns.sh against the sanitized build, leaks fatal
#   4. clean release build -> tests/bench/bench.sh -> compare.py against
#      tests/bench/baseline.json
#   5. clean cross build with the OpenWrt SDK (aarch64 musl), warnings counted
#
# Stops at the first failing step and prints a summary either way.
#
# env: HOSTDEPS (default /home/sochinorth/routebot/.hostdeps)
#      OPENWRT_SDK (default /home/sochinorth/routebot/.openwrt-sdk)
#      CC (host compiler, default cc), BENCH_N, BENCH_QUIET_MS (see bench.sh)
#      GATE_BUILD (where build dirs go, default <repo>/build-gate-*)
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
HOSTDEPS=${HOSTDEPS:-/home/sochinorth/routebot/.hostdeps}
OPENWRT_SDK=${OPENWRT_SDK:-/home/sochinorth/routebot/.openwrt-sdk}
B=${GATE_BUILD:-$ROOT/build-gate}
JOBS=$(nproc 2>/dev/null || echo 4)
CC=${CC:-cc}
export CC

# OpenWrt's package flags for this SDK's target (rules.mk + hardening.mk:
# -Os, no caller-saves, no PLT, SSP regular, FORTIFY 1, full RELRO), minus
# -Os on the host, where the bench wants the -O2 the brief asks for
HARDEN="-pipe -fno-caller-saves -fno-plt -Wformat -Werror=format-security -fstack-protector -D_FORTIFY_SOURCE=1"
RELRO="-Wl,-z,now -Wl,-z,relro"
SAN="-fsanitize=address,undefined -fno-omit-frame-pointer"
export ASAN_OPTIONS="detect_leaks=1:abort_on_error=0:exitcode=23"
export UBSAN_OPTIONS="print_stacktrace=1"

SUMMARY=
LSAN=unknown
note() { SUMMARY="$SUMMARY$*
"; }
hr() { printf '\n==== %s\n' "$*"; }

summary() {
	printf '\n==== gate summary\n%s' "$SUMMARY"
	printf 'LSan: %s\n' "$LSAN"
	if [ "$1" = 0 ]; then echo "GATE: PASS"; else echo "GATE: FAIL ($2)"; fi
	exit "$1"
}
die() { note "FAIL  $1"; summary 1 "$1"; }

# build NAME DIR [cmake args...]: configure + build from scratch, sets WARN
build() {
	_name=$1 _dir=$2; shift 2
	rm -rf "$_dir"
	mkdir -p "$_dir"
	cmake -S "$ROOT" -B "$_dir" "$@" > "$_dir/configure.log" 2>&1 ||
		{ cat "$_dir/configure.log"; die "$_name: configure failed"; }
	cmake --build "$_dir" -j "$JOBS" > "$_dir/build.log" 2>&1
	_rc=$?
	WARN=$(grep -c 'warning:' "$_dir/build.log")
	if [ "$WARN" != 0 ] || [ "$_rc" != 0 ]; then
		grep -E -A3 'warning:|error:' "$_dir/build.log"
	fi
	echo "$_name: $WARN compiler warnings"
	[ "$_rc" = 0 ] || die "$_name: build failed"
}

HOSTARGS="-DCMAKE_PREFIX_PATH=$HOSTDEPS -DCMAKE_BUILD_RPATH=$HOSTDEPS/lib"

# --- 1 ---
hr "1. ASan+UBSan debug build ($CC)"
# shellcheck disable=SC2086
build asan "$B-asan" $HOSTARGS -DCMAKE_BUILD_TYPE=Debug -DROUTEBOT_UNIT_TESTS=ON \
	-DCMAKE_C_FLAGS="$SAN" -DCMAKE_EXE_LINKER_FLAGS="$SAN"
note "ok    1. sanitized build: $WARN warnings"

# --- 2 ---
hr "2. unit tests"
NT=$(ctest --test-dir "$B-asan" -N 2>/dev/null | sed -n 's/^Total Tests: //p')
if [ "${NT:-0}" = 0 ]; then
	echo "no unit tests (add tests/unit/test_*.c)"
	note "ok    2. unit tests: none yet"
else
	ctest --test-dir "$B-asan" --output-on-failure -j "$JOBS" || die "2. unit tests"
	note "ok    2. unit tests: $NT passed"
fi

# --- 3 ---
hr "3. tests/netns.sh (sanitized)"
# LeakSanitizer stops the world with ptrace; make sure that works in the
# user namespace netns.sh runs in, or leaks would pass unnoticed
printf '#include <stdlib.h>\nvoid *p;\nint main(void) { p = malloc(7); p = 0; return 0; }\n' > "$B-asan/leak.c"
$CC $SAN -o "$B-asan/leak" "$B-asan/leak.c" ||
	die "3. can't build the LSan probe"
unshare -rn "$B-asan/leak" > "$B-asan/leak.out" 2>&1
_rc=$?
if [ "$_rc" = 23 ] && grep -q "LeakSanitizer: detected memory leaks" "$B-asan/leak.out"; then
	LSAN="works in the user namespace (probe leak caught, exit 23)"
else
	LSAN="NOT working in the user namespace (probe exit $_rc): leaks are not checked"
	cat "$B-asan/leak.out"
	die "3. LeakSanitizer doesn't work here; fix the environment rather than gate without it"
fi
echo "LSan: $LSAN"
# SHOW_LOG: the sanitizer reports land in routebot's log, which netns.sh
# only prints on failure; it greps for ASan and UBSan, not for leaks after
# a refused start (exit 1 either way), so look at the log here as well
SHOW_LOG=1 "$ROOT/tests/netns.sh" "$B-asan/routebot" > "$B-asan/netns.out" 2>&1
_rc=$?
if [ "$_rc" != 0 ]; then
	cat "$B-asan/netns.out"
	die "3. netns.sh failed"
fi
SHOW_LOG=1 "$ROOT/tests/flush.sh" "$B-asan/routebot" >> "$B-asan/netns.out" 2>&1 || { cat "$B-asan/netns.out"; die "3. flush.sh failed"; }
if grep -q "Sanitizer\|runtime error:" "$B-asan/netns.out"; then
	grep -B2 -A20 "Sanitizer\|runtime error:" "$B-asan/netns.out"
	die "3. sanitizer reports in the netns.sh log"
fi
_ok=$(grep -c '^ok ' "$B-asan/netns.out")
echo "netns.sh: $_ok checks passed, no sanitizer reports"
note "ok    3. netns.sh (ASan+UBSan+LSan): $_ok checks"

# --- 4 ---
hr "4. release build + bench"
# shellcheck disable=SC2086
build release "$B-release" $HOSTARGS -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS_RELEASE=-DNDEBUG \
	-DCMAKE_C_FLAGS="-O2 -g $HARDEN" -DCMAKE_EXE_LINKER_FLAGS="$RELRO"
_rw=$WARN
HOSTDEPS=$HOSTDEPS "$ROOT/tests/bench/bench.sh" "$B-release/routebot" "$B-release/bench.json" ||
	die "4. bench.sh failed (see above; results in $B-release/bench.json)"
python3 -I "$ROOT/tests/bench/compare.py" "$ROOT/tests/bench/baseline.json" "$B-release/bench.json" ||
	die "4. bench regressed against tests/bench/baseline.json"
note "ok    4. release build: $_rw warnings; bench within limits ($B-release/bench.json)"

# --- 5 ---
hr "5. OpenWrt SDK cross build"
ST=$OPENWRT_SDK/staging_dir
TC=$(ls -d "$ST"/toolchain-* 2>/dev/null | head -n 1)
TG=$(ls -d "$ST"/target-* 2>/dev/null | head -n 1)
[ -n "$TC" ] && [ -n "$TG" ] || die "5. no OpenWrt SDK toolchain under $ST"
XCC=$(ls "$TC"/bin/*-openwrt-linux-musl-gcc 2>/dev/null | head -n 1)
[ -n "$XCC" ] || die "5. no *-openwrt-linux-musl-gcc in $TC/bin"
# the SDK config's TARGET_OPTIMIZATION and CPU, as the package build uses
XOPT=$(sed -n 's/^CONFIG_TARGET_OPTIMIZATION="\(.*\)"/\1/p' "$OPENWRT_SDK/.config" 2>/dev/null)
export STAGING_DIR="$ST"
# shellcheck disable=SC2086
build cross "$B-cross" -DCMAKE_SYSTEM_NAME=Linux \
	-DCMAKE_SYSTEM_PROCESSOR="$(basename "$XCC" | cut -d- -f1)" -DCMAKE_C_COMPILER="$XCC" \
	-DCMAKE_FIND_ROOT_PATH="$TG;$TC" -DCMAKE_FIND_ROOT_PATH_MODE_PROGRAM=NEVER \
	-DCMAKE_FIND_ROOT_PATH_MODE_LIBRARY=ONLY -DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=ONLY \
	-DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS_RELEASE=-DNDEBUG \
	-DCMAKE_C_FLAGS="${XOPT:--Os -pipe} $HARDEN" -DCMAKE_EXE_LINKER_FLAGS="$RELRO"
note "ok    5. cross build ($(basename "$XCC")): $WARN warnings, $(stat -c %s "$B-cross/routebot") bytes unstripped"

summary 0
