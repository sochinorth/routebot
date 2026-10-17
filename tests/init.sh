#!/bin/sh
# The init script's stop logic, with procd and the daemon stubbed: stop and
# shutdown flush once the daemon is gone, restart doesn't.
# usage: tests/init.sh
set -eu

INIT=$(cd "$(dirname "$0")/.." && pwd)/openwrt/routebot/files/routebot.init
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
FAILS=0
pass() { echo "ok   $*"; }
fail() { echo "FAIL $*"; FAILS=$((FAILS + 1)); }

# stubs: pidof sees the daemon for $T/alive more polls, sleep doesn't
mkdir "$T/bin"
cat > "$T/bin/pidof" <<EOF
#!/bin/sh
n=\$(cat "$T/alive")
echo pidof >> "$T/calls"
[ "\$n" -gt 0 ] || exit 1
echo \$((n - 1)) > "$T/alive"
echo 42
EOF
cat > "$T/bin/sleep" <<EOF
#!/bin/sh
echo sleep >> "$T/calls"
EOF
cat > "$T/bin/routebot" <<EOF
#!/bin/sh
echo "routebot \$*" >> "$T/calls"
EOF
chmod +x "$T/bin/pidof" "$T/bin/sleep" "$T/bin/routebot"
PATH=$T/bin:$PATH

# rc.common's procd stop(), with action set as rc.common sets it
# run ACTION POLLS: the daemon is seen for POLLS polls after procd_kill
run() {
	: > "$T/calls"
	echo "$2" > "$T/alive"
	(
		action=$1
		procd_kill() { echo procd_kill >> "$T/calls"; }
		# shellcheck disable=SC1090
		. "$INIT"
		PROG=routebot
		procd_kill routebot
		service_stopped
	)
	tr '\n' ' ' < "$T/calls" | sed 's/ $//'
}

check() {
	_got=$(run "$1" "$2")
	if [ "$_got" = "$3" ]; then pass "$1, daemon gone after $2 polls: $_got"
	else fail "$1, daemon gone after $2 polls: got '$_got', want '$3'"; fi
}

F="routebot -F -c /etc/config/routebot"
check stop 0 "procd_kill pidof $F"
check stop 2 "procd_kill pidof sleep pidof sleep pidof $F"
check shutdown 1 "procd_kill pidof sleep pidof $F"
# never gone (procd SIGKILLs it at term_timeout, 5): flush after 6 sleeps
check stop 99 "procd_kill $(printf 'pidof sleep %.0s' 1 2 3 4 5 6)pidof $F"
check restart 1 "procd_kill"

echo
[ "$FAILS" = 0 ] && echo "all passed" || { echo "$FAILS failed"; exit 1; }
