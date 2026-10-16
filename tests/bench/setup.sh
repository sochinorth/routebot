# Bench setup shared by bench.sh and validate.sh, sourced after tests/lib.sh
# with HERE (this directory), HOSTDEPS and PY set. Builds the mallocstat
# shim ($SHIM), the topology, starts ubusd ($UBUSD, $UBUS), generates the
# lists ($L) and writes $T/config. Sets V4, V6 and CONFLICTS from the
# generator's manifest.

L=$T/lists
UBUSD=

on_cleanup() {
	[ -n "$UBUSD" ] && kill "$UBUSD" 2>/dev/null || true
}

# --- the shim ---
if [ -n "${MALLOCSTAT_SO:-}" ]; then
	SHIM=$(realpath "$MALLOCSTAT_SO")
else
	SHIM=$T/mallocstat.so
	${CC:-cc} -O2 -fPIC -shared -o "$SHIM" "$HERE/mallocstat.c"
fi

# --- topology ---
# warp0: NOARP dummy; wan0: veth, gateway from main; p1..p3: veths, gateways
# from main with distinct metrics; q1, q2: NOARP dummies
ip link set lo up
ip link add warp0 type dummy
ip link set warp0 arp off up
ip link add wan0 type veth peer name wanp
ip addr add 192.0.2.2/24 dev wan0
ip -6 addr add 2001:db8::2/64 dev wan0 nodad
ip link set wanp up
ip link set wan0 up
ip route add default via 192.0.2.1 dev wan0 metric 10
ip -6 route add default via 2001:db8::1 dev wan0 metric 10
for i in 1 2 3; do
	ip link add p$i type veth peer name pp$i
	ip addr add 10.1.$i.2/24 dev p$i
	ip -6 addr add 2001:db8:1:$i::2/64 dev p$i nodad
	ip link set pp$i up
	ip link set p$i up
	ip route add default via 10.1.$i.1 dev p$i metric 10$i
	ip -6 route add default via 2001:db8:1:$i::1 dev p$i metric 10$i
done
for i in 1 2; do
	ip link add q$i type dummy
	ip link set q$i arp off up
done

# netifd lookups go through ubus as on OpenWrt; without a ubusd routebot
# would retry connecting every 3 s, which is noise in every measurement
if [ -x "$HOSTDEPS/sbin/ubusd" ]; then
	# ubusd insists on creating /var/run/ubus even with -s: give it a
	# private /run (a unix socket path works across network namespaces)
	LD_LIBRARY_PATH=$HOSTDEPS/lib unshare -rm sh -c \
		'mount -t tmpfs none /run && exec "$0" -s "$1"' \
		"$HOSTDEPS/sbin/ubusd" "$T/ubus.sock" 2>/dev/null &
	UBUSD=$!
	for _ in $(seq 50); do [ -S "$T/ubus.sock" ] && break; sleep 0.1; done
	UBUS=true
else
	echo "bench: no ubusd in $HOSTDEPS/sbin: routebot will retry ubus every 3s (noisy)"
	UBUS=false
fi

# --- workload ---
$PY "$HERE/genlists.py" "$L" > /dev/null
cp "$L/misc/m03.lst" "$T/m03.orig"
mf() { $PY -c 'import json,sys; m=json.load(open(sys.argv[1])); print(eval(sys.argv[2], {}, m))' "$L/manifest.json" "$1"; }
V4=$(mf 'routes["total"]["v4"]')
V6=$(mf 'routes["total"]["v6"]')
CONFLICTS=$(mf conflicts)

cat > "$T/config" <<EOF
config routebot

config group 'warp'
	list device 'warp0'
	option fwmark '0x10'

config group 'wan'
	list device 'wan0'
	option fwmark '0xaa'

config group 'pool'
	list device 'p1'
	list device 'p2:2'
	list device 'p3'
	option fwmark '0x20'
	option buckets '512'

config group 'pool2'
	list device 'q1'
	list device 'q2'
	option fwmark '0x30'

config rule 'big'
	option group 'pool'
	list cidrset '$L/big/*.lst'

config rule 'asn'
	option group 'warp'
	list cidrset '$L/asn/as13335.lst'

config rule 'misc'
	option group 'wan'
	list cidrset '$L/misc/*'
EOF
