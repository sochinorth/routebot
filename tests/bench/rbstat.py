#!/usr/bin/env python3
"""Sampling and reporting for tests/bench/bench.sh.

  rbstat.py snap    LABEL PID COUNTERS SNAPS
  rbstat.py quiesce LABEL PID COUNTERS SNAPS [--since NS] [--window MS] [--timeout S]
  rbstat.py report  SNAPS META OUT

snap appends one JSON line to SNAPS: the mallocstat counters (COUNTERS is
the shim's MALLOCSTAT_FILE), CPU time and memory of PID. PID may be gone,
then only the counters are recorded.

quiesce first waits until PID is idle, then snaps. Idle means, for WINDOW ms
in a row (default 300): the allocation counters, the scheduler's CPU time
(/proc/PID/schedstat, ns) and utime+stime are unchanged, and nothing is
pending: the process is not running or stopped, it sits in epoll_wait, no
signal is pending and none of its netlink sockets has unread data. The
pending checks close the race where routebot hasn't even woken up yet when
we start looking. --since (epoch ns, taken before the action) makes it also
record how long the process stayed busy after it, for information.

report turns the snapshots into the result JSON ("Benchmark" in README.md).
"""
import json
import os
import struct
import sys
import time

# struct ms_counters in mallocstat.c
FIELDS = ["magic", "version", "n_malloc", "n_calloc", "n_realloc", "n_memalign", "n_free",
	  "n_allocs", "bytes", "live", "peak_live", "n_big", "n_failed"]
MAGIC = 0x3174617473636c6d
CLK_TCK = os.sysconf("SC_CLK_TCK")
# x86_64 epoll_wait, epoll_pwait, epoll_pwait2; aarch64 epoll_pwait, epoll_pwait2
EPOLL_NRS = {"x86_64": {232, 281, 441}, "aarch64": {22, 441}}.get(os.uname().machine, set())
MEM_KEYS = ["VmRSS", "RssAnon", "RssFile", "RssShmem", "VmHWM", "VmData", "VmSize"]


def counters(path):
	try:
		with open(path, "rb") as f:
			raw = f.read(8 * len(FIELDS))
	except OSError:
		return None
	if len(raw) < 8 * len(FIELDS):
		return None
	vals = dict(zip(FIELDS, struct.unpack(f"<{len(FIELDS)}Q", raw)))
	return vals if vals["magic"] == MAGIC else None


def read(path):
	with open(path) as f:
		return f.read()


def proc(pid):
	"""CPU and memory of pid, None if it is gone."""
	try:
		stat = read(f"/proc/{pid}/stat")
		status = read(f"/proc/{pid}/status")
		sched = read(f"/proc/{pid}/schedstat").split()
	except OSError:
		return None
	# comm may contain spaces and parens: split after the last ')'
	rest = stat[stat.rindex(")") + 2:].split()
	p = {"state": rest[0], "utime": int(rest[11]), "stime": int(rest[12]),
	     "sched_ns": int(sched[0])}
	for line in status.splitlines():
		k, _, v = line.partition(":")
		if k in MEM_KEYS:
			p[k + "_kB"] = int(v.split()[0])
		elif k in ("SigPnd", "ShdPnd"):
			p[k] = int(v, 16)
	return p


def pending(pid, p):
	"""Why pid isn't idle, or None."""
	if p["state"] not in ("S", "D"):
		return "state " + p["state"]
	if p.get("SigPnd") or p.get("ShdPnd"):
		return "signal pending"
	try:
		sc = read(f"/proc/{pid}/syscall").split()
		if sc[0] == "running" or (EPOLL_NRS and int(sc[0]) not in EPOLL_NRS):
			return "in syscall " + sc[0]
	except (OSError, IndexError, ValueError):
		pass
	try:
		inodes = set()
		for fd in os.listdir(f"/proc/{pid}/fd"):
			try:
				t = os.readlink(f"/proc/{pid}/fd/{fd}")
			except OSError:
				continue
			if t.startswith("socket:["):
				inodes.add(t[8:-1])
		for line in read(f"/proc/{pid}/net/netlink").splitlines()[1:]:
			f = line.split()
			if len(f) >= 10 and f[9] in inodes and int(f[4]):
				return "netlink rmem " + f[4]
	except OSError:
		pass
	return None


def snapshot(label, pid, cpath):
	s = {"label": label, "t": time.time()}
	c = counters(cpath)
	if c:
		s["ms"] = {k: c[k] for k in FIELDS[2:]}
	p = proc(pid)
	if p:
		s["proc"] = p
	return s


def append(path, s):
	with open(path, "a") as f:
		f.write(json.dumps(s) + "\n")


def quiesce(label, pid, cpath, since_ns, window_ms, timeout_s):
	t0 = time.monotonic()
	since = since_ns / 1e9 if since_ns else time.time()
	last_key, last_change, last_change_wall = None, t0, time.time()
	why = "not sampled"
	while True:
		now, now_wall = time.monotonic(), time.time()
		c = counters(cpath)
		p = proc(pid)
		if p is None:
			sys.exit(f"quiesce {label}: process {pid} is gone")
		key = (c and c["n_allocs"], c and c["n_free"], c and c["bytes"],
		       p["sched_ns"], p["utime"] + p["stime"])
		why = pending(pid, p)
		if key != last_key or why:
			last_key, last_change, last_change_wall = key, now, now_wall
		elif now - last_change >= window_ms / 1000:
			break
		if now - t0 > timeout_s:
			sys.exit(f"quiesce {label}: still busy after {timeout_s}s ({why or 'changing'})")
		time.sleep(0.01)
	s = snapshot(label, pid, cpath)
	# upper bound: includes our own startup when the work was already done
	s["busy_s"] = max(0.0, last_change_wall - since)
	return s


# --- report ---

def diff(a, b):
	"""b - a for one stretch of work: allocations and CPU."""
	d = {}
	if "ms" in a and "ms" in b:
		for k in ("n_allocs", "bytes", "n_free", "n_malloc", "n_calloc", "n_realloc", "n_memalign"):
			d[k] = b["ms"][k] - a["ms"][k]
	if "proc" in a and "proc" in b:
		d["utime"] = b["proc"]["utime"] - a["proc"]["utime"]
		d["stime"] = b["proc"]["stime"] - a["proc"]["stime"]
		d["cpu_ticks"] = d["utime"] + d["stime"]
		d["sched_ns"] = b["proc"]["sched_ns"] - a["proc"]["sched_ns"]
	return d


def per_unit(d, n, wall_s):
	r = {"n": n}
	if "n_allocs" in d:
		r["allocs"] = d["n_allocs"] / n
		r["bytes"] = d["bytes"] / n
		r["frees"] = d["n_free"] / n
		r["reallocs"] = d["n_realloc"] / n
	if "cpu_ticks" in d:
		r["cpu_ms"] = d["cpu_ticks"] * 1000 / CLK_TCK / n
		r["user_ms"] = d["utime"] * 1000 / CLK_TCK / n
		r["sys_ms"] = d["stime"] * 1000 / CLK_TCK / n
		r["sched_cpu_ms"] = d["sched_ns"] / 1e6 / n
	if wall_s is not None:
		r["wall_ms"] = wall_s * 1000 / n
	return r


def memory(s):
	m = {k + "_kB": s["proc"][k + "_kB"] for k in MEM_KEYS if k + "_kB" in s.get("proc", {})}
	if "ms" in s:
		m["heap_live_kB"] = round(s["ms"]["live"] / 1024)
		m["heap_peak_kB"] = round(s["ms"]["peak_live"] / 1024)
	return m


def report(snaps_path, meta_path, out_path):
	snaps = [json.loads(l) for l in read(snaps_path).splitlines() if l.strip()]
	meta = json.loads(read(meta_path))
	by = {}
	for s in snaps:
		by.setdefault(s["label"], []).append(s)
	res = {"schema": 1, "ok": bool(meta.pop("ok", False)), "meta": meta, "memory": {}, "units": {}}
	if meta.get("workload"):
		res["workload"] = meta.pop("workload")

	zero = {"label": "exec", "ms": {k: 0 for k in FIELDS[2:]},
		"proc": {"utime": 0, "stime": 0, "sched_ns": 0}}
	if "startup" in by:
		st = by["startup"][0]
		res["units"]["startup"] = per_unit(diff(zero, st), 1, st.get("busy_s"))
	for phase in meta.get("phases", []):
		if phase in by:
			res["memory"][phase] = memory(by[phase][-1])
	for unit in meta.get("units", []):
		begin, its = by.get(f"unit:{unit}:begin"), by.get(f"unit:{unit}")
		if not begin or not its:
			continue
		n = meta["n"]
		wall = sum(s.get("busy_s", 0) for s in its)
		res["units"][unit] = per_unit(diff(begin[-1], its[-1]), n, wall)
	if "exit" in by and "end" in by:
		d = diff(by["end"][-1], by["exit"][-1])
		ex = by["exit"][-1].get("ms", {})
		res["shutdown"] = {"allocs": d.get("n_allocs"), "bytes": d.get("bytes"),
				   "heap_live_at_exit_B": ex.get("live")}
	with open(out_path, "w") as f:
		json.dump(res, f, indent=1, sort_keys=True)
		f.write("\n")


def main():
	a = sys.argv[1:]
	if not a:
		sys.exit(__doc__)
	if a[0] == "snap" and len(a) == 5:
		append(a[4], snapshot(a[1], a[2], a[3]))
	elif a[0] == "quiesce" and len(a) >= 5:
		opts = dict(zip(a[5::2], a[6::2]))
		s = quiesce(a[1], a[2], a[3], int(opts.get("--since", 0)),
			    float(opts.get("--window", 300)), float(opts.get("--timeout", 120)))
		append(a[4], s)
	elif a[0] == "report" and len(a) == 4:
		report(a[1], a[2], a[3])
	else:
		sys.exit(__doc__)


if __name__ == "__main__":
	main()
