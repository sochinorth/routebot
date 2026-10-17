#!/usr/bin/env python3
"""Compare two bench.sh results.

usage: compare.py BASELINE.json CURRENT.json

Prints baseline, current and delta for every metric. Fails (exit 1) when the
current run is broken or incomplete, ran a different workload, or regressed
by more than 10% in
  - memory: VmRSS, RssAnon, VmHWM of any phase
  - per-unit allocations or bytes allocated
unless the regression is below an absolute floor (64 KiB of memory, 2
allocations, 1 KiB allocated per unit), so noise in tiny numbers passes.
CPU and wall time are printed for information only: never gated.
"""
import json
import sys

LIMIT = 0.10
GATED_MEM = ("VmRSS_kB", "RssAnon_kB", "VmHWM_kB")
GATED_UNIT = ("allocs", "bytes")
FLOOR = {"VmRSS_kB": 64, "RssAnon_kB": 64, "VmHWM_kB": 64, "allocs": 2, "bytes": 1024}
INFO_MEM = ("RssFile_kB", "heap_live_kB", "heap_peak_kB")
INFO_UNIT = ("frees", "reallocs", "cpu_ms", "user_ms", "sys_ms", "sched_cpu_ms", "wall_ms")


def load(path):
	with open(path) as f:
		return json.load(f)


def fmt(v):
	if v is None:
		return "-"
	if isinstance(v, float) and v != int(v):
		return f"{v:,.2f}" if abs(v) < 100 else f"{v:,.0f}"
	return f"{int(v):,}"


def main():
	if len(sys.argv) != 3:
		sys.exit(__doc__)
	base, cur = load(sys.argv[1]), load(sys.argv[2])
	problems = []

	if not cur.get("ok"):
		problems.append("current run is not ok (a check failed or routebot crashed)")
	if cur.get("meta", {}).get("exit_status") not in ("0", 0):
		problems.append(f"routebot exit status {cur.get('meta', {}).get('exit_status')}")
	bw, cw = base.get("workload", {}).get("sha256"), cur.get("workload", {}).get("sha256")
	if bw != cw:
		problems.append(f"workload differs (baseline {bw}, current {cw}): regenerate the baseline")
	if base.get("meta", {}).get("ubus") != cur.get("meta", {}).get("ubus"):
		problems.append("one run had ubusd and the other didn't")

	rows = []

	def row(section, name, metric, b, c, gated):
		status = ""
		if c is None:
			status = "MISSING"
			if b is not None:
				problems.append(f"{section} {name}: {metric} missing")
		elif b is not None:
			if gated:
				over = c - b
				if b and over > b * LIMIT and over >= FLOOR[metric]:
					status = "FAIL"
					problems.append(f"{section} {name}: {metric} {fmt(b)} -> {fmt(c)} "
							f"(+{over / b * 100:.1f}%)")
				elif not b and over >= FLOOR[metric]:
					status = "FAIL"
					problems.append(f"{section} {name}: {metric} 0 -> {fmt(c)}")
				else:
					status = "ok"
			else:
				status = "info"
		delta = ""
		if b is not None and c is not None:
			delta = f"{(c - b) / b * 100:+.1f}%" if b else ("0" if c == b else "new")
		rows.append((f"{section}:{name}", metric, fmt(b), fmt(c), delta, status))

	bmeta = base.get("meta", {})
	phases = [p for p in bmeta.get("phases", []) if p in base.get("memory", {})]
	phases += [p for p in base.get("memory", {}) if p not in phases]
	units = [u for u in ["startup"] + bmeta.get("units", []) if u in base.get("units", {})]
	units += [u for u in base.get("units", {}) if u not in units]

	for phase in phases:
		bm = base["memory"][phase]
		cm = cur.get("memory", {}).get(phase, {})
		for k in GATED_MEM + INFO_MEM:
			if k in bm or k in cm:
				row("mem", phase, k, bm.get(k), cm.get(k), k in GATED_MEM)
	for unit in units:
		bu = base["units"][unit]
		cu = cur.get("units", {}).get(unit, {})
		for k in GATED_UNIT + INFO_UNIT:
			if k in bu or k in cu:
				row("unit", unit, k, bu.get(k), cu.get(k), k in GATED_UNIT)
	for sec in ("shutdown", "flush"):
		bs, cs = base.get(sec, {}), cur.get(sec, {})
		for k in ("allocs", "bytes", "VmHWM_kB", "heap_peak_kB", "cpu_ms", "user_ms",
			  "sys_ms", "sched_cpu_ms", "wall_ms"):
			if k in bs or k in cs:
				row(sec, "", k, bs.get(k), cs.get(k), False)

	w = [max(len(r[i]) for r in rows + [("where", "metric", "baseline", "current", "delta", "")])
	     for i in range(6)]
	head = ("where", "metric", "baseline", "current", "delta", "")
	for r in [head] + rows:
		print(f"{r[0]:<{w[0]}}  {r[1]:<{w[1]}}  {r[2]:>{w[2]}}  {r[3]:>{w[3]}}  {r[4]:>{w[4]}}  {r[5]}")

	print()
	if problems:
		print("compare: FAIL")
		for p in problems:
			print("  " + p)
		sys.exit(1)
	print(f"compare: ok (memory and allocations within {LIMIT:.0%} of the baseline; "
	      "CPU and wall time not gated)")


if __name__ == "__main__":
	main()
