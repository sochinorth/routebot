#!/usr/bin/env python3
"""Analysis half of validate.sh; see there.

usage: validate.py ROUTEBOT COUNTERS_A MTRACE_LOG COUNTERS_C BT_LOG STRACE_LOG
"""
import os
import re
import subprocess
import sys

sys.dont_write_bytecode = True	# no __pycache__ in the tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rbstat  # noqa: E402

PAGE = 4096
fails = 0


def check(ok, what):
	global fails
	print(("ok   " if ok else "FAIL ") + what)
	fails += not ok


def mtrace_totals(path):
	"""Counts from glibc's mtrace log: '+' alloc, '-' free, '<' '>' realloc halves."""
	allocs = frees = nbytes = 0
	for line in open(path, errors="replace"):
		# "@ caller op addr [size]"
		f = line.split()
		if len(f) < 4 or f[0] != "@":
			continue
		op, rest = f[2], f[3:]
		if op in ("+", ">"):
			allocs += 1
			nbytes += int(rest[1], 16) if len(rest) > 1 else 0
		elif op in ("-", "<"):
			frees += 1
	return allocs, frees, nbytes


def bt_records(path):
	"""[(fn, size, [frames])] from the shim's backtrace log."""
	recs, cur = [], None
	for line in open(path, errors="replace"):
		line = line.rstrip("\n")
		if line.startswith("alloc "):
			_, fn, size = line.split()
			cur = (fn, int(size), [])
			recs.append(cur)
		elif line and cur:
			cur[2].append(line)
		else:
			cur = None
	return recs


def where(rb, frames):
	"""First routebot frame as file:line (function)."""
	base = os.path.basename(rb)
	for fr in frames:
		m = re.match(r"(.*)\((?:[^)+]*)\+(0x[0-9a-f]+)\)", fr)
		if not m or os.path.basename(m.group(1)) != base:
			continue
		out = subprocess.run(["addr2line", "-f", "-C", "-e", rb, hex(int(m.group(2), 16) - 1)],
				     capture_output=True, text=True).stdout.split("\n")
		if len(out) >= 2 and not out[1].startswith("??"):
			fn, loc = out[0], out[1].split(" ")[0]
			return f"{os.path.relpath(loc) if loc.startswith('/') else loc} ({fn})"
	return "?"


def syscalls(path):
	"""Anonymous mmaps and mremaps of the traced routebot, in order: [(kind, size)]."""
	out, brk = [], []
	for line in open(path, errors="replace"):
		if "execve(" in line:	# env's own calls don't count
			out, brk = [], []
			continue
		m = re.search(r"mmap\(NULL, (\d+), PROT_READ\|PROT_WRITE, MAP_PRIVATE\|MAP_ANONYMOUS, -1, 0\) = 0x", line)
		if m:
			out.append(("mmap", int(m.group(1))))
			continue
		m = re.search(r"mremap\(0x[0-9a-f]+, (\d+), (\d+), MREMAP_MAYMOVE\) = 0x", line)
		if m:
			out.append(("mremap", int(m.group(2))))
			continue
		m = re.search(r"brk\((0x[0-9a-f]+)\) += (0x[0-9a-f]+)", line)
		if m:
			brk.append(int(m.group(2), 16))
	return out, brk


def main():
	rb, ca, mlog, cc, btlog, slog = sys.argv[1:7]

	a = rbstat.counters(ca)
	allocs, frees, nbytes = mtrace_totals(mlog)
	print(f"     shim:   {a['n_allocs']} allocs, {a['n_free']} frees, {a['bytes']} bytes")
	print(f"     mtrace: {allocs} allocs, {frees} frees, {nbytes} bytes")
	# mtrace starts in a constructor and stops at exit: a few allocations of
	# the loader and libc init are outside its window
	check(0 <= a["n_allocs"] - allocs <= 8, f"alloc counts agree (shim - mtrace = {a['n_allocs'] - allocs})")
	check(abs(a["n_free"] - frees) <= 8, f"free counts agree (shim - mtrace = {a['n_free'] - frees})")
	check(abs(a["bytes"] - nbytes) <= 64 * 1024, f"bytes agree (shim - mtrace = {a['bytes'] - nbytes})")

	c = rbstat.counters(cc)
	check(c["n_allocs"] == a["n_allocs"] and c["bytes"] == a["bytes"],
	      f"backtrace mode counts the same ({c['n_allocs']} allocs, {c['bytes']} bytes)")

	recs = bt_records(btlog)
	check(len(recs) == c["n_big"], f"{len(recs)} backtraces for {c['n_big']} big allocations")
	sc, brk = syscalls(slog)
	heap = max(brk) - min(brk) if brk else 0
	print(f"     strace: {len(sc)} anonymous mmap/mremap; brk heap peaked at {heap // 1024} KiB")

	# pair each big allocation with the next syscall of a matching size;
	# glibc's mmap threshold grows after frees, so later ones come from brk
	j = matched = 0
	sites, from_heap, first_big_hit = {}, [], None
	print("     big allocations, in order:")
	for fn, size, frames in recs:
		hit = ""
		for k in range(j, len(sc)):
			if size <= sc[k][1] <= size + PAGE + 64:
				hit = f"{sc[k][0]} {sc[k][1]}"
				j, matched = k + 1, matched + 1
				break
		if not hit:
			from_heap.append(size)
		if first_big_hit is None and size >= 128 * 1024:
			first_big_hit = bool(hit)
		loc = where(rb, frames)
		sites.setdefault(loc, []).append(size)
		print(f"       {fn:8} {size:>9}  {hit or 'heap (brk)':>16}  {loc}")
	print("     by call site:")
	for loc, sizes in sorted(sites.items(), key=lambda kv: -sum(kv[1])):
		print(f"       {len(sizes):3}x {sum(sizes) / 1024:9.0f} KiB  max {max(sizes) / 1024:7.0f} KiB  {loc}")
	check(bool(first_big_hit),
	      f"{matched} of {len(recs)} big allocations seen as mmap/mremap of matching size, "
	      "the first >= 128 KiB one included")
	check(max(from_heap, default=0) <= heap,
	      f"the rest fit the brk heap ({max(from_heap, default=0) // 1024} <= {heap // 1024} KiB)")
	unmatched_sc = [s for s in sc[j:] if s[1] >= 1 << 20]
	check(not unmatched_sc, f"no unexplained >= 1 MiB mmaps after the last match ({len(unmatched_sc)})")
	sys.exit(1 if fails else 0)


if __name__ == "__main__":
	main()
