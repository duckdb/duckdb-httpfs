#!/usr/bin/env bash
# run_with_watchdog.sh — run a command under a stall / hard-timeout watchdog.
#
# Why: the MinIO integration job can wedge on a single unittest for the full 6h
# GitHub cap with no indication of WHICH test or WHY. This wrapper streams the
# child's output live (so the CI log is unchanged on a healthy run) and watches
# it. If the child produces NO output for WATCHDOG_STALL_SECS it dumps an
# all-thread backtrace, then re-arms so a second backtrace is captured a while
# later. Two backtraces make the failure mode obvious:
#   * identical stacks parked on a mutex  -> a real deadlock
#   * stacks moving / parked in curl poll -> a slow network wait, not a lock
# After WATCHDOG_MAX_SECS it hard-kills the child and fails, so the job dies in
# minutes with evidence instead of burning the 6h cap silently.
#
# Usage: scripts/run_with_watchdog.sh <cmd> [args...]
#
# Tunables (env):
#   WATCHDOG_STALL_SECS  no-output window that triggers a backtrace dump (def 240)
#   WATCHDOG_MAX_SECS    hard cap; kill + fail after this many seconds  (def 1800)
#   WATCHDOG_POLL_SECS   how often to check for progress                (def 10)
set -uo pipefail

STALL_SECS="${WATCHDOG_STALL_SECS:-240}"
MAX_SECS="${WATCHDOG_MAX_SECS:-1800}"
POLL="${WATCHDOG_POLL_SECS:-10}"

LOG="$(mktemp)"

# stdbuf -oL -eL: line-buffer the child so stall detection sees progress in real
# time even though stdout is a pipe. tee: keep the live CI log while we watch the
# file. stdbuf exec's the target, so $! is the child (e.g. unittest) PID.
stdbuf -oL -eL "$@" > >(tee "$LOG") 2>&1 &
PID=$!

dump() {
	echo "::group::WATCHDOG DUMP — $1"
	echo ">>> $1 (elapsed ${SECONDS}s)"
	echo ">>> last output lines (identify the running test):"
	tail -n 5 "$LOG" | sed 's/^/    /'
	echo ">>> all-thread backtrace of pid ${PID}:"
	if command -v gdb >/dev/null 2>&1; then
		sudo gdb -p "$PID" -batch \
			-ex "set pagination off" \
			-ex "thread apply all bt" 2>&1 | sed 's/^/    /'
	elif command -v eu-stack >/dev/null 2>&1; then
		sudo eu-stack -p "$PID" 2>&1 | sed 's/^/    /'
	else
		echo "    (neither gdb nor eu-stack installed — cannot backtrace)"
	fi
	echo "::endgroup::"
}

last_size=-1
stall=0
while kill -0 "$PID" 2>/dev/null; do
	sleep "$POLL"
	sz="$(wc -c < "$LOG" 2>/dev/null || echo 0)"
	if [ "$sz" = "$last_size" ]; then
		stall=$((stall + POLL))
	else
		stall=0
		last_size="$sz"
	fi
	if [ "$stall" -ge "$STALL_SECS" ]; then
		dump "STALLED ${stall}s with no output"
		stall=0
	fi
	if [ "$SECONDS" -ge "$MAX_SECS" ]; then
		dump "HARD TIMEOUT ${MAX_SECS}s — killing"
		kill -9 "$PID" 2>/dev/null
		wait "$PID" 2>/dev/null
		exit 124
	fi
done

wait "$PID"
rc=$?
echo ">>> WATCHDOG: process exited rc=${rc} after ${SECONDS}s"
exit "$rc"
