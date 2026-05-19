#!/usr/bin/env bash
# catch-all.sh - Extremely broad outbound network sweep for human review.
# Dumps every internet socket on the machine.  Legitimate traffic is
# expected to dominate the output; the goal is to surface anything
# anomalous for a person to investigate.
#
# Run with sudo to see all users' sockets.  Without sudo, only the
# current user's sockets are visible.

set -u

echo "================================================================"
echo " Catch-all network sweep"
echo " host: $(hostname)  user: $(whoami)  time: $(date '+%Y-%m-%d %H:%M:%S')"
echo "================================================================"
echo

if [ "$(id -u)" -ne 0 ]; then
  echo "(running as $(whoami); rerun with sudo for full coverage)"
  echo
fi

echo "[1] ESTABLISHED outbound TCP connections (hostnames resolved)"
echo "----------------------------------------------------------------"
lsof -P -iTCP -sTCP:ESTABLISHED 2>/dev/null

echo
echo "[2] LISTENing TCP sockets (incoming-ready, includes any backdoor listener)"
echo "----------------------------------------------------------------"
lsof -P -iTCP -sTCP:LISTEN 2>/dev/null

echo
echo "[3] UDP sockets (DNS, NTP, mDNS, plus any UDP-tunneled C2)"
echo "----------------------------------------------------------------"
lsof -P -iUDP 2>/dev/null

echo
echo "[4] Unique <process, remote endpoint> pairs from established TCP"
echo "----------------------------------------------------------------"
# Note: "--" terminates grep's option parsing so the literal "->" pattern
# isn't misread as a flag (it starts with '-').
lsof -P -iTCP -sTCP:ESTABLISHED 2>/dev/null \
  | grep -F -- "->" \
  | awk '{ print $1, $9 }' \
  | sort -u

echo
echo "[5] ps command line for every process holding a network socket"
echo "----------------------------------------------------------------"
lsof -t -i 2>/dev/null | sort -u | while read -r pid; do
  [ -z "$pid" ] && continue
  ps -p "$pid" -o pid=,user=,command= 2>/dev/null
done

echo
echo "[6] Binary paths (resolved) for every process holding a network socket"
echo "----------------------------------------------------------------"
# `ps -p $pid -o comm=` returns the full executable path on macOS for any
# visible process, and "comm=" gives one value with no header.  The path
# is a single value per row even when it contains spaces, so no parsing
# trouble.  Avoid `lsof -p` here: without sudo, lsof for a PID you don't
# own silently falls back to its own process's txt mapping instead of
# erroring, which produces wrong-but-confident output.
lsof -t -i 2>/dev/null | sort -u | while read -r pid; do
  [ -z "$pid" ] && continue
  exe=$(ps -p "$pid" -o comm= 2>/dev/null | head -1)
  printf "  %-7s %s\n" "$pid" "$exe"
done

echo
echo "================================================================"
echo " End of sweep.  Review sections [1], [4], and [6] for unfamiliar"
echo " process names, unusual binary paths (under /tmp, /var/tmp,"
echo " hidden dotdirs, user homes), or remote hosts you don't recognize."
echo "================================================================"
