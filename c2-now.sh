#!/usr/bin/env bash
# c2-now.sh - One-shot check: is the blockchain C2 malware running on this
# machine RIGHT NOW.  Scans ALL processes (no "node" pre-filter), uses
# ps -wwax to avoid command-line truncation, and checks outbound network
# connections from any process via two paths (reverse-DNS substring and
# forward-resolution per known C2 host).
#
# All string matching is fixed-string (grep -F), no regex.

set -u

found=0

indent() {
  while IFS= read -r line; do
    printf "    %s\n" "$line"
  done
}

echo "================================================================"
echo " C2 live-process scan"
echo " host: $(hostname)  user: $(whoami)  time: $(date '+%Y-%m-%d %H:%M:%S')"
echo "================================================================"

# Full process list: -ww disables truncation, -ax shows all processes,
# -o pid=,user=,command= drops the column headers and gives us full argv.
ps_output=$(ps -wwaxo pid=,user=,command= 2>/dev/null \
  | grep -F -v "active-scan" \
  | grep -F -v "malware-check.sh" \
  | grep -F -v "c2-now.sh")

echo
echo "[1/3] Obfuscation signatures in any running process command line..."
hit=0
sig1=$(echo "$ps_output" | grep -F -e "-e" | grep -F "global[" || true)
sig2=$(echo "$ps_output" | grep -F "_V" | grep -F "=-22" || true)
sig3=$(echo "$ps_output" | grep -F "Gez(" || true)
if [ -n "$sig1" ]; then echo "  HIT eval+global[]:"; echo "$sig1" | indent; hit=1; fi
if [ -n "$sig2" ]; then echo "  HIT _V / =-22:";     echo "$sig2" | indent; hit=1; fi
if [ -n "$sig3" ]; then echo "  HIT Gez():";          echo "$sig3" | indent; hit=1; fi
if [ $hit -eq 1 ]; then found=$((found+1)); else echo "  Clean."; fi

echo
echo "[2/3] Wallet addresses or campaign IDs in any running process command line..."
wallets=$(echo "$ps_output" | grep -F \
  -e "TMfKQEd7TJJa5xNZJZ2Lep" \
  -e "TXfxHUet9pJVU1BgVkBAb" \
  -e "TLmj13VL4p6NQ7jpxz8d9" \
  -e "0xbe037400670fbf1c" \
  -e "0x3f0e5781d0855fb" \
  -e "0x9bc1355344b54de" \
  -e "A7-2259" \
  -e "5-022526" \
  -e "C5-022526" || true)
if [ -n "$wallets" ]; then
  echo "  HIT:"
  echo "$wallets" | indent
  found=$((found+1))
else
  echo "  Clean."
fi

echo
echo "[3/3] Outbound network connections to known C2 hosts (any process)..."

# Path A: lsof reverse-DNS output, fixed-string substring match.
lsof_dns=$(lsof -i -P 2>/dev/null \
  | grep -F -v "active-scan" \
  | grep -F -i \
    -e "trongrid" \
    -e "aptoslabs" \
    -e "bsc-dataseed" \
    -e "publicnode" \
    -e "136.0.9.8" || true)

# Path B: forward-resolve each known C2 host so lsof matches against
# current IPs even when PTR records don't include the hostname.
lsof_fwd=""
for host in trongrid.io aptoslabs.com bsc-dataseed.binance.org publicnode.com; do
  out=$(lsof -i "@$host" -P 2>/dev/null | grep -F -v "active-scan" || true)
  if [ -n "$out" ]; then
    lsof_fwd="${lsof_fwd}--- via @${host} ---
${out}
"
  fi
done

if [ -n "$lsof_dns" ] || [ -n "$lsof_fwd" ]; then
  if [ -n "$lsof_dns" ]; then
    echo "  HIT (lsof output substring match):"
    echo "$lsof_dns" | indent
  fi
  if [ -n "$lsof_fwd" ]; then
    echo "  HIT (forward-resolved hostname):"
    echo "$lsof_fwd" | indent
  fi
  found=$((found+1))
else
  echo "  Clean."
fi

echo
echo "================================================================"
if [ "$found" -gt 0 ]; then
  echo " RESULT: $found indicator group(s) matched. Investigate above."
  exit 1
else
  echo " RESULT: no live C2 indicators detected."
  echo " Note: this checks only this user's visible processes;"
  echo "       re-run with sudo to include other users' processes."
  exit 0
fi
