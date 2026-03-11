#!/usr/bin/env bash
# Active Monitor — Blockchain C2 Backdoor (A7-2259 / 5-022526 / C5-022526)
# Background daemon that detects, kills, and notifies on malware indicators.
# Install: bash active-monitor.sh install
# Uninstall: bash active-monitor.sh uninstall
# Run manually: bash active-monitor.sh run

set -euo pipefail

INTERVAL=30  # seconds between scans
LOG_DIR="$HOME/.local/share/active-scan"
LOG_FILE="$LOG_DIR/monitor.log"
PID_FILE="$LOG_DIR/monitor.pid"
PLIST_NAME="com.activescan.monitor"
PLIST_PATH="$HOME/Library/LaunchAgents/${PLIST_NAME}.plist"
SCRIPT_PATH="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"

# --- Process patterns ---
PROC_PATTERN='node.*-e.*global\[|node.*_V.*=.*-22|node.*Gez\('

# --- C2 network indicators ---
C2_PATTERN='trongrid|aptoslabs|bsc-dataseed|publicnode|136\.0\.9\.8'

# --- Wallet / case ID strings ---
WALLET_PATTERN='TMfKQEd7TJJa5xNZJZ2Lep|TXfxHUet9pJVU1BgVkBAb|TLmj13VL4p6NQ7jpxz8d9|0xbe037400670fbf1c|0x3f0e5781d0855fb|0x9bc1355344b54de|A7-2259|5-022526|C5-022526'

# --- Persistence patterns ---
PERSIST_PATTERN='node.*-e|trongrid|binance'

# --- Infected config patterns ---
CONFIG_PATTERN='global\["!"\]|_\$_c266|fromCharCode\(127\)'

mkdir -p "$LOG_DIR"

log() {
    local ts
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    echo "[$ts] $1" >> "$LOG_FILE"
}

notify() {
    local title="$1"
    local message="$2"
    osascript -e "display notification \"$message\" with title \"$title\" sound name \"Sosumi\"" 2>/dev/null || true
}

kill_pid() {
    local pid="$1"
    local info="$2"
    if kill -9 "$pid" 2>/dev/null; then
        log "KILLED PID $pid — $info"
        notify "Malware Killed" "PID $pid terminated: $info"
    else
        log "KILL FAILED PID $pid (already dead?) — $info"
    fi
}

scan_processes() {
    local hits
    hits=$(ps aux 2>/dev/null | grep -E "$PROC_PATTERN" | grep -v grep | grep -v "active-monitor" || true)
    if [ -n "$hits" ]; then
        log "DETECT: Malware process(es) found"
        echo "$hits" | while IFS= read -r line; do
            local pid
            pid=$(echo "$line" | awk '{print $2}')
            local cmd
            cmd=$(echo "$line" | awk '{for(i=11;i<=NF;i++) printf "%s ", $i; print ""}')
            log "  PID=$pid CMD=$cmd"
            kill_pid "$pid" "malware process: $cmd"
        done
        return 1
    fi
    return 0
}

scan_network() {
    local c2
    c2=$(lsof -i -nP 2>/dev/null | grep -i node | grep -iE "$C2_PATTERN" || true)
    if [ -n "$c2" ]; then
        log "DETECT: C2 network connection(s)"
        echo "$c2" | while IFS= read -r line; do
            local pid
            pid=$(echo "$line" | awk '{print $2}')
            local dest
            dest=$(echo "$line" | awk '{print $9}')
            log "  PID=$pid DEST=$dest"
            kill_pid "$pid" "C2 connection to $dest"
        done
        return 1
    fi
    return 0
}

scan_persistence() {
    # Crontab
    local cron
    cron=$(crontab -l 2>/dev/null | grep -iE "$PERSIST_PATTERN" || true)
    if [ -n "$cron" ]; then
        log "DETECT: Suspicious crontab entry: $cron"
        notify "Malware Persistence" "Suspicious crontab entry detected — manual removal needed"
    fi

    # LaunchAgents (skip our own plist)
    if [ -d "$HOME/Library/LaunchAgents" ]; then
        local la
        la=$(grep -rl -iE "$PERSIST_PATTERN" "$HOME/Library/LaunchAgents/" 2>/dev/null | grep -v "$PLIST_NAME" || true)
        if [ -n "$la" ]; then
            log "DETECT: Suspicious LaunchAgent(s): $la"
            notify "Malware Persistence" "Suspicious LaunchAgent detected: $la"
        fi
    fi
}

scan_configs() {
    local scan_dirs=("$HOME/Documents" "$HOME/projects" "$HOME/code" "$HOME/Code" "$HOME/repos" "$HOME/src" "$HOME/dev")
    for dir in "${scan_dirs[@]}"; do
        [ -d "$dir" ] || continue
        while IFS= read -r f; do
            if grep -qE "$CONFIG_PATTERN" "$f" 2>/dev/null; then
                log "DETECT: Infected config: $f"
                notify "Infected Config" "Malware payload in $f"
            fi
        done < <(find "$dir" -maxdepth 6 -name "next.config.*" -type f 2>/dev/null)
    done
}

run_scan() {
    local detections=0

    scan_processes || detections=$((detections + 1))
    scan_network || detections=$((detections + 1))
    scan_persistence
    # Config scan is expensive — run every 10th cycle (5 min at 30s interval)
    if [ "${CYCLE_COUNT:-0}" -eq 0 ] || [ $((CYCLE_COUNT % 10)) -eq 0 ]; then
        scan_configs
    fi

    if [ "$detections" -gt 0 ]; then
        log "SCAN COMPLETE: $detections threat category(ies) detected and handled"
    fi
}

monitor_loop() {
    log "Monitor started (PID $$, interval ${INTERVAL}s)"
    echo $$ > "$PID_FILE"
    CYCLE_COUNT=0

    trap 'log "Monitor stopped (PID $$)"; rm -f "$PID_FILE"; exit 0' SIGTERM SIGINT

    while true; do
        run_scan
        CYCLE_COUNT=$((CYCLE_COUNT + 1))
        sleep "$INTERVAL"
    done
}

do_install() {
    cat > "$PLIST_PATH" << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${PLIST_NAME}</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>${SCRIPT_PATH}</string>
        <string>run</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${LOG_DIR}/stdout.log</string>
    <key>StandardErrorPath</key>
    <string>${LOG_DIR}/stderr.log</string>
</dict>
</plist>
PLIST

    launchctl load "$PLIST_PATH" 2>/dev/null || true
    launchctl start "$PLIST_NAME" 2>/dev/null || true

    echo "Installed and started."
    echo "  Plist:    $PLIST_PATH"
    echo "  Log:      $LOG_FILE"
    echo "  Interval: ${INTERVAL}s"
    echo ""
    echo "Commands:"
    echo "  Status:    launchctl list | grep activescan"
    echo "  Stop:      launchctl stop $PLIST_NAME"
    echo "  Start:     launchctl start $PLIST_NAME"
    echo "  Uninstall: bash $SCRIPT_PATH uninstall"
    echo "  Logs:      tail -f $LOG_FILE"
}

do_uninstall() {
    launchctl stop "$PLIST_NAME" 2>/dev/null || true
    launchctl unload "$PLIST_PATH" 2>/dev/null || true
    rm -f "$PLIST_PATH"

    if [ -f "$PID_FILE" ]; then
        local pid
        pid=$(cat "$PID_FILE")
        kill "$pid" 2>/dev/null || true
        rm -f "$PID_FILE"
    fi

    echo "Uninstalled. Log files preserved at $LOG_DIR"
}

do_status() {
    if [ -f "$PID_FILE" ]; then
        local pid
        pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            echo "Running (PID $pid)"
            echo "Log: $LOG_FILE"
            if [ -f "$LOG_FILE" ]; then
                echo ""
                echo "Last 10 log entries:"
                tail -10 "$LOG_FILE"
            fi
            return 0
        fi
    fi
    echo "Not running"
    return 1
}

case "${1:-}" in
    run)
        monitor_loop
        ;;
    install)
        do_install
        ;;
    uninstall)
        do_uninstall
        ;;
    status)
        do_status
        ;;
    scan)
        echo "Running single scan..."
        CYCLE_COUNT=0
        run_scan
        echo "Done. Check $LOG_FILE for results."
        ;;
    *)
        echo "Usage: $(basename "$0") {install|uninstall|run|status|scan}"
        echo ""
        echo "  install    Install as LaunchAgent (auto-start on login)"
        echo "  uninstall  Remove LaunchAgent and stop monitor"
        echo "  run        Run monitor in foreground"
        echo "  status     Check if monitor is running"
        echo "  scan       Run a single scan and exit"
        exit 1
        ;;
esac
