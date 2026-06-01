#!/usr/bin/env bash
# qs — Quicksched background manager
#
# Usage:
#   qs              start scx_quicksched in background (no TUI)
#   qs --status     show running status and uptime
#   qs stop         stop the background instance
#   qs [flags...]   run interactively in TUI mode with extra flags

set -euo pipefail

PIDFILE=/var/run/scx_quicksched.pid
LOGFILE=/var/log/scx_quicksched.log
SELF=$(readlink -f "$0")
BINARY=$(dirname "$SELF")/scx_quicksched

_running() {
    [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null
}

case "${1:-start}" in
    --status | status)
        if _running; then
            PID=$(cat "$PIDFILE")
            ELAPSED=$(ps -p "$PID" -o etimes= 2>/dev/null | tr -d ' ' || echo 0)
            H=$(( ELAPSED / 3600 ))
            M=$(( (ELAPSED % 3600) / 60 ))
            S=$(( ELAPSED % 60 ))
            printf "scx_quicksched running  pid=%-6s  uptime=%d:%02d:%02d\n" \
                "$PID" "$H" "$M" "$S"
            echo "  log:  tail -f $LOGFILE"
        else
            echo "scx_quicksched is not running"
            exit 1
        fi
        ;;

    stop)
        if _running; then
            sudo kill "$(cat "$PIDFILE")"
            rm -f "$PIDFILE"
            echo "scx_quicksched stopped"
        else
            echo "scx_quicksched is not running"
            exit 1
        fi
        ;;

    start | "")
        if _running; then
            echo "scx_quicksched already running (pid=$(cat "$PIDFILE"))"
            exit 0
        fi
        echo "starting scx_quicksched..."
        sudo sh -c "\"$BINARY\" --no-tui --pidfile \"$PIDFILE\" >> \"$LOGFILE\" 2>&1 &"
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            sleep 0.1
            _running && break
        done
        if _running; then
            echo "started (pid=$(cat "$PIDFILE"))  log: $LOGFILE"
        else
            echo "failed to start — check $LOGFILE"
            exit 1
        fi
        ;;

    *)
        exec sudo "$BINARY" "$@"
        ;;
esac
