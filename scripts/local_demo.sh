#!/usr/bin/env bash
# Runs the full local (non-VM) smoke test in one go: starts the HTTP demo
# server and the mock Telnet server, starts the sniffer on loopback, fires
# both victim logins, then tears everything down and prints what the
# sniffer recovered.
#
# Needs `sudo` interactively for the sniffer step (raw AF_PACKET socket) --
# run this yourself in a terminal, it'll prompt for your password normally.
#
# Usage: ./scripts/local_demo.sh

set -euo pipefail
cd "$(dirname "$0")/.."

HTTP_PORT=8080
TELNET_PORT=2323
LOG_DIR=$(mktemp -d)
trap 'echo "[local_demo] cleaning up..."; kill $HTTP_PID $TELNET_PID 2>/dev/null; sudo kill $SNIFFER_PID 2>/dev/null; true' EXIT

# sudo's password prompt goes straight to /dev/tty, bypassing any output
# redirect -- and a backgrounded (`&`) command can lose access to the
# controlling terminal for that prompt entirely, so authenticating sudo
# *inside* the backgrounded sniffer command below is unreliable (it can
# silently fail to ever run). Authenticate here instead, in the foreground,
# so the cached credential lets the backgrounded call proceed without
# prompting again.
echo "[local_demo] sniffer needs root for the raw socket -- authenticating now:"
sudo -v

echo "[local_demo] starting HTTP server on :$HTTP_PORT"
uv run python server/http_server.py "$HTTP_PORT" > "$LOG_DIR/http_server.log" 2>&1 &
HTTP_PID=$!

echo "[local_demo] starting mock telnet server on :$TELNET_PORT"
uv run python server/mock_telnet_server.py "$TELNET_PORT" > "$LOG_DIR/mock_telnet.log" 2>&1 &
TELNET_PID=$!

sleep 1

echo "[local_demo] starting sniffer on lo (needs sudo)..."
sudo "$(which uv)" run python sniffer/sniffer.py lo "$HTTP_PORT" "$TELNET_PORT" \
  > "$LOG_DIR/sniffer.log" 2>&1 &
SNIFFER_PID=$!
sleep 1

echo "[local_demo] running HTTP login..."
uv run python victim/http_login.py 127.0.0.1 arzon 2105128 "$HTTP_PORT"

echo "[local_demo] running Telnet login..."
uv run python victim/telnet_login.py 127.0.0.1 arian 2105143 "$TELNET_PORT"

sleep 1
echo ""
echo "[local_demo] === sniffer results ==="
grep -a "credentials recovered" sniffer_session.log || echo "(nothing recovered -- something's wrong)"
echo ""
echo "[local_demo] full logs kept in $LOG_DIR"
