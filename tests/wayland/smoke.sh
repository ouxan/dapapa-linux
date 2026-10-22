#!/bin/sh
# Starts the GUI on a headless Weston compositor and checks that it maps a native Wayland toplevel
# and keeps running. Needs weston; the user's real session is never used.
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK=$(mktemp -d /tmp/dapapa-wayland.XXXXXX)
export XDG_RUNTIME_DIR="$WORK/runtime" XDG_CONFIG_HOME="$WORK/config" XDG_STATE_HOME="$WORK/state"
mkdir -p -m 700 "$XDG_RUNTIME_DIR"

weston --backend=headless --socket=dapapa-test --width=900 --height=760 > "$WORK/weston.log" 2>&1 &
WESTON=$!
trap 'kill $WESTON 2>/dev/null; rm -rf "$WORK"' EXIT
sleep 2

WAYLAND_DISPLAY=dapapa-test WAYLAND_DEBUG=1 DISPLAY= timeout 12 \
    dotnet "$ROOT/src/Dapapa.App/bin/Release/net10.0/dapapa.dll" > "$WORK/app.log" 2>&1
status=$?

failed=0
check() { if eval "$2"; then echo "PASS: $1"; else echo "FAIL: $1"; failed=1; fi; }
check "app keeps running on Wayland" "[ $status -eq 124 ]"
check "native xdg toplevel with app id dapapa" "grep -q 'xdg_toplevel#[0-9]*\.set_app_id(\"dapapa\")' '$WORK/app.log'"
check "minimum size 460x560" "grep -q 'xdg_toplevel#[0-9]*\.set_min_size(460, 560)' '$WORK/app.log'"
check "window title dapapa" "grep -q 'xdg_toplevel#[0-9]*\.set_title(\"dapapa\")' '$WORK/app.log'"
check "frames are committed" "[ \$(grep -c 'wl_surface#[0-9]*\.commit' '$WORK/app.log') -gt 2 ]"
check "no unhandled exception" "! grep -q -i 'unhandled exception' '$WORK/app.log'"
[ $failed -eq 0 ] || tail -n 30 "$WORK/app.log"
exit $failed
