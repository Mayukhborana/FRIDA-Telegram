#!/usr/bin/env bash
set -e

PKG_OR_PID=${1:-5974}   # pass PID or package name, default 1796
RUN_MONKEY=${RUN_MONKEY:-0} # set env var RUN_MONKEY=1 to run monkey

HOOK_JAVA=hooks/java_host_decode.js
HOOK_NATIVE=hooks/native_host.js
FRIDA_LOG=frida_host.log
TG_JAVA_JSON=tg_trace.jsonl
TG_NATIVE_JSON=tg_native_trace.jsonl

rm -f "$FRIDA_LOG" "$TG_JAVA_JSON" "$TG_NATIVE_JSON" frida_json_all.log || true

echo "[*] Attaching to target: ${PKG_OR_PID}"
# if numeric then use -p else -n
if [[ "$PKG_OR_PID" =~ ^[0-9]+$ ]]; then
    frida -U -p "$PKG_OR_PID" -l "$HOOK_JAVA" -l "$HOOK_NATIVE" > "$FRIDA_LOG" 2>&1 &
else
    frida -U -n "$PKG_OR_PID" -l "$HOOK_JAVA" -l "$HOOK_NATIVE" > "$FRIDA_LOG" 2>&1 &
fi
FRIDA_PID=$!
echo "[*] Frida host PID: $FRIDA_PID"
echo "[*] Wait 4s for hooks to initialize..."
sleep 4

if [ "$RUN_MONKEY" = "1" ]; then
    echo "[*] Running monkey (200 events)..."
    adb shell monkey -p org.telegram.messenger -v --throttle 300 200 || true
else
    echo "[*] RUN_MONKEY not set. Interact with the app manually now (30s)..."
    sleep 30
fi

echo "[*] Stopping Frida host client..."
kill "$FRIDA_PID" || true
sleep 1

# Extract JSON lines
grep -E '^\{".*"\}$' "$FRIDA_LOG" > frida_json_all.log || true
grep '"type":"java"' frida_json_all.log > "$TG_JAVA_JSON" || true
grep '"type":"native"' frida_json_all.log > "$TG_NATIVE_JSON" || true

echo "[*] Collected:"
echo "  $TG_JAVA_JSON: $(wc -l < "$TG_JAVA_JSON" 2>/dev/null || echo 0) lines"
echo "  $TG_NATIVE_JSON: $(wc -l < "$TG_NATIVE_JSON" 2>/dev/null || echo 0) lines"
echo "[*] Frida log: $FRIDA_LOG"

# optional parse with python if available
if command -v python3 >/dev/null 2>&1; then
    if [ -f parse_traces.py ]; then
        python3 parse_traces.py "$TG_JAVA_JSON" "$TG_NATIVE_JSON" || true
    fi
fi
