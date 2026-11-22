#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
umask 077
ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
. "$ROOT_DIR/lib/macos_security_common.sh"
. "$ROOT_DIR/lib/macos_security_endpoint.sh"
TEST_TMP=$(msc_mktemp_dir msc-endpoint-tests)
MSC_ENDPOINT_PID=''; MSC_ENDPOINT_READER=''
trap 'msc_endpoint_finish || true; /bin/rm -rf "$TEST_TMP"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

cat >"$TEST_TMP/eslogger" <<'FAKE'
#!/bin/sh
if [ "$1" = --list-events ]; then
    [ "$STREAM_CASE" != unsupported ] || exit 8
    printf '%s\n' exec future_unselected_event
    exit 0
fi
[ "$#" -eq 1 ] && [ "$1" = exec ] || exit 9
[ "$STREAM_CASE" != early_exit ] || { : >"$STREAM_READY"; exit 8; }
if [ "$STREAM_CASE" = malformed ]; then
    printf '%s\n' 'not JSON'
else
    printf '%s\n' '{"event_type":"exec","process":{"pid":1},"arguments":["private-argument"],"environment":["private-value"]}'
fi
trap 'exit 130' INT
: >"$STREAM_READY"
while :; do /bin/sleep 0.1; done
FAKE
chmod 700 "$TEST_TMP/eslogger"
STREAM_READY=$TEST_TMP/ready
export STREAM_READY STREAM_CASE
for STREAM_CASE in good malformed early_exit unsupported; do
    run=$TEST_TMP/$STREAM_CASE
    mkdir "$run"
    rm -f "$STREAM_READY"
    result=0
    msc_endpoint_stream "$run" "$ROOT_DIR/collectors/monitoring/normalize-eslogger.sh" "$TEST_TMP/eslogger" 2>/dev/null || result=$?
    if [ "$STREAM_CASE" = unsupported ]; then
        [ "$result" -eq 1 ] && [ -f "$run/eslogger.status" ] && [ ! -e "$run/.endpoint-events" ]
        continue
    fi
    [ "$result" -eq 0 ] && [ -p "$run/.endpoint-events" ]
    attempts=0
    until [ -f "$STREAM_READY" ]; do
        attempts=$((attempts + 1)); [ "$attempts" -le 50 ] || exit 1
        /bin/sleep 0.1
    done
    logger_pid=$MSC_ENDPOINT_PID; normaliser_pid=$MSC_ENDPOINT_READER
    result=0
    msc_endpoint_finish || result=$?
    [ ! -e "$run/.endpoint-events" ]
    if kill -0 "$logger_pid" 2>/dev/null || kill -0 "$normaliser_pid" 2>/dev/null; then exit 1; fi
    if [ "$STREAM_CASE" = good ]; then
        [ "$result" -eq 0 ]
        jq -e -s 'length==1 and .[0].kind=="exec" and (tostring|contains("private-")|not)' "$run/timeline.jsonl" >/dev/null
    else
        [ "$result" -eq 1 ]
        grep -q 'stream incomplete' "$run/eslogger.status"
    fi
done
printf '%s\n' 'PASS: Endpoint Security FIFO allow-list, privacy, errors and cleanup'
