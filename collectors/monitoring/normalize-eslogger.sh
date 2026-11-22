#!/bin/sh
# SPDX-License-Identifier: MIT
# Normalize Apple eslogger JSONL while excluding command arguments and
# environment values from the agent-facing timeline.

set -uC
umask 077
ROOT_DIR=$(CDPATH='' cd -- "$(/usr/bin/dirname -- "$0")/../.." && /bin/pwd -P)
# shellcheck source=lib/macos_security_common.sh
. "$ROOT_DIR/lib/macos_security_common.sh"
INPUT=""; OUTPUT=""
while [ "$#" -gt 0 ]; do
    case $1 in
        --input) shift; INPUT=${1:-} ;;
        --output) shift; OUTPUT=${1:-} ;;
        --self-test) printf '%s\n' '{"schema":"macos-security-event-normalizer/v1","record_type":"self_test","status":"pass"}'; exit 0 ;;
        *) exit 2 ;;
    esac
    shift
done
[ "$INPUT" = - ] || [ -r "$INPUT" ] || exit 2
[ -n "$OUTPUT" ] || exit 2
msc_require_jq || exit 2
OUTPUT=$(msc_report_file "$OUTPUT") || exit 2
: >"$OUTPUT" || exit 2
normalise() {
    jq --unbuffered -Rc '
      def payload_kind:
        objects|keys|map(select(IN("exec","btm_launch_item_add","btm_launch_item_remove","gatekeeper_user_override",
          "xp_malware_detected","xp_malware_remediated","profile_add","profile_remove","tcc_modify",
          "openssh_login","screensharing_attach","sudo","su"))) | select(length==1) | .[0];
      def process_start:
        if type=="object" and (.tv_sec|type=="number" and .>0 and .<4102444800 and floor==.) and
          (.tv_usec|type=="number" and .>=0 and .<1000000 and floor==.)
        then (.tv_sec*1000000+.tv_usec)
        elif type=="string" then
          try (capture("^(?<base>[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\\.(?<fraction>[0-9]{1,9}))?Z$")
            | ((.base+"Z")|fromdateiso8601)*1000000 + ((((.fraction // "")+"000000")[0:6])|tonumber)
            | select(.>0 and .<=4102444800000000)) catch null
        else null end // null;
      select(length>0) | (try fromjson catch error("Invalid Endpoint Security JSON")) |
      try (
        ((.event_type_name|strings) // (.event_type|strings) // (.event.type|strings) //
          (.event|payload_kind) // "unknown") as $kind |
        (if ($kind|test("(^|_)exec$";"i")) then ((.event.exec.target|objects) // null) else null end) as $exec_target |
        ($exec_target //
          .process // .event.process // .instigator // {}) as $process |
        ($process.start_time // null) as $start |
        ((.timestamp|strings) // (.time|strings) // (.observed_at|strings) // null) as $event_time |
        {
          schema:"macos-security-event/v1",record_type:"event",
          observed_at:($event_time // (now|todateiso8601)),
          kind:$kind,
          category:(if ($kind|test("xp_malware";"i")) then "malware" elif ($kind|test("gatekeeper";"i")) then "gatekeeper" elif ($kind|test("tcc";"i")) then "privacy" elif ($kind|test("btm|launch_item";"i")) then "persistence" elif ($kind|test("ssh|screensharing|sudo|su";"i")) then "authentication" else "process" end),
          source:"eslogger",confidence:"high",
          data:{
            pid:((($process.audit_token | objects | .pid) // $process.pid // .pid) | numbers // null),
            ppid:(($process.ppid // .ppid) | numbers // null),
            process_start_us:($start|process_start),
            exec_target_present:($exec_target!=null),timestamp_reported:($event_time!=null),
            executable:($process.executable.path // $process.path // .executable.path // .path // null | strings // null),
            signing_id:($process.signing_id // $process.signingID // null | strings // null),
            team_id:($process.team_id // $process.teamID // null | strings // null),
            responsible_pid:(.responsible_process.pid | numbers // null),
            remote_address:(.remote_address // .event.remote_address // null | strings // null),
            arguments_collected:false,environment_collected:false
          },
          evidence_trust:"untrusted_observations"
        }
      ) catch error("Invalid Endpoint Security event shape")' >>"$OUTPUT"
}
if [ "$INPUT" = - ]; then normalise; else normalise <"$INPUT"; fi
