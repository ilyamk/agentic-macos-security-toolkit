def stamp:
    if type=="string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
    then (try fromdateiso8601 catch null) else null end;
def integer($max): type=="number" and .>0 and .<=$max and floor==.;
def identity: [.pid,.process_start_us]|join(":");
def network_record:
    type=="object" and .schema=="macos-security-network-observation/v1" and .direction=="outbound" and
    (.observed_at|stamp)!=null and (.protocol|IN("tcp","udp")) and (.decision|IN("observed","allowed","blocked")) and
    ((.remote_scope // "unknown")|IN("local","public","unknown")) and
    (.pid==null or (.pid|integer(2147483647))) and
    (.process_start_us==null or ((.process_start_us|integer(4102444800000000)) and .pid!=null and
        .process_start_us <= ((.observed_at|stamp)*1000000+999999)));

($from|stamp) as $lower | ($to|stamp) as $upper |
if ($from!="" and $lower==null) or ($to!="" and $upper==null) or
   ($lower!=null and $upper!=null and $lower>$upper)
then error("Invalid time window") else . end |
split("\n") | map(select(test("[^[:space:]]")) | fromjson) |
if length>4000 or (all(.[]; network_record)|not) then error("Invalid network observations") else . end |
. as $observations |
(reduce ($timeline[] | objects | select(.schema=="macos-security-event/v1" and .source=="eslogger") |
    select(.kind|strings|test("(^|_)exec$";"i")) |
    select(.data.exec_target_present==true and .data.timestamp_reported==true and
        (.data.pid|integer(2147483647)) and (.data.process_start_us|integer(4102444800000000))) |
    (.observed_at|strings|sub("\\.[0-9]{1,9}Z$";"Z")) as $seconds |
    ($seconds|stamp) as $epoch | select($epoch!=null) |
    {pid:.data.pid,process_start_us:.data.process_start_us,observed_at:$seconds,epoch:$epoch} ) as $event
    ({}; ($event|identity) as $key |
      if .[$key]==null then .[$key]=$event else .[$key].ambiguous=true end)) as $procs |
[$observations[] | (.observed_at|stamp) as $epoch |
 select(($lower==null or $epoch>=$lower) and ($upper==null or $epoch<=$upper)) |
 {observed_at,protocol,decision,remote_scope:(.remote_scope // "unknown"),pid,process_start_us} as $event |
 ($procs[$event|identity]) as $proc |
 $event+{correlation:(if $proc!=null and ($proc.ambiguous|not) and
                       $epoch >= $proc.epoch and $epoch-$proc.epoch<=300
                    then {method:"pid_and_process_start",exec_observed_at:$proc.observed_at,confidence:"medium"}
                    else null end)}
] as $kept |
{schema:"macos-security-network-import/v1",record_type:"network_import",evidence_trust:"untrusted_observations",
 source:"user_supplied_network_observations",collection_coverage:"unknown",
 window:{from:(if $from=="" then null else $from end),to:(if $to=="" then null else $to end),
     first_observed_at:($kept|map(.observed_at)|min),last_observed_at:($kept|map(.observed_at)|max)},
 input_count:($observations|length),event_count:($kept|length),out_of_window_count:(($observations|length)-($kept|length)),
 correlated_count:([$kept[]|select(.correlation!=null)]|length),events:$kept}
