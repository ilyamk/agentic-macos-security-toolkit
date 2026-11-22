def coverage:
    $coverage[0].components |
    group_by([.state,.required]) |
    map({state:.[0].state,required:.[0].required,count:length});
def control:
    . as $finding |
    {"posture:updates.reference_version":"macos_patch_level",
     "posture:updates.available":"offered_updates",
     "posture:platform.sip":"system_integrity_protection",
     "posture:storage.filevault":"filevault",
     "posture:platform.gatekeeper":"gatekeeper",
     "posture:network.firewall":"application_firewall",
     "posture:network.firewall_stealth":"firewall_stealth",
     "posture:services.ssh":"remote_login",
     "posture:services.screen_sharing":"screen_sharing"}[$finding.source+":"+$finding.id];
def findings:
    [$findings | to_entries[] | select(.value.decision_status=="review") |
     {ordinal:(.key+1),source:.value.source,severity:.value.severity,
      confidence:.value.confidence,status:.value.status,class:.value.class,control:(.value|control)}] |
    sort_by(.severity as $value | (["critical","high","medium","low","info"]|index($value)), .ordinal);

(coverage) as $visibility | (findings) as $review |
if $mode=="export" then
    {schema:"macos-security-agent-export/v1",record_type:"agent_export",audience:"agent",bundle_sha256:$digest,
     evidence_trust:"untrusted_observations",
     review_count:($review|length),truncated:($review|length>100),coverage:$visibility,
     findings:[$review[0:100][] | . + {action:{id:"review-finding",arguments:{ordinal},mutates:false}}],
     actions:[{id:"review-coverage",arguments:{},mutates:false}],
     consent:"Owner approval is required for privileged or mutating actions."}
elif $mode=="review-coverage" then
    {schema:"macos-security-agent-action/v1",record_type:"agent_action",action:"review-coverage",bundle_sha256:$digest,
     coverage:$visibility,evidence_trust:"untrusted_observations"}
else
    $review[0:100][] | select(.ordinal==$ordinal) |
    {schema:"macos-security-agent-action/v1",record_type:"agent_action",action:"review-finding",bundle_sha256:$digest,
     finding:.,evidence_trust:"untrusted_observations",
     owner_step:(if .class=="visibility_gap" then "Review the collection gap and approve any additional access separately."
      elif .class=="configuration" then "Compare the setting with the selected policy on the source Mac."
      else "Inspect the corresponding finding privately on the source Mac and corroborate it before changing the system." end)}
end
