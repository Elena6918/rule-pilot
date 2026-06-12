# RulePilot Tuning Report — Suspicious Command Execution

## Summary

RulePilot executed the baseline SPL, ran diagnostic searches, generated a refined rule, and computed before/after alert-volume proxy metrics. Result counts are result rows, not confirmed false positives.

## Baseline Rule

```spl
index=rulepilot_demo event_type=process command_line="*powershell*" OR command_line="*curl*" OR command_line="*wget*" OR command_line="*base64*"
| table _time, host, user, process, parent_process, command_line
| sort - _time
```

## Diagnostics

- Baseline result rows: 122
- Burst/cluster groups (suspicious_command_clusters): 16
- Top process: powershell.exe (29 result rows)
- Top user: dave (37 result rows)
- Top parent_process: bash (92 result rows)

## Refined Rule

```spl
search index=rulepilot_demo event_type=process (command_line="*powershell* -EncodedCommand*" OR command_line="*curl* | *sh*" OR command_line="*wget* | *sh*" OR command_line="*base64* -d*" OR command_line="*/dev/tcp/*") user!="svc_*"
| table _time, host, user, process, parent_process, command_line
| sort - _time
```

## Before/After Metrics

| Metric | Value |
| --- | --- |
| Baseline result rows | 122 |
| Refined result rows | 12 |
| Absolute reduction | 110 |
| Percent reduction | 90.2% |

## Analyst Interpretation

The baseline SPL is too broad, capturing routine admin and service account activity.

Filter out service accounts and focus on high-risk command patterns. This refinement targets specific high-risk command patterns and excludes service accounts, reducing noise from benign activity.

**Expected effect:** The result count should decrease significantly, focusing on truly suspicious command executions.

**Risk:** Low risk of missing true positives as the refinement still captures high-risk patterns.

## Caveats

- Result counts are an alert-volume proxy, not a measurement of detection accuracy.
- Synthetic data is used for the demo; validate against representative production data.
- Field availability and normalization should be checked before deploying in another environment.

## Output Path

- Refined SPL: `/Users/elena/Desktop/rule-pilot/detections/suspicious_command_refined.spl`
