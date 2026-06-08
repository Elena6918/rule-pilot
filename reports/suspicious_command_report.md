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
search index=rulepilot_demo event_type=process (command_line=*powershell* OR command_line=*curl* OR command_line=*wget* OR command_line=*base64*) user!="svc_*" parent_process IN ("bash", "cmd.exe", "python3")
| bucket _time span=10m
| stats count as suspicious_count by _time, process, user, parent_process, command_line
| where suspicious_count >= 5
| sort - suspicious_count
```

## Before/After Metrics

| Metric | Value |
| --- | --- |
| Baseline result rows | 122 |
| Refined result rows | N/A |
| Absolute reduction | N/A |
| Percent reduction | N/A |

## Analyst Interpretation

Baseline triggers constantly on admins, CI jobs, and routine scripts. Need to reduce noise while preserving high-risk execution patterns.

Aggregate by time window, filter out service accounts, and focus on specific command-line patterns. Filters out service accounts and common parent processes. Aggregates events over time to identify repeated bursts of suspicious activity.

**Expected effect:** Reduces false positives by filtering out benign noise while still surfacing high-risk execution patterns.

**Risk:** May miss occasional isolated incidents, but should reduce overall noise.

## Caveats

- Result counts are an alert-volume proxy, not a measurement of detection accuracy.
- Synthetic data is used for the demo; validate against representative production data.
- Field availability and normalization should be checked before deploying in another environment.

## Output Path

- Refined SPL: `/Users/elena/Desktop/rule-pilot/detections/suspicious_command_refined.spl`
