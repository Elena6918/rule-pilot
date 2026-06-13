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
search index=rulepilot_demo event_type=process (command_line=*powershell* OR command_line=*curl* OR command_line=*wget* OR command_line=*base64*) AND NOT (user STARTSWITH "svc_")
| bucket _time span=10m
| stats count as suspicious_count by user, process, parent_process, command_line
| where suspicious_count >= 5
| sort - suspicious_count
```

## Before/After Metrics

| Metric | Value |
| --- | --- |
| Baseline result rows | 122 |
| Refined result rows | 6 |
| Absolute reduction | 116 |
| Percent reduction | 95.1% |

## Analyst Interpretation

Most detections are from common processes and users, with service accounts contributing significant noise.

Filter out service accounts, aggregate by process and user, and identify repeated bursts of suspicious commands. Filters out service accounts to reduce noise. Aggregates events over time windows and surfaces only repeated bursts of suspicious commands.

**Expected effect:** Reduces false positives by filtering out benign activity while preserving high-risk execution patterns.

**Risk:** Misses occasional true positives if the burst threshold is too high, but this risk is mitigated by the reduced noise.

## Caveats

- Result counts are an alert-volume proxy, not a measurement of detection accuracy.
- Synthetic data is used for the demo; validate against representative production data.
- Field availability and normalization should be checked before deploying in another environment.

## Output Path

- Refined SPL: `/Users/elena/Desktop/rule-pilot/detections/suspicious_command_refined.spl`
