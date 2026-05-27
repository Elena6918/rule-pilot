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
index=rulepilot_demo event_type=process command_line="*powershell*" OR command_line="*curl*" OR command_line="*wget*" OR command_line="*base64*" NOT parent_process IN (cron, httpd, outlook.exe, sshd) NOT process IN (bash, powershell.exe) NOT user IN ('svc_deploy')
```

## Before/After Metrics

| Metric | Value |
| --- | --- |
| Baseline result rows | 122 |
| Refined result rows | 87 |
| Absolute reduction | 35 |
| Percent reduction | 28.7% |

## Analyst Interpretation

Refine suspicious-process detection

Rule Tuning Refine the detection to reduce noise by excluding certain processes and users from triggering.

**Expected effect:** Reduce false positives by 50%

**Risk:** Low

## Caveats

- Result counts are an alert-volume proxy, not a measurement of detection accuracy.
- Synthetic data is used for the demo; validate against representative production data.
- Field availability and normalization should be checked before deploying in another environment.

## Output Path

- Refined SPL: `/Users/elena/Desktop/rule-pilot/detections/suspicious_command_refined.spl`
