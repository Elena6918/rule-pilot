# RulePilot Tuning Report — Failed Login Burst Refinement

## Summary

RulePilot executed the baseline SPL, ran diagnostic searches, generated a refined rule, and computed before/after alert-volume proxy metrics. Result counts are result rows, not confirmed false positives.

## Baseline Rule

```spl
index=rulepilot_demo sourcetype=auth action=login
| stats count by user, src_ip, status
| sort - count
```

## Diagnostics

- Baseline result rows: 113
- Burst/cluster groups (suspicious_failed_login_bursts): 1
- Top reason: mistyped_password (28 result rows)
- Top user: svc_backup (16 result rows)
- Top src_ip: 45.83.12.9 (16 result rows)

## Refined Rule

```spl
search index=rulepilot_demo sourcetype=auth action=login status=failure user!="svc_*" reason!="mistyped_password"
| bucket _time span=10m
| stats count as failed_count by _time, user, src_ip
| where failed_count >= 5
```

## Before/After Metrics

| Metric | Value |
| --- | --- |
| Baseline result rows | 113 |
| Refined result rows | 1 |
| Absolute reduction | 112 |
| Percent reduction | 99.1% |

## Analyst Interpretation

The baseline is too noisy due to isolated typos and service account activity, which are not indicative of suspicious behavior.

Filter out service accounts and common mistyped password reasons, then aggregate failed logins over time to identify bursts. By excluding service accounts and common mistyped password reasons, we reduce noise. Aggregating over 10-minute windows helps identify repeated failed login bursts.

**Expected effect:** The result count will be significantly reduced, focusing on suspicious login bursts while excluding benign noise.

**Risk:** There is a low risk of missing some legitimate failed login attempts, but the focus is on reducing noise and identifying true suspicious activity.

## Caveats

- Result counts are an alert-volume proxy, not a measurement of detection accuracy.
- Synthetic data is used for the demo; validate against representative production data.
- Field availability and normalization should be checked before deploying in another environment.

## Output Path

- Refined SPL: `/Users/elena/Desktop/rule-pilot/detections/failed_login_refined.spl`
