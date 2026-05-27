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
index=rulepilot_demo sourcetype=auth action=login | stats count by user, src_ip, status | sort - count > 3
```

## Before/After Metrics

| Metric | Value |
| --- | --- |
| Baseline result rows | 113 |
| Refined result rows | 113 |
| Absolute reduction | 0 |
| Percent reduction | 0.0% |

## Analyst Interpretation

Failed Login Burst Refinement

burst_thresholding Apply burst thresholding to filter out isolated typos and routine service-account churn while preserving suspicious burst behavior.

**Expected effect:** Reduce noise in failed login detection by filtering out non-bursty logins.

**Risk:** Moderate

## Caveats

- Result counts are an alert-volume proxy, not a measurement of detection accuracy.
- Synthetic data is used for the demo; validate against representative production data.
- Field availability and normalization should be checked before deploying in another environment.

## Output Path

- Refined SPL: `/Users/elena/Desktop/rule-pilot/detections/failed_login_refined.spl`
