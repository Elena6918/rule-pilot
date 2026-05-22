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
    print("Known suspicious entity:")
    print("  user=alice src_ip=45.83.12.9")


if __name__ == "__main__":
    main()