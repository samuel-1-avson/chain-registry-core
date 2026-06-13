#!/usr/bin/env python3
"""
Chain Registry Soak Test Runner

Automates a multi-validator soak test: publishes packages, records metrics,
and validates success criteria.

Usage:
    python runner.py \
        --validators http://v1:8080,http://v2:8080,http://v3:8080 \
        --duration 72h \
        --publish-rate 30s \
        --output ./results

Scenarios are defined in scenarios.json and executed on a schedule.
"""

import argparse
import json
import os
import random
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

import requests


@dataclass
class Validator:
    url: str
    name: str
    region: str = ""


@dataclass
class MetricsSnapshot:
    timestamp: datetime
    block_height: int = 0
    peer_count: int = 0
    validator_count: int = 0
    pending_pool_size: int = 0
    uptime_seconds: float = 0.0


class SoakTestRunner:
    def __init__(
        self,
        validators: List[Validator],
        duration: timedelta,
        publish_interval: timedelta,
        output_dir: Path,
        scenarios: Optional[List[dict]] = None,
    ):
        self.validators = validators
        self.duration = duration
        self.publish_interval = publish_interval
        self.output_dir = output_dir
        self.scenarios = scenarios or []

        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.metrics_log: List[Dict] = []
        self.events_log: List[Dict] = []
        self.published_count = 0
        self.verified_count = 0
        self._stop_event = threading.Event()
        self._publish_thread: Optional[threading.Thread] = None
        self._metrics_thread: Optional[threading.Thread] = None

    def _log_event(self, level: str, message: str, **kwargs):
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": level,
            "message": message,
            **kwargs,
        }
        self.events_log.append(entry)
        print(f"[{entry['timestamp']}] [{level}] {message}")

    def _fetch_metrics(self, validator: Validator) -> Optional[MetricsSnapshot]:
        try:
            resp = requests.get(
                f"{validator.url}/v1/chain/stats",
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json()
            return MetricsSnapshot(
                timestamp=datetime.utcnow(),
                block_height=data.get("block_height", 0),
                peer_count=data.get("peer_count", 0),
                validator_count=data.get("validator_count", 0),
                pending_pool_size=data.get("pending_pool_size", 0),
                uptime_seconds=data.get("uptime_seconds", 0.0),
            )
        except Exception as e:
            self._log_event("ERROR", f"Metrics fetch failed for {validator.name}: {e}")
            return None

    def _publish_package(self) -> bool:
        """Publish a dummy package to a random validator."""
        validator = random.choice(self.validators)
        pkg_name = f"soak-test/pkg-{int(time.time())}-{random.randint(1000,9999)}"
        try:
            # Create a minimal tarball
            with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as f:
                f.write(b"\x1f\x8b\x08\x00" + b"\x00" * 100)  # Minimal gzip header
                tmp_path = f.name

            with open(tmp_path, "rb") as f:
                resp = requests.post(
                    f"{validator.url}/v1/packages",
                    files={"file": ("package.tar.gz", f, "application/gzip")},
                    data={
                        "name": pkg_name,
                        "version": "1.0.0",
                        "canonical": pkg_name,
                    },
                    timeout=30,
                )

            os.unlink(tmp_path)

            if resp.status_code in (200, 201, 202):
                self.published_count += 1
                self._log_event("INFO", f"Published {pkg_name} to {validator.name}")
                return True
            else:
                self._log_event("WARN", f"Publish failed: {resp.status_code} {resp.text[:200]}")
                return False
        except Exception as e:
            self._log_event("ERROR", f"Publish exception: {e}")
            return False

    def _metrics_loop(self):
        """Collect metrics from all validators every 10 seconds."""
        while not self._stop_event.is_set():
            for v in self.validators:
                metrics = self._fetch_metrics(v)
                if metrics:
                    self.metrics_log.append({
                        "validator": v.name,
                        "timestamp": metrics.timestamp.isoformat() + "Z",
                        "block_height": metrics.block_height,
                        "peer_count": metrics.peer_count,
                        "validator_count": metrics.validator_count,
                        "pending_pool_size": metrics.pending_pool_size,
                        "uptime_seconds": metrics.uptime_seconds,
                    })
            time.sleep(10)

    def _publish_loop(self):
        """Publish packages at the configured interval."""
        while not self._stop_event.is_set():
            self._publish_package()
            self._stop_event.wait(self.publish_interval.total_seconds())

    def _run_scenarios(self):
        """Execute scheduled scenarios."""
        start = datetime.utcnow()
        for scenario in self.scenarios:
            offset = self._parse_duration(scenario.get("after", "0s"))
            trigger_at = start + offset
            wait_seconds = (trigger_at - datetime.utcnow()).total_seconds()
            if wait_seconds > 0:
                self._stop_event.wait(wait_seconds)
            if self._stop_event.is_set():
                break
            self._execute_scenario(scenario)

    def _execute_scenario(self, scenario: dict):
        name = scenario.get("name", "unnamed")
        action = scenario.get("action", "")
        self._log_event("INFO", f"Executing scenario: {name}")

        if action == "kill_validator":
            target = scenario.get("target", "")
            duration = self._parse_duration(scenario.get("duration", "30m"))
            self._log_event("WARN", f"Killing {target} for {duration}")
            # TODO: SSH or docker stop
        elif action == "restart_all":
            self._log_event("WARN", "Restarting all validators")
            # TODO: orchestration
        elif action == "network_partition":
            self._log_event("WARN", "Simulating network partition")
            # TODO: iptables / tc
        elif action == "l1_outage":
            self._log_event("WARN", "Simulating L1 RPC outage")
            # TODO: block L1 traffic
        else:
            self._log_event("WARN", f"Unknown scenario action: {action}")

    @staticmethod
    def _parse_duration(s: str) -> timedelta:
        """Parse '72h', '30m', '5s' into timedelta."""
        unit = s[-1].lower()
        value = int(s[:-1])
        if unit == "h":
            return timedelta(hours=value)
        elif unit == "m":
            return timedelta(minutes=value)
        elif unit == "s":
            return timedelta(seconds=value)
        elif unit == "d":
            return timedelta(days=value)
        else:
            raise ValueError(f"Unknown duration unit: {unit}")

    def run(self):
        start = datetime.utcnow()
        end = start + self.duration

        self._log_event("INFO", f"Soak test started: {start.isoformat()}Z")
        self._log_event("INFO", f"Duration: {self.duration}")
        self._log_event("INFO", f"Validators: {len(self.validators)}")
        self._log_event("INFO", f"Publish interval: {self.publish_interval}")

        # Start background threads
        self._metrics_thread = threading.Thread(target=self._metrics_loop, daemon=True)
        self._publish_thread = threading.Thread(target=self._publish_loop, daemon=True)
        self._metrics_thread.start()
        self._publish_thread.start()

        # Run scenarios in main thread
        self._run_scenarios()

        # Wait until duration expires
        remaining = (end - datetime.utcnow()).total_seconds()
        if remaining > 0:
            self._stop_event.wait(remaining)

        self.stop()
        self._generate_report(start, datetime.utcnow())

    def stop(self):
        self._stop_event.set()
        self._log_event("INFO", "Soak test stopping...")
        if self._publish_thread:
            self._publish_thread.join(timeout=5)
        if self._metrics_thread:
            self._metrics_thread.join(timeout=5)

    def _generate_report(self, start: datetime, end: datetime):
        report_path = self.output_dir / "report.json"
        report = {
            "start": start.isoformat() + "Z",
            "end": end.isoformat() + "Z",
            "duration_seconds": (end - start).total_seconds(),
            "validators": [{"name": v.name, "url": v.url} for v in self.validators],
            "published_count": self.published_count,
            "metrics_samples": len(self.metrics_log),
            "events": len(self.events_log),
            "success_criteria": self._evaluate_success_criteria(),
        }
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)

        # Save raw data
        with open(self.output_dir / "metrics.jsonl", "w") as f:
            for m in self.metrics_log:
                f.write(json.dumps(m) + "\n")

        with open(self.output_dir / "events.jsonl", "w") as f:
            for e in self.events_log:
                f.write(json.dumps(e) + "\n")

        self._log_event("INFO", f"Report saved to {report_path}")

    def _evaluate_success_criteria(self) -> dict:
        """Evaluate success criteria from collected metrics."""
        if not self.metrics_log:
            return {"overall": "NO_DATA", "details": {}}

        heights = [m["block_height"] for m in self.metrics_log]
        peers = [m["peer_count"] for m in self.metrics_log]
        validators = [m["validator_count"] for m in self.metrics_log]

        min_peers = min(peers) if peers else 0
        max_height = max(heights) if heights else 0
        min_validators = min(validators) if validators else 0

        # Expected blocks: 72h * 3600s/h / 5s/block = 51840 blocks
        expected_blocks = int(self.duration.total_seconds() / 5)
        block_rate = max_height / expected_blocks if expected_blocks > 0 else 0

        results = {
            "block_rate": block_rate,
            "min_peer_count": min_peers,
            "max_block_height": max_height,
            "min_validator_count": min_validators,
            "published_packages": self.published_count,
        }

        overall = "PASS"
        if block_rate < 0.5:
            overall = "FAIL"
        elif min_peers < 2:
            overall = "FAIL"
        elif min_validators < 3:
            overall = "FAIL"

        results["overall"] = overall
        return results


def main():
    parser = argparse.ArgumentParser(description="Chain Registry Soak Test Runner")
    parser.add_argument(
        "--validators",
        required=True,
        help="Comma-separated list of validator REST URLs",
    )
    parser.add_argument(
        "--duration",
        default="72h",
        help="Test duration (e.g. 72h, 30m, 1d)",
    )
    parser.add_argument(
        "--publish-rate",
        default="30s",
        help="Package publish interval (e.g. 30s, 1m)",
    )
    parser.add_argument(
        "--scenarios",
        type=Path,
        help="JSON file with scheduled scenarios",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("./results"),
        help="Output directory for results",
    )
    args = parser.parse_args()

    validators = []
    for i, url in enumerate(args.validators.split(",")):
        validators.append(Validator(url=url.strip(), name=f"validator-{i+1}"))

    scenarios = []
    if args.scenarios and args.scenarios.exists():
        with open(args.scenarios) as f:
            scenarios = json.load(f).get("scenarios", [])

    runner = SoakTestRunner(
        validators=validators,
        duration=SoakTestRunner._parse_duration(args.duration),
        publish_interval=SoakTestRunner._parse_duration(args.publish_rate),
        output_dir=args.output,
        scenarios=scenarios,
    )

    try:
        runner.run()
    except KeyboardInterrupt:
        print("\nInterrupted by user")
        runner.stop()
        sys.exit(1)

    print(f"\nSoak test complete. Results in {args.output}")


if __name__ == "__main__":
    main()
