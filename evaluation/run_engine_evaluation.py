#!/usr/bin/env python3

import json
import sys
from pathlib import Path
from datetime import datetime, date

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from collector.elastic_client import analyze, export_analyst_view

DATASET_PATH = PROJECT_ROOT / "evaluation" / "evaluation_dataset.json"
OUTPUT_PATH = PROJECT_ROOT / "evaluation" / "engine_output.json"
ANALYST_VIEW_OUTPUT = PROJECT_ROOT / "evaluation" / "analyst_view"

def load_dataset():
    with DATASET_PATH.open("r", encoding="utf-8") as f:
        dataset = json.load(f)

    if not isinstance(dataset, list):
        raise ValueError("Expected evaluation_dataset.json to contain a list.")

    hits = []

    for event in dataset:
        if not isinstance(event, dict):
            raise ValueError("Invalid event record.")

        event_id = event.get("event_id")
        timestamp = event.get("time_utc")
        sysmon_id = event.get("event_id_sysmon")
        computer = event.get("computer")
        event_data = event.get("event_data", {})

        if not event_id or not timestamp or not sysmon_id:
            raise ValueError(f"Missing required fields in event: {event_id}")

        if not isinstance(event_data, dict):
            raise ValueError(f"Invalid event_data in event: {event_id}")

        source = {
            "@timestamp": timestamp,
            "host": {"name": computer} if computer else {},
            "winlog": {
                "event_id": str(sysmon_id),
                "event_data": event_data,
            },
        }

        hits.append({
            "_id": event_id,
            "_source": source,
        })

    return hits


def make_json_serializable(value):
    if isinstance(value, dict):
        return {
            str(key): make_json_serializable(item)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple, set)):
        items = list(value)
        if isinstance(value, set):
            items = sorted(items, key=str)
        return [make_json_serializable(item) for item in items]

    if isinstance(value, (datetime, date)):
        return value.isoformat()

    return value


def main():
    print("[1/3] Loading evaluation dataset...")
    hits = load_dataset()
    print(f"      Loaded {len(hits)} events.")

    print("[2/3] Running the original Engine analysis...")
    result = analyze(hits)

    print("[3/3] Saving Engine output...")
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_PATH.open("w", encoding="utf-8") as f:
        json.dump(
            make_json_serializable(result),
            f,
            indent=2,
            ensure_ascii=False,
        )
    print("[4/4] Exporting Analyst GUI data...")
    export_analyst_view(result, str(ANALYST_VIEW_OUTPUT))
    print(f"      Analyst view: {ANALYST_VIEW_OUTPUT}")

    print("\nENGINE EVALUATION RUN COMPLETED")
    print(f"Input events: {len(hits)}")
    print(f"Output file: {OUTPUT_PATH}")
    print(f"Stories: {len(result.get('stories', []))}")
    print(f"Campaigns: {len(result.get('campaigns', []))}")
    print("Incident API: Not called")
    print("Ground Truth: Not loaded")


if __name__ == "__main__":
    main()
