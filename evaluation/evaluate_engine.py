import json
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime
from statistics import median

ROOT = Path(__file__).resolve().parents[1]
EVAL = ROOT / "evaluation"

ENGINE_FILE = EVAL / "engine_output.json"
GT_FILE = EVAL / "ground_truth.json"
DATASET_FILE = EVAL / "evaluation_dataset.json"
REPORT_FILE = EVAL / "evaluation_report.json"

ATTACK = "CAMP-001"
UNKNOWN = "UNKNOWN"
BENIGN = "BENIGN"

SEVERITY_VALUES = {
    "HIGH": 1.0,
    "CRITICAL": 0.5,
    "MEDIUM": 0.5,
    "LOW": 0.0,
}

STAGE_MAP = {
    "execution": "EXECUTION",
    "dns": "COMMAND_AND_CONTROL",
    "network": "COMMAND_AND_CONTROL",
    "file": "SAMPLE_STAGING_DETONATION",
}

# Composite weights from the evaluation methodology.
# Active-state calibration is excluded because Ground Truth has no
# active/inactive labels. Remaining weights are normalized to sum to 1.
COMPOSITE_WEIGHTS = {
    "core_pair_f1": 0.25,
    "benign_to_camp001_precision_component": 0.20,
    "campaign_purity_times_cleanliness": 0.15,
    "stage_accuracy": 0.15,
    "severity_score": 0.10,
    "noise_suppression_rate": 0.05,
}


def load_json(path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def safe_div(a, b):
    return a / b if b else 0.0


def f1_score(precision, recall):
    return safe_div(2 * precision * recall, precision + recall)


def pair_key(a, b):
    return tuple(sorted((str(a), str(b))))


def parse_time(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def extract_related_pairs(ground_truth):
    pairs = set()

    for event_id, record in ground_truth.items():
        for related in record.get("related_events", []):
            if isinstance(related, dict):
                related_id = (
                    related.get("event_id")
                    or related.get("id")
                    or related.get("related_event_id")
                )
            else:
                related_id = related

            if related_id and related_id != event_id:
                pairs.add(pair_key(event_id, related_id))

    return pairs


def extract_predicted_pairs(stories):
    pairs = set()

    for story in stories:
        for relationship in story.get("relationships", []):
            source = relationship.get("from")
            target = relationship.get("to")

            if source and target and source != target:
                pairs.add(pair_key(source, target))

    return pairs


def calculate_pair_metrics(predicted, expected, ground_truth):
    tp = predicted & expected
    fp = predicted - expected
    fn = expected - predicted

    precision = safe_div(len(tp), len(predicted))
    recall = safe_div(len(tp), len(expected))

    attack_ids = {
        event_id for event_id, record in ground_truth.items()
        if record.get("scenario_id") == ATTACK
    }

    def is_core(pair):
        return pair[0] in attack_ids or pair[1] in attack_ids

    predicted_core = {p for p in predicted if is_core(p)}
    expected_core = {p for p in expected if is_core(p)}

    core_tp = predicted_core & expected_core
    core_fp = predicted_core - expected_core
    core_fn = expected_core - predicted_core

    core_precision = safe_div(len(core_tp), len(predicted_core))
    core_recall = safe_div(len(core_tp), len(expected_core))

    return {
        "overall": {
            "true_positives": len(tp),
            "false_positives": len(fp),
            "false_negatives": len(fn),
            "precision": precision,
            "recall": recall,
            "f1": f1_score(precision, recall),
        },
        "core_pairs": {
            "true_positives": len(core_tp),
            "false_positives": len(core_fp),
            "false_negatives": len(core_fn),
            "precision": core_precision,
            "recall": core_recall,
            "f1": f1_score(core_precision, core_recall),
            "core_miss_rate": safe_div(len(core_fn), len(expected_core)),
        },
    }


def classify_false_correlations(predicted, expected, ground_truth):
    # Only predictions absent from Ground Truth are false correlations.
    false_pairs = predicted - expected
    counts = Counter()

    for a, b in false_pairs:
        sa = ground_truth.get(a, {}).get("scenario_id", UNKNOWN)
        sb = ground_truth.get(b, {}).get("scenario_id", UNKNOWN)

        if UNKNOWN in (sa, sb):
            counts["UNKNOWN_involved"] += 1
        elif sa == BENIGN and sb == BENIGN:
            counts["BENIGN_to_BENIGN"] += 1
        elif {sa, sb} == {BENIGN, ATTACK}:
            counts["BENIGN_to_CAMP001"] += 1
        elif sa == ATTACK and sb == ATTACK:
            counts["CAMP001_to_CAMP001"] += 1
        else:
            counts["OTHER"] += 1

    # Denominator: all predicted pairs having at least one attack endpoint.
    # Numerator: false BENIGN-to-CAMP-001 pairs only.
    predicted_attack_pairs = {
        pair for pair in predicted
        if pair[0] in ground_truth
        and pair[1] in ground_truth
        and ATTACK in (
            ground_truth[pair[0]].get("scenario_id"),
            ground_truth[pair[1]].get("scenario_id"),
        )
    }

    return {
        "false_pair_counts": dict(counts),
        "total_false_pairs": len(false_pairs),
        "benign_to_camp001_false_correlation_rate": safe_div(
            counts["BENIGN_to_CAMP001"],
            len(predicted_attack_pairs),
        ),
        "predicted_pairs_with_attack_endpoint": len(predicted_attack_pairs),
        "rate_denominator": (
            "All predicted pairs with at least one CAMP-001 endpoint, "
            "including true-positive pairs"
        ),
    }


def build_membership(engine):
    stories = engine.get("stories", [])
    campaigns = engine.get("campaigns", [])

    story_by_id = {
        story["story_id"]: story
        for story in stories
        if story.get("story_id")
    }

    event_to_stories = defaultdict(set)
    event_to_campaigns = defaultdict(set)
    campaign_events = {}

    for story in stories:
        story_id = story.get("story_id")
        for event in story.get("events", []):
            event_id = event.get("id")
            if event_id and story_id:
                event_to_stories[event_id].add(story_id)

    for campaign in campaigns:
        campaign_id = campaign.get("campaign_id")
        cluster = set()

        for story_id in campaign.get("story_ids", []):
            story = story_by_id.get(story_id)
            if not story:
                continue

            for event in story.get("events", []):
                event_id = event.get("id")
                if event_id:
                    cluster.add(event_id)
                    event_to_campaigns[event_id].add(campaign_id)

        if campaign_id:
            campaign_events[campaign_id] = cluster

    return event_to_stories, event_to_campaigns, campaign_events, story_by_id


def calculate_campaign_metrics(
    ground_truth, campaign_events, event_to_stories, event_to_campaigns
):
    attack_ids = {
        event_id for event_id, record in ground_truth.items()
        if record.get("scenario_id") == ATTACK
    }
    benign_ids = {
        event_id for event_id, record in ground_truth.items()
        if record.get("scenario_id") == BENIGN
    }

    clusters = [
        (campaign_id, events)
        for campaign_id, events in campaign_events.items()
        if events
    ]

    largest_id, largest_events = (
        max(clusters, key=lambda item: len(item[1]))
        if clusters else (None, set())
    )

    attack_in_largest = largest_events & attack_ids

    attack_campaigns = {
        campaign_id
        for campaign_id, events in clusters
        if events & attack_ids
    }

    # A campaign claims a majority only if it contains strictly more
    # than half of all CAMP-001 events.
    majority_threshold = len(attack_ids) / 2
    majority_campaigns = [
        campaign_id
        for campaign_id, events in clusters
        if len(events & attack_ids) > majority_threshold
    ]

    benign_in_campaigns = {
        event_id for event_id in benign_ids
        if event_to_campaigns.get(event_id)
    }
    benign_in_stories = {
        event_id for event_id in benign_ids
        if event_to_stories.get(event_id)
    }
    suppressed_benign = (
        benign_ids - benign_in_campaigns - benign_in_stories
    )

    return {
        "largest_campaign_id": largest_id,
        "largest_campaign_event_count": len(largest_events),
        "attack_events_in_largest_campaign": len(attack_in_largest),
        "campaign_purity": safe_div(len(attack_in_largest), len(attack_ids)),
        "campaign_cleanliness": safe_div(
            len(attack_in_largest), len(largest_events)
        ),
        "campaigns_containing_attack_events": len(attack_campaigns),
        "attack_campaign_ids": sorted(attack_campaigns),
        "majority_attack_campaigns": majority_campaigns,
        "majority_attack_campaign_count": len(majority_campaigns),
        "fragmented": len(majority_campaigns) > 1,
        "benign_events_in_campaigns": len(benign_in_campaigns),
        "benign_events_in_stories": len(benign_in_stories),
        "benign_events_suppressed_from_both": len(suppressed_benign),
        "noise_suppression_rate": safe_div(
            len(suppressed_benign), len(benign_ids)
        ),
    }


def calculate_stage_metrics(stories, ground_truth, dataset):
    # Keep all candidate stage predictions per event. If multiple stories
    # assign conflicting stages to one event, mark it ambiguous.
    candidates = defaultdict(set)
    alignment_failures = 0

    for story in stories:
        events = story.get("events", [])
        stages = story.get("progression", {}).get("stages", [])

        if not stages or len(stages) != len(events):
            if stages:
                alignment_failures += 1
            continue

        for event, stage in zip(events, stages):
            event_id = event.get("id")
            mapped = STAGE_MAP.get(str(stage).lower())
            if event_id and mapped:
                candidates[event_id].add(mapped)

    predictions = {
        event_id: next(iter(values))
        for event_id, values in candidates.items()
        if len(values) == 1
    }
    ambiguous_predictions = {
        event_id for event_id, values in candidates.items()
        if len(values) > 1
    }

    attack_records = {
        event_id: record
        for event_id, record in ground_truth.items()
        if record.get("scenario_id") == ATTACK
    }

    # All 56 attack events are in the denominator. Missing or ambiguous
    # predictions count as incorrect rather than disappearing.
    correct = sum(
        predictions.get(event_id) == record.get("attack_stage")
        for event_id, record in attack_records.items()
    )

    evaluable_ids = set(attack_records) & set(predictions)
    conditional_correct = sum(
        predictions[event_id] == attack_records[event_id].get("attack_stage")
        for event_id in evaluable_ids
    )

    dataset_times = {
        event.get("event_id"): parse_time(event.get("time_utc"))
        for event in dataset
    }

    chronological_attack_ids = sorted(
        attack_records,
        key=lambda event_id: (
            dataset_times.get(event_id) is None,
            dataset_times.get(event_id) or datetime.max.replace(
                tzinfo=None
            ),
            event_id,
        ),
    )

    first_stage_time = {}
    for event_id in chronological_attack_ids:
        stage = predictions.get(event_id)
        timestamp = dataset_times.get(event_id)
        if stage and timestamp and stage not in first_stage_time:
            first_stage_time[stage] = timestamp

    expected_order = [
        "SAMPLE_STAGING_DETONATION",
        "EXECUTION",
        "COMMAND_AND_CONTROL",
    ]

    order_evaluable = all(
        stage in first_stage_time for stage in expected_order
    )
    order_correct = (
        first_stage_time[expected_order[0]]
        < first_stage_time[expected_order[1]]
        < first_stage_time[expected_order[2]]
        if order_evaluable else None
    )

    return {
        "accuracy": safe_div(correct, len(attack_records)),
        "correct": correct,
        "evaluated_attack_events": len(evaluable_ids),
        "total_attack_events": len(attack_records),
        "coverage": safe_div(len(evaluable_ids), len(attack_records)),
        "conditional_accuracy_on_evaluable_events": safe_div(
            conditional_correct, len(evaluable_ids)
        ),
        "missing_or_ambiguous_predictions": (
            len(attack_records) - len(evaluable_ids)
        ),
        "ambiguous_event_predictions": len(
            ambiguous_predictions & set(attack_records)
        ),
        "story_alignment_failures": alignment_failures,
        "stage_order_correct": order_correct,
        "stage_order_evaluable": order_evaluable,
        "first_predicted_stage_timestamps": {
            stage: timestamp.isoformat()
            for stage, timestamp in first_stage_time.items()
        },
        "note": (
            "Accuracy denominator includes all CAMP-001 events. Missing "
            "or ambiguous predictions count as incorrect. Stage order "
            "uses event timestamps from the input dataset. Persistence "
            "is not mapped to a Ground Truth stage."
        ),
    }


def calculate_active_state_calibration():
    return {
        "status": "NOT EVALUABLE",
        "score": None,
        "reason": (
            "Ground Truth contains no active/inactive labels. "
            "No calibration score is assigned and this metric is "
            "excluded from the composite score."
        ),
    }


def is_private_lab_ip(value):
    return "192.168.56." in str(value or "")


def trap_categories(event):
    data = event.get("event_data", {})
    eid = str(event.get("event_id_sysmon", ""))
    text = json.dumps(data, ensure_ascii=False).lower()
    categories = set()

    # Known benign CreateRemoteThread console-control propagation.
    if eid == "8" and "ctrlroutine" in text and "kernelbase.dll" in text:
        categories.add("create_remote_thread_ctrlroutine")

    # Run / RunOnce registry activity.
    if eid in ("12", "13") and (
        "\\run" in text or "\\runonce" in text
    ):
        categories.add("run_key_registry_activity")

    # DismHost temporary executable / cleanup behavior.
    if "dismhost" in text and (
        "temp" in text or "dismhost.exe" in text
    ):
        categories.add("dismhost_temp_activity")

    if "certutil" in text:
        categories.add("certutil_activity")

    if "fakenet" in text:
        categories.add("fakenet_activity")

    if "a7a.com" in text:
        categories.add("a7a_domain_activity")

    if eid in ("12", "13") and data.get("RuleName"):
        categories.add("sysmon_rule_name_registry_activity")

    destination_ip = (
        data.get("DestinationIp")
        or data.get("DestinationIP")
        or data.get("destination.ip")
    )
    if eid == "3" and is_private_lab_ip(destination_ip):
        categories.add("private_subnet_network_activity")

    return categories


def find_regular_private_network_events(dataset):
    # Identify repeated private-subnet connections to the same destination
    # with at least 3 intervals and a maximum 20% deviation from the median.
    grouped = defaultdict(list)

    for event in dataset:
        if str(event.get("event_id_sysmon")) != "3":
            continue

        data = event.get("event_data", {})
        destination_ip = (
            data.get("DestinationIp")
            or data.get("DestinationIP")
            or data.get("destination.ip")
        )

        if not is_private_lab_ip(destination_ip):
            continue

        timestamp = parse_time(event.get("time_utc"))
        if timestamp:
            grouped[destination_ip].append(
                (timestamp, event.get("event_id"))
            )

    regular_ids = set()

    for records in grouped.values():
        records.sort(key=lambda item: item[0])

        if len(records) < 4:
            continue

        intervals = [
            (records[i][0] - records[i - 1][0]).total_seconds()
            for i in range(1, len(records))
        ]

        middle = median(intervals)
        if middle <= 0:
            continue

        if all(abs(value - middle) / middle <= 0.20 for value in intervals):
            regular_ids.update(event_id for _, event_id in records)

    return regular_ids


def calculate_trap_metrics(dataset, ground_truth):
    categories_by_event = {}
    regular_ids = find_regular_private_network_events(dataset)

    for event in dataset:
        event_id = event.get("event_id")
        if not event_id:
            continue

        if ground_truth.get(event_id, {}).get("scenario_id") != BENIGN:
            continue

        categories = trap_categories(event)

        if event_id in regular_ids:
            categories.add("regular_interval_private_network")

        if categories:
            categories_by_event[event_id] = categories

    category_counts = Counter()
    for categories in categories_by_event.values():
        category_counts.update(categories)

    return {
        "unique_benign_trap_events": len(categories_by_event),
        "category_event_counts": dict(category_counts),
        "category_note": (
            "Categories may overlap; one event can belong to multiple "
            "trap categories. Unique trap event count is deduplicated."
        ),
        "trap_event_ids": sorted(categories_by_event),
        "categories_by_event": {
            event_id: sorted(categories)
            for event_id, categories in categories_by_event.items()
        },
    }


def calculate_severity_metrics(
    campaigns, campaign_events, ground_truth, trap_metrics
):
    attack_ids = {
        event_id for event_id, record in ground_truth.items()
        if record.get("scenario_id") == ATTACK
    }

    benign_trap_ids = set(trap_metrics["trap_event_ids"])

    attack_campaigns = []
    event_campaigns = defaultdict(list)

    for campaign in campaigns:
        campaign_id = campaign.get("campaign_id")
        events = campaign_events.get(campaign_id, set())
        severity = str(campaign.get("severity", "LOW")).upper()

        for event_id in events:
            event_campaigns[event_id].append({
                "campaign_id": campaign_id,
                "severity": severity,
            })

        if events & attack_ids:
            attack_campaigns.append({
                "campaign_id": campaign_id,
                "severity": severity,
                "attack_event_count": len(events & attack_ids),
                "severity_score": SEVERITY_VALUES.get(severity, 0.0),
            })

    # Campaign severity is evaluated at campaign level, not copied and
    # described as an independently assigned event severity.
    attack_campaign_scores = [
        item["severity_score"] for item in attack_campaigns
    ]
    base_score = safe_div(
        sum(attack_campaign_scores), len(attack_campaign_scores)
    )

    high_critical_campaign_ids = {
        item["campaign_id"]
        for item in attack_campaigns
        if item["severity"] in ("HIGH", "CRITICAL")
    }

    exposed_traps = {
        event_id
        for event_id in benign_trap_ids
        if any(
            item["campaign_id"] in high_critical_campaign_ids
            for item in event_campaigns.get(event_id, [])
        )
    }

    exposure_rate = safe_div(len(exposed_traps), len(benign_trap_ids))

    # A bounded contamination adjustment: up to 0.25 points, scaled by
    # the proportion of detected benign traps in HIGH/CRITICAL campaigns.
    # This is explicitly a campaign-contamination proxy, not an event-level
    # severity classification.
    penalty = 0.25 * exposure_rate
    final_score = max(0.0, base_score - penalty)

    return {
        "attack_campaign_severity_score_before_penalty": base_score,
        "attack_campaigns_scored": len(attack_campaigns),
        "attack_campaign_details": attack_campaigns,
        "benign_trap_events_detected": len(benign_trap_ids),
        "benign_trap_events_in_high_or_critical_campaigns": len(exposed_traps),
        "benign_trap_high_critical_campaign_exposure_rate": exposure_rate,
        "contamination_penalty": penalty,
        "final_severity_score": final_score,
        "exposed_benign_trap_event_ids": sorted(exposed_traps),
        "methodology_note": (
            "Engine severity is available at campaign level in this output. "
            "Benign events in HIGH/CRITICAL campaigns are reported as "
            "campaign exposure, not as independently classified event "
            "severity. Penalty = 0.25 * exposure rate."
        ),
    }


def main():
    engine = load_json(ENGINE_FILE)
    ground_truth = load_json(GT_FILE)
    dataset = load_json(DATASET_FILE)

    if not isinstance(ground_truth, dict):
        raise ValueError("Ground Truth must be a dictionary keyed by event_id.")
    if not isinstance(dataset, list):
        raise ValueError("Evaluation dataset must be a list.")

    stories = engine.get("stories", [])
    campaigns = engine.get("campaigns", [])

    expected = extract_related_pairs(ground_truth)
    predicted = extract_predicted_pairs(stories)

    pair_metrics = calculate_pair_metrics(
        predicted, expected, ground_truth
    )
    false_correlations = classify_false_correlations(
        predicted, expected, ground_truth
    )

    (
        event_to_stories,
        event_to_campaigns,
        campaign_events,
        story_by_id,
    ) = build_membership(engine)

    campaign_metrics = calculate_campaign_metrics(
        ground_truth,
        campaign_events,
        event_to_stories,
        event_to_campaigns,
    )

    stage_metrics = calculate_stage_metrics(
        stories, ground_truth, dataset
    )

    active_metrics = calculate_active_state_calibration()

    trap_metrics = calculate_trap_metrics(dataset, ground_truth)

    severity_metrics = calculate_severity_metrics(
        campaigns,
        campaign_events,
        ground_truth,
        trap_metrics,
    )

    benign_false_rate = false_correlations[
        "benign_to_camp001_false_correlation_rate"
    ]

    components = {
        "core_pair_f1": pair_metrics["core_pairs"]["f1"],
        "benign_to_camp001_precision_component": 1 - benign_false_rate,
        "campaign_purity_times_cleanliness": (
            campaign_metrics["campaign_purity"]
            * campaign_metrics["campaign_cleanliness"]
        ),
        "stage_accuracy": stage_metrics["accuracy"],
        "severity_score": severity_metrics["final_severity_score"],
        "noise_suppression_rate": campaign_metrics["noise_suppression_rate"],
    }

    total_weight = sum(COMPOSITE_WEIGHTS.values())
    composite = safe_div(
        sum(
            COMPOSITE_WEIGHTS[name] * components[name]
            for name in COMPOSITE_WEIGHTS
        ),
        total_weight,
    )

    normalized_weights = {
        name: weight / total_weight
        for name, weight in COMPOSITE_WEIGHTS.items()
    }

    report = {
        "dataset": {
            "events": len(dataset),
            "ground_truth_events": len(ground_truth),
            "engine_events": len(engine.get("events", [])),
            "stories": len(stories),
            "campaigns": len(campaigns),
        },
        "relationship_metrics": pair_metrics,
        "false_correlations": false_correlations,
        "campaign_metrics": campaign_metrics,
        "stage_metrics": stage_metrics,
        "active_state_calibration": active_metrics,
        "trap_metrics": trap_metrics,
        "severity_metrics": severity_metrics,
        "composite_score": {
            "score": composite,
            "available": True,
            "components": components,
            "original_weights": COMPOSITE_WEIGHTS,
            "normalized_weights_excluding_active_state": normalized_weights,
            "excluded_metrics": {
                "active_state_calibration": (
                    "NOT EVALUABLE: Ground Truth has no active/inactive label"
                )
            },
            "formula": (
                "Weighted mean of the six evaluable components, using "
                "original weights normalized by their sum (0.90)."
            ),
            "note": (
                "This is a revised composite score. It is not directly "
                "comparable to the earlier 0.5128 score because the earlier "
                "Evaluator included an unsupported active-state score and "
                "used incorrect false-correlation and severity logic."
            ),
        },
    }

    with REPORT_FILE.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print("\nEVALUATION COMPLETED")
    print("=" * 55)
    print(f"Dataset events: {len(dataset)}")
    print(f"Engine stories: {len(stories)}")
    print(f"Engine campaigns: {len(campaigns)}")

    print("\nRELATIONSHIPS")
    print(f"Overall Precision: {pair_metrics['overall']['precision']:.4f}")
    print(f"Overall Recall:    {pair_metrics['overall']['recall']:.4f}")
    print(f"Overall F1:        {pair_metrics['overall']['f1']:.4f}")
    print(f"Core Pair F1:      {pair_metrics['core_pairs']['f1']:.4f}")
    print(f"Core Miss Rate:    {pair_metrics['core_pairs']['core_miss_rate']:.4f}")

    print("\nFALSE CORRELATIONS (FALSE POSITIVES ONLY)")
    for name, count in false_correlations["false_pair_counts"].items():
        print(f"{name}: {count}")
    print(
        "Benign-to-CAMP001 false rate: "
        f"{false_correlations['benign_to_camp001_false_correlation_rate']:.4f}"
    )

    print("\nCAMPAIGNS")
    print(f"Purity:            {campaign_metrics['campaign_purity']:.4f}")
    print(f"Cleanliness:       {campaign_metrics['campaign_cleanliness']:.4f}")
    print(
        "Attack campaigns: "
        f"{campaign_metrics['campaigns_containing_attack_events']}"
    )
    print(
        "Majority campaigns: "
        f"{campaign_metrics['majority_attack_campaign_count']}"
    )
    print(f"Fragmented:        {campaign_metrics['fragmented']}")

    print("\nSTAGES")
    print(f"Accuracy (all 56): {stage_metrics['accuracy']:.4f}")
    print(f"Coverage:          {stage_metrics['coverage']:.4f}")
    print(
        "Conditional accuracy: "
        f"{stage_metrics['conditional_accuracy_on_evaluable_events']:.4f}"
    )
    print(f"Order correct:     {stage_metrics['stage_order_correct']}")

    print("\nSEVERITY")
    print(
        "Attack campaign score: "
        f"{severity_metrics['attack_campaign_severity_score_before_penalty']:.4f}"
    )
    print(
        "Benign traps in HIGH/CRITICAL campaigns: "
        f"{severity_metrics['benign_trap_events_in_high_or_critical_campaigns']}"
    )
    print(f"Final severity score: {severity_metrics['final_severity_score']:.4f}")

    print("\nNOISE / TRAPS")
    print(
        "Unique benign trap events: "
        f"{trap_metrics['unique_benign_trap_events']}"
    )
    print(
        "Noise suppression rate: "
        f"{campaign_metrics['noise_suppression_rate']:.4f}"
    )

    print("\nACTIVE STATE")
    print("NOT EVALUABLE - excluded from composite score")

    print("\nCOMPOSITE")
    print(f"Score: {composite:.4f}")
    print(f"\nFull report: {REPORT_FILE}")


if __name__ == "__main__":
    main()
