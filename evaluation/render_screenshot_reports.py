import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVAL = ROOT / "evaluation"
REPORT = EVAL / "evaluation_report.json"

with REPORT.open(encoding="utf-8") as f:
    r = json.load(f)

d = r["dataset"]
rel = r["relationship_metrics"]
o = rel["overall"]
c = rel["core_pairs"]
fc = r["false_correlations"]
camp = r["campaign_metrics"]
st = r["stage_metrics"]
sev = r["severity_metrics"]
traps = r["trap_metrics"]
comp = r["composite_score"]

def pct(x):
    return f"{x * 100:.2f}%"

def ratio(n, total):
    return f"{n}/{total} ({pct(n / total if total else 0)})"

def section(title):
    print("\n" + "=" * 76)
    print(f" {title}")
    print("=" * 76)

def line(label, value, explanation=""):
    print(f"{label:<39} {value:>25}")
    if explanation:
        print(f"  {explanation}")

# SCREENSHOT 1
section("01 | EVALUATION OVERVIEW")
line("Input telemetry events", f"{d['events']:,}")
line("Ground Truth events", f"{d['ground_truth_events']:,}")
line("Attack events", f"{st['total_attack_events']:,}")
line("Engine stories generated", f"{d['stories']:,}")
line("Engine campaigns generated", f"{d['campaigns']:,}")
line("Attack scenario", "CAMP-001")
print("\nGround Truth is used by the evaluator as the reference.")
print("It is not an input to the engine's correlation process.")

# SCREENSHOT 2
section("02 | RELATIONSHIP DETECTION PERFORMANCE")
line("True positive relationships", f"{o['true_positives']:,}")
line("False positive relationships", f"{o['false_positives']:,}")
line("Missed expected relationships", f"{o['false_negatives']:,}")
line("Precision", pct(o["precision"]),
     "Correct predictions / all predicted relationships")
line("Recall", pct(o["recall"]),
     "Detected expected relationships / all expected relationships")
line("Overall F1-score", pct(o["f1"]),
     "Harmonic mean of precision and recall")

section("CORE ATTACK RELATIONSHIPS")
line("Core true positives", f"{c['true_positives']:,}")
line("Core false positives", f"{c['false_positives']:,}")
line("Core false negatives", f"{c['false_negatives']:,}")
line("Core precision", pct(c["precision"]))
line("Core recall", pct(c["recall"]))
line("Core Pair F1", pct(c["f1"]))
line("Core miss rate", pct(c["core_miss_rate"]))

section("FALSE CORRELATION BREAKDOWN")
for name, count in sorted(fc["false_pair_counts"].items()):
    line(name.replace("_", " "), f"{count:,}")
line("Benign-to-attack false correlation rate",
     pct(fc["benign_to_camp001_false_correlation_rate"]),
     f"{fc['false_pair_counts'].get('BENIGN_to_CAMP001', 0)} false links / "
     f"{fc['predicted_pairs_with_attack_endpoint']} predicted attack-related links")

# SCREENSHOT 3
section("03 | CAMPAIGN RECONSTRUCTION")
line("Attack events captured in largest campaign",
     ratio(camp["attack_events_in_largest_campaign"],
           st["total_attack_events"]),
     "Campaign purity: attack-event coverage")
line("Largest campaign total events",
     f"{camp['largest_campaign_event_count']:,}")
line("Campaign cleanliness",
     pct(camp["campaign_cleanliness"]),
     f"{camp['attack_events_in_largest_campaign']} attack events / "
     f"{camp['largest_campaign_event_count']} total events")
line("Campaigns containing attack events",
     f"{camp['campaigns_containing_attack_events']:,}")
line("Majority attack campaigns",
     f"{camp['majority_attack_campaign_count']:,}")
line("Campaign fragmentation",
     str(camp["fragmented"]))

section("ATTACK STAGE RECONSTRUCTION")
line("Correct stage predictions",
     f"{st['correct']}/{st['total_attack_events']} ({pct(st['accuracy'])})")
line("Stage prediction coverage",
     f"{st['evaluated_attack_events']}/{st['total_attack_events']} ({pct(st['coverage'])})")
line("Conditional stage accuracy",
     f"{st['correct']}/{st['evaluated_attack_events']} ({pct(st['conditional_accuracy_on_evaluable_events'])})")
line("Missing or ambiguous predictions",
     f"{st['missing_or_ambiguous_predictions']:,}")
line("Stage order correct",
     str(st["stage_order_correct"]))

section("SEVERITY & BENIGN NOISE")
line("Attack campaign severity score",
     pct(sev["attack_campaign_severity_score_before_penalty"]),
     f"{len(sev['attack_campaign_details'])} attack-containing campaign(s)")
line("Benign traps in HIGH/CRITICAL campaigns",
     f"{sev['benign_trap_events_in_high_or_critical_campaigns']:,}")
line("Detected benign trap events",
     f"{traps['unique_benign_trap_events']:,}")
line("Noise suppression rate",
     pct(camp["noise_suppression_rate"]),
     f"{camp['benign_events_suppressed_from_both']} suppressed / "
     f"{r['dataset']['ground_truth_events'] - st['total_attack_events']} benign Ground Truth events")
line("Final severity score", pct(sev["final_severity_score"]))

section("OVERALL EVALUATION")
line("Composite score", pct(comp["score"]),
     "Weighted score across six evaluable components")
line("Active-state calibration", "NOT EVALUABLE",
     "No active/inactive labels in Ground Truth; excluded from composite")

print("\n" + "=" * 76)
print("END OF EVALUATION REPORT")
print(f"Full JSON report: {EVAL / 'evaluation_report.json'}")
print("=" * 76)
