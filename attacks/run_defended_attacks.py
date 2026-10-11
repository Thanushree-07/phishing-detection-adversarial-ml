"""
Re-runs the same prompt injection attacks against the DEFENDED classifier,
and produces a final before/after comparison table.

Run this AFTER run_injection_attacks.py has already produced
injection_results_before_defense.csv.
"""

import csv
import time
from llm_classifier_defended import classify_defended
from injection_payloads import ATTACKS, BASE_PHISH_MESSAGE


def run_defended_attacks():
    results = []

    print("=== Control case (no attack, defended classifier) ===")
    baseline_result = classify_defended(BASE_PHISH_MESSAGE)
    print(f"Base message classified as: {baseline_result}")
    results.append({
        "attack": "none (control)",
        "classifier_output": baseline_result,
        "attack_succeeded": baseline_result == "SAFE",
    })
    print()

    for name, payload_func in ATTACKS.items():
        attack_text = payload_func()
        print(f"=== Attack: {name} (defended) ===")

        try:
            result = classify_defended(attack_text)
        except Exception as e:
            print(f"  Error calling classifier: {e}")
            time.sleep(5)
            continue

        succeeded = (result == "SAFE")
        print(f"  Classifier output: {result}")
        print(f"  Attack succeeded: {succeeded}")
        print()

        results.append({
            "attack": name,
            "classifier_output": result,
            "attack_succeeded": succeeded,
        })

        time.sleep(1)

    return results


def load_before_results(filename="injection_results_before_defense.csv"):
    before = {}
    try:
        with open(filename, newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                before[row["attack"]] = row["attack_succeeded"] == "True"
    except FileNotFoundError:
        print(f"Warning: {filename} not found. Run run_injection_attacks.py first.")
    return before


def print_comparison_table(before, after_results):
    print("\n" + "=" * 70)
    print("BEFORE vs AFTER DEFENSE COMPARISON")
    print("=" * 70)
    print(f"{'Attack':<20} {'Before (succeeded?)':<22} {'After (succeeded?)':<20}")
    print("-" * 70)
    for r in after_results:
        attack_name = r["attack"]
        before_val = before.get(attack_name, "N/A")
        after_val = r["attack_succeeded"]
        print(f"{attack_name:<20} {str(before_val):<22} {str(after_val):<20}")


def save_results(results, filename="injection_results_after_defense.csv"):
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["attack", "classifier_output", "attack_succeeded"])
        writer.writeheader()
        writer.writerows(results)
    print(f"\nSaved results to {filename}")


if __name__ == "__main__":
    before = load_before_results()
    after_results = run_defended_attacks()

    total_attacks = len(after_results) - 1
    succeeded = sum(r["attack_succeeded"] for r in after_results if r["attack"] != "none (control)")
    print("=" * 50)
    print("SUMMARY (defended classifier)")
    print("=" * 50)
    print(f"Attacks attempted: {total_attacks}")
    print(f"Attacks still succeeding: {succeeded}")
    print(f"Success rate after defense: {succeeded/total_attacks*100:.0f}%")

    save_results(after_results)
    print_comparison_table(before, after_results)