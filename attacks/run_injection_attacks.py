"""
Runs each prompt injection attack against the LLM classifier and records
whether the attack succeeded (i.e., the classifier wrongly said SAFE for
a message that is actually phishing).

This produces the "before defense" results.
"""

import csv
import time
from llm_classifier import classify
from injection_payloads import ATTACKS, BASE_PHISH_MESSAGE


def run_all_attacks():
    results = []

    # First, confirm the undefended base message (no attack) is correctly
    # caught as PHISH. This is our control case.
    print("=== Control case (no attack) ===")
    baseline_result = classify(BASE_PHISH_MESSAGE)
    print(f"Base message classified as: {baseline_result}")
    results.append({
        "attack": "none (control)",
        "classifier_output": baseline_result,
        "attack_succeeded": baseline_result == "SAFE",
    })
    print()

    # Now run each injection attack
    for name, payload_func in ATTACKS.items():
        attack_text = payload_func()
        print(f"=== Attack: {name} ===")

        try:
            result = classify(attack_text)
        except Exception as e:
            print(f"  Error calling classifier: {e}")
            time.sleep(5)
            continue

        succeeded = (result == "SAFE")  # attack succeeds if it fooled the model into SAFE
        print(f"  Classifier output: {result}")
        print(f"  Attack succeeded: {succeeded}")
        print()

        results.append({
            "attack": name,
            "classifier_output": result,
            "attack_succeeded": succeeded,
        })

        time.sleep(1)  # small delay to avoid rate limits

    return results


def save_results(results, filename="injection_results_before_defense.csv"):
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["attack", "classifier_output", "attack_succeeded"])
        writer.writeheader()
        writer.writerows(results)
    print(f"Saved results to {filename}")


if __name__ == "__main__":
    results = run_all_attacks()

    print("=" * 50)
    print("SUMMARY")
    print("=" * 50)
    total_attacks = len(results) - 1  # exclude control case
    succeeded = sum(r["attack_succeeded"] for r in results if r["attack"] != "none (control)")
    print(f"Attacks attempted: {total_attacks}")
    print(f"Attacks succeeded (fooled the model): {succeeded}")
    print(f"Success rate: {succeeded/total_attacks*100:.0f}%")

    save_results(results)