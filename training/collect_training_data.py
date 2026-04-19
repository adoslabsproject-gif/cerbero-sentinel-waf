#!/usr/bin/env python3
"""
Collect training data from Cerbero Sentinel logs.

Reads structured JSON logs and extracts:
  - Blocked requests → positive examples (attacks)
  - Allowed requests → negative examples (benign)

Produces a labeled dataset for fine-tuning the prompt injection model.

Usage:
  python collect_training_data.py --logs /path/to/sentinel.log --output data/
  python collect_training_data.py --logs /path/to/sentinel.log --output data/ --min-score 0.6
"""

import json
import os
import sys
import argparse
from collections import Counter

def parse_log_line(line):
    """Parse a single JSON log line."""
    try:
        data = json.loads(line.strip())
        fields = data.get("fields", {})
        return {
            "level": data.get("level", ""),
            "message": fields.get("message", ""),
            "ip": fields.get("ip", ""),
            "path": fields.get("path", ""),
            "score": fields.get("score", 0),
            "flags": fields.get("flags", ""),
            "body": fields.get("body", ""),
            "action": fields.get("action", ""),
        }
    except (json.JSONDecodeError, KeyError):
        return None

def main():
    parser = argparse.ArgumentParser(description="Collect training data from Cerbero logs")
    parser.add_argument("--logs", required=True, help="Path to sentinel log file")
    parser.add_argument("--output", default="data/", help="Output directory")
    parser.add_argument("--min-score", type=float, default=0.5, help="Minimum score for positive examples")
    parser.add_argument("--max-samples", type=int, default=50000, help="Maximum samples per class")
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)

    positives = []  # attacks
    negatives = []  # benign

    print(f"Reading logs from {args.logs}...")

    with open(args.logs, "r") as f:
        for line in f:
            entry = parse_log_line(line)
            if not entry or not entry.get("body"):
                continue

            body = entry["body"].strip()
            if len(body) < 5 or len(body) > 5000:
                continue

            score = entry.get("score", 0)

            if score >= args.min_score or "block" in entry.get("action", "").lower():
                positives.append({"text": body, "label": 1, "score": score})
            elif score < 0.2:
                negatives.append({"text": body, "label": 0, "score": score})

    # Balance classes
    positives = positives[:args.max_samples]
    negatives = negatives[:args.max_samples]

    print(f"\nCollected:")
    print(f"  Positive (attack) samples: {len(positives)}")
    print(f"  Negative (benign) samples: {len(negatives)}")

    if len(positives) < 10:
        print("\nWarning: Very few positive samples. You need more blocked requests in your logs.")
        print("Run Cerbero for a few weeks to collect enough attack data.")

    # Save as JSONL
    train_file = os.path.join(args.output, "train.jsonl")
    with open(train_file, "w") as f:
        for sample in positives + negatives:
            f.write(json.dumps(sample) + "\n")

    print(f"\nTraining data saved to {train_file}")
    print(f"Total samples: {len(positives) + len(negatives)}")

    # Stats
    if positives:
        flags = Counter()
        for p in positives:
            for flag in str(p.get("flags", "")).split(","):
                flag = flag.strip().strip("[]\"' ")
                if flag:
                    flags[flag] += 1
        if flags:
            print("\nTop attack types:")
            for flag, count in flags.most_common(10):
                print(f"  {flag}: {count}")

    print(f"\nNext: python train_prompt_injection.py --data {args.output} --output models/")

if __name__ == "__main__":
    main()
