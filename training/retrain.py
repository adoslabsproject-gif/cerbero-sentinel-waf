#!/usr/bin/env python3
"""
Automated retraining — run periodically to keep models current.

Full pipeline:
  1. Collect new data from logs
  2. Merge with existing training data
  3. Fine-tune model
  4. Export to ONNX
  5. Replace old model (atomic swap)

Usage:
  python retrain.py --logs /path/to/sentinel.log --models /path/to/models/

Cron:
  0 3 * * 0 cd /opt/sentinel/training && python retrain.py --logs /var/log/sentinel.log --models /opt/sentinel/models/
"""

import os
import sys
import json
import shutil
import argparse
from datetime import datetime

def main():
    parser = argparse.ArgumentParser(description="Automated model retraining")
    parser.add_argument("--logs", required=True, help="Sentinel log file")
    parser.add_argument("--models", required=True, help="Models directory (where ONNX files go)")
    parser.add_argument("--data-dir", default="data/", help="Training data directory")
    parser.add_argument("--min-new-samples", type=int, default=50, help="Minimum new samples to trigger retraining")
    args = parser.parse_args()

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    print(f"=== Cerbero Sentinel Retraining — {timestamp} ===\n")

    # Step 1: Collect new data
    print("Step 1: Collecting new training data...")
    os.system(f"python collect_training_data.py --logs {args.logs} --output {args.data_dir}")

    train_file = os.path.join(args.data_dir, "train.jsonl")
    if not os.path.exists(train_file):
        print("No training data collected. Skipping retraining.")
        return

    with open(train_file) as f:
        sample_count = sum(1 for _ in f)

    if sample_count < args.min_new_samples:
        print(f"Only {sample_count} samples (minimum: {args.min_new_samples}). Skipping.")
        return

    print(f"  {sample_count} samples collected\n")

    # Step 2: Train
    print("Step 2: Fine-tuning model...")
    model_dir = f"models/prompt-injection-{timestamp}"
    exit_code = os.system(
        f"python train_prompt_injection.py --data {args.data_dir} --output {model_dir} --epochs 3"
    )
    if exit_code != 0:
        print("Training failed. Keeping existing model.")
        return

    # Step 3: Export to ONNX
    print("\nStep 3: Exporting to ONNX...")
    tmp_output = f"models/onnx-{timestamp}"
    exit_code = os.system(
        f"python export_onnx.py --model {model_dir} --output {tmp_output}"
    )
    if exit_code != 0:
        print("ONNX export failed. Keeping existing model.")
        return

    # Step 4: Atomic swap — backup old, copy new
    print("\nStep 4: Deploying new model...")
    onnx_file = os.path.join(tmp_output, "prompt-injection.onnx")
    if not os.path.exists(onnx_file):
        print("ONNX file not found. Keeping existing model.")
        return

    target = os.path.join(args.models, "prompt-injection.onnx")
    backup = os.path.join(args.models, f"prompt-injection.onnx.backup-{timestamp}")

    # Backup existing
    if os.path.exists(target):
        shutil.copy2(target, backup)
        print(f"  Backed up existing model to {backup}")

    # Copy new
    shutil.copy2(onnx_file, target)
    print(f"  New model deployed to {target}")

    # Copy vocab if updated
    vocab_src = os.path.join(tmp_output, "vocab.txt")
    if os.path.exists(vocab_src):
        shutil.copy2(vocab_src, os.path.join(args.models, "vocab.txt"))

    # Cleanup
    shutil.rmtree(tmp_output, ignore_errors=True)

    print(f"\n=== Retraining complete. Restart Cerbero to load the new model. ===")
    print(f"  Model: {target}")
    print(f"  Samples: {sample_count}")
    print(f"  Backup: {backup}")

if __name__ == "__main__":
    main()
