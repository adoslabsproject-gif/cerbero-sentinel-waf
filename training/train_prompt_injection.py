#!/usr/bin/env python3
"""
Fine-tune DeBERTa for prompt injection detection on YOUR platform's data.

Takes the base model (from download_base_models.py) and your collected data
(from collect_training_data.py), fine-tunes it, and saves the result.

Usage:
  python train_prompt_injection.py --data data/ --output models/prompt-injection
  python train_prompt_injection.py --data data/ --output models/prompt-injection --epochs 5 --lr 2e-5
"""

import json
import os
import sys
import argparse

def main():
    parser = argparse.ArgumentParser(description="Fine-tune prompt injection model")
    parser.add_argument("--data", required=True, help="Directory with train.jsonl")
    parser.add_argument("--output", default="models/prompt-injection", help="Output directory")
    parser.add_argument("--base-model", default="base_models/prompt-injection",
                        help="Base model directory (from download_base_models.py)")
    parser.add_argument("--epochs", type=int, default=3, help="Training epochs")
    parser.add_argument("--batch-size", type=int, default=16, help="Batch size")
    parser.add_argument("--lr", type=float, default=2e-5, help="Learning rate")
    parser.add_argument("--max-length", type=int, default=512, help="Max token length")
    args = parser.parse_args()

    try:
        import torch
        from transformers import (
            AutoTokenizer,
            AutoModelForSequenceClassification,
            TrainingArguments,
            Trainer,
        )
        from datasets import Dataset
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import accuracy_score, precision_recall_fscore_support
    except ImportError:
        print("Install dependencies: pip install -r requirements.txt")
        sys.exit(1)

    # Load data
    train_file = os.path.join(args.data, "train.jsonl")
    if not os.path.exists(train_file):
        print(f"Error: {train_file} not found. Run collect_training_data.py first.")
        sys.exit(1)

    samples = []
    with open(train_file) as f:
        for line in f:
            samples.append(json.loads(line))

    if len(samples) < 20:
        print(f"Error: Only {len(samples)} samples. Need at least 20 for training.")
        sys.exit(1)

    print(f"Loaded {len(samples)} samples")
    labels = [s["label"] for s in samples]
    print(f"  Positive (attack): {sum(labels)}")
    print(f"  Negative (benign): {len(labels) - sum(labels)}")

    # Split
    texts = [s["text"] for s in samples]
    train_texts, val_texts, train_labels, val_labels = train_test_split(
        texts, labels, test_size=0.1, random_state=42, stratify=labels
    )

    # Load base model
    base = args.base_model
    if not os.path.exists(base):
        print(f"Base model not found at {base}")
        print("Falling back to Hugging Face: protectai/deberta-v3-base-prompt-injection-v2")
        base = "protectai/deberta-v3-base-prompt-injection-v2"

    print(f"\nLoading base model: {base}")
    tokenizer = AutoTokenizer.from_pretrained(base)
    model = AutoModelForSequenceClassification.from_pretrained(base, num_labels=2)

    # Tokenize
    def tokenize(texts):
        return tokenizer(texts, padding="max_length", truncation=True,
                         max_length=args.max_length, return_tensors="pt")

    train_enc = tokenize(train_texts)
    val_enc = tokenize(val_texts)

    train_dataset = Dataset.from_dict({
        "input_ids": train_enc["input_ids"],
        "attention_mask": train_enc["attention_mask"],
        "labels": train_labels,
    })
    val_dataset = Dataset.from_dict({
        "input_ids": val_enc["input_ids"],
        "attention_mask": val_enc["attention_mask"],
        "labels": val_labels,
    })

    # Metrics
    def compute_metrics(pred):
        preds = pred.predictions.argmax(-1)
        precision, recall, f1, _ = precision_recall_fscore_support(
            pred.label_ids, preds, average="binary"
        )
        acc = accuracy_score(pred.label_ids, preds)
        return {"accuracy": acc, "f1": f1, "precision": precision, "recall": recall}

    # Train
    os.makedirs(args.output, exist_ok=True)
    training_args = TrainingArguments(
        output_dir=args.output,
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        learning_rate=args.lr,
        weight_decay=0.01,
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        logging_steps=50,
        fp16=torch.cuda.is_available(),
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
        compute_metrics=compute_metrics,
    )

    print(f"\nTraining for {args.epochs} epochs...")
    trainer.train()

    # Evaluate
    results = trainer.evaluate()
    print(f"\nResults:")
    print(f"  Accuracy:  {results['eval_accuracy']:.4f}")
    print(f"  F1:        {results['eval_f1']:.4f}")
    print(f"  Precision: {results['eval_precision']:.4f}")
    print(f"  Recall:    {results['eval_recall']:.4f}")

    # Save
    trainer.save_model(args.output)
    tokenizer.save_pretrained(args.output)
    print(f"\nModel saved to {args.output}")
    print(f"\nNext: python export_onnx.py --model {args.output} --output ../models/")

if __name__ == "__main__":
    main()
