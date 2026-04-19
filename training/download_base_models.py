#!/usr/bin/env python3
"""
Download base models from Hugging Face for Cerbero Sentinel training.

Downloads:
  - DeBERTa-v3-base for prompt injection detection
  - all-MiniLM-L6-v2 for semantic embeddings
  - Tokenizer vocabulary (vocab.txt)

These are the starting point — fine-tune them with your own data
using train_prompt_injection.py.
"""

import os
import sys

def main():
    try:
        from transformers import AutoTokenizer, AutoModelForSequenceClassification
        from optimum.onnxruntime import ORTModelForSequenceClassification
    except ImportError:
        print("Install dependencies first: pip install -r requirements.txt")
        sys.exit(1)

    base_dir = os.path.join(os.path.dirname(__file__), "base_models")
    os.makedirs(base_dir, exist_ok=True)

    # 1. Prompt Injection — DeBERTa-v3-base (fine-tuned by ProtectAI)
    print("Downloading prompt injection model (DeBERTa-v3-base)...")
    model_name = "protectai/deberta-v3-base-prompt-injection-v2"
    try:
        tokenizer = AutoTokenizer.from_pretrained(model_name)
        model = AutoModelForSequenceClassification.from_pretrained(model_name)
        save_path = os.path.join(base_dir, "prompt-injection")
        tokenizer.save_pretrained(save_path)
        model.save_pretrained(save_path)
        print(f"  Saved to {save_path}")

        # Export to ONNX
        print("  Exporting to ONNX...")
        onnx_model = ORTModelForSequenceClassification.from_pretrained(save_path, export=True)
        onnx_path = os.path.join(base_dir, "prompt-injection-onnx")
        onnx_model.save_pretrained(onnx_path)
        print(f"  ONNX model saved to {onnx_path}")
    except Exception as e:
        print(f"  Error: {e}")
        print("  You can download manually from: https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2")

    # 2. Embeddings — all-MiniLM-L6-v2
    print("\nDownloading embeddings model (all-MiniLM-L6-v2)...")
    model_name = "sentence-transformers/all-MiniLM-L6-v2"
    try:
        tokenizer = AutoTokenizer.from_pretrained(model_name)
        save_path = os.path.join(base_dir, "embeddings")
        tokenizer.save_pretrained(save_path)

        # Save vocab.txt for Cerbero's Rust tokenizer
        vocab_file = os.path.join(save_path, "vocab.txt")
        if os.path.exists(vocab_file):
            import shutil
            shutil.copy(vocab_file, os.path.join(base_dir, "vocab.txt"))
            print(f"  vocab.txt copied to {base_dir}/vocab.txt")
        print(f"  Saved to {save_path}")
    except Exception as e:
        print(f"  Error: {e}")

    print("\n--- Done ---")
    print(f"\nBase models saved to: {base_dir}/")
    print("\nNext steps:")
    print("  1. Collect training data: python collect_training_data.py --logs /path/to/sentinel.log")
    print("  2. Fine-tune: python train_prompt_injection.py --data data/ --output models/")
    print("  3. Export: python export_onnx.py --model models/prompt-injection --output ../models/")
    print("  4. Copy vocab.txt to your models dir: cp base_models/vocab.txt ../models/")

if __name__ == "__main__":
    main()
