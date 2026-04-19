#!/usr/bin/env python3
"""
Export fine-tuned model to ONNX format for Cerbero Sentinel.

Takes a trained PyTorch model and produces:
  - prompt-injection.onnx (quantized INT8 for fast inference)
  - vocab.txt (WordPiece vocabulary for Rust tokenizer)

Usage:
  python export_onnx.py --model models/prompt-injection --output ../models/
"""

import os
import sys
import shutil
import argparse

def main():
    parser = argparse.ArgumentParser(description="Export model to ONNX")
    parser.add_argument("--model", required=True, help="Trained model directory")
    parser.add_argument("--output", default="../models/", help="Output directory for ONNX files")
    parser.add_argument("--quantize", action="store_true", default=True, help="Quantize to INT8")
    parser.add_argument("--no-quantize", action="store_false", dest="quantize")
    args = parser.parse_args()

    try:
        from optimum.onnxruntime import ORTModelForSequenceClassification, ORTQuantizer
        from optimum.onnxruntime.configuration import AutoQuantizationConfig
        from transformers import AutoTokenizer
    except ImportError:
        print("Install dependencies: pip install -r requirements.txt")
        sys.exit(1)

    if not os.path.exists(args.model):
        print(f"Error: Model not found at {args.model}")
        sys.exit(1)

    os.makedirs(args.output, exist_ok=True)

    # Export to ONNX
    print(f"Exporting {args.model} to ONNX...")
    onnx_model = ORTModelForSequenceClassification.from_pretrained(args.model, export=True)
    onnx_dir = os.path.join(args.output, "onnx_tmp")
    onnx_model.save_pretrained(onnx_dir)

    if args.quantize:
        print("Quantizing to INT8...")
        quantizer = ORTQuantizer.from_pretrained(onnx_dir)
        qconfig = AutoQuantizationConfig.avx512_vnni(is_static=False)
        quantizer.quantize(save_dir=onnx_dir, quantization_config=qconfig)

    # Copy ONNX file to output
    for f in os.listdir(onnx_dir):
        if f.endswith(".onnx"):
            src = os.path.join(onnx_dir, f)
            dst = os.path.join(args.output, "prompt-injection.onnx")
            shutil.copy2(src, dst)
            size_mb = os.path.getsize(dst) / (1024 * 1024)
            print(f"  {dst} ({size_mb:.1f} MB)")
            break

    # Copy vocab.txt
    tokenizer = AutoTokenizer.from_pretrained(args.model)
    tokenizer.save_pretrained(args.output)
    vocab_src = os.path.join(args.output, "vocab.txt")
    if os.path.exists(vocab_src):
        print(f"  vocab.txt saved to {args.output}")
    else:
        # Some tokenizers use spiece.model instead
        print("  Warning: vocab.txt not found. Your tokenizer may use sentencepiece.")

    # Cleanup temp
    shutil.rmtree(onnx_dir, ignore_errors=True)

    print(f"\nDone. Files in {args.output}:")
    for f in sorted(os.listdir(args.output)):
        if not f.startswith("."):
            size = os.path.getsize(os.path.join(args.output, f))
            print(f"  {f} ({size / 1024:.0f} KB)")

    print(f"\nSet SENTINEL_MODELS_PATH={os.path.abspath(args.output)} and restart Cerbero.")

if __name__ == "__main__":
    main()
