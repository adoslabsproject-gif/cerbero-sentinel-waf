# Cerbero Sentinel — Training Pipeline

Train and customize ML models for your specific platform.

## How It Works

1. **Download base models** from Hugging Face (DeBERTa, MiniLM)
2. **Collect data** from your Cerbero logs (blocked requests = positive, allowed = negative)
3. **Fine-tune** the model on your platform's specific attack patterns
4. **Export to ONNX** and deploy

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Download base models from Hugging Face
python download_base_models.py

# 3. Collect training data from your logs
python collect_training_data.py --logs /path/to/sentinel.log --output data/

# 4. Fine-tune prompt injection model
python train_prompt_injection.py --data data/ --output models/

# 5. Export to ONNX
python export_onnx.py --model models/prompt-injection --output ../models/

# 6. Restart Cerbero — it will auto-detect the new models
SENTINEL_MODELS_PATH=../models/ ../target/release/sentinel
```

## Retraining Schedule

Run the training pipeline periodically (weekly/monthly) to keep models current with new attack patterns. Each run produces a new ONNX model that replaces the previous one.

```bash
# Cron example: retrain every Sunday at 3 AM
0 3 * * 0 cd /opt/sentinel/training && python retrain.py >> /var/log/sentinel-training.log 2>&1
```
