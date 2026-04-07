---
title: AI Supply Chain Attack Detector
emoji: 🔐
colorFrom: red
colorTo: pink
sdk: docker
app_port: 7860
pinned: false
---

# 🔐 AI Supply Chain Attack Detector

An [OpenEnv](https://github.com/meta-pytorch/OpenEnv) environment where AI agents detect real-world AI supply chain attacks.

## Tasks

| Task | Difficulty | Description |
|------|-----------|-------------|
| `typosquat` | 🟢 Easy | Detect maliciously named packages in `requirements.txt` |
| `modelcard` | 🟡 Medium | Identify suspicious Hugging Face model cards |
| `poisoning` | 🔴 Hard | Find backdoor triggers and label inversions in training data |

## Quick Start

```bash
pip install -r requirements.txt
uvicorn server.app:app --host 0.0.0.0 --port 7860
```

## Docker

```bash
docker build -t supply-chain-detector .
docker run -p 7860:7860 -e HF_TOKEN=your_token supply-chain-detector
```

## Inference

```bash
export HF_TOKEN=your_token
export API_BASE_URL=https://router.huggingface.co/v1
export MODEL_NAME=Qwen/Qwen2.5-72B-Instruct
python inference.py
```

## API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/reset` | POST | Start new episode |
| `/step` | POST | Submit action |
| `/state` | GET | Get current state |

## Observation Space

```json
{
  "task_id": "string",
  "task_type": "typosquat|modelcard|poisoning",
  "content": "string (content to analyze)",
  "instructions": "string",
  "step": 0,
  "reward": 0.0,
  "done": false
}
```

## Action Space

```json
{
  "analysis": "detailed analysis string",
  "threats_found": ["threat1", "threat2"],
  "severity": "clean|low|medium|high|critical",
  "explanation": "justification string"
}
```

## Reward (0.0 – 1.0)

- **1.0** — All threats correctly identified with correct severity
- **0.5–0.9** — Partial detection
- **0.0** — Missed all threats or all false positives

## Baseline Scores

| Task | Score | Model |
|------|-------|-------|
| typosquat | ~0.72 | Qwen2.5-72B |
| modelcard | ~0.65 | Qwen2.5-72B |
| poisoning | ~0.55 | Qwen2.5-72B |

## Real-World Motivation

- **Typosquatting**: Thousands of malicious PyPI packages target AI/ML developers monthly
- **Model card attacks**: Backdoored models distributed via Hugging Face Hub
- **Dataset poisoning**: Poisoned training data embeds permanent backdoors in production models