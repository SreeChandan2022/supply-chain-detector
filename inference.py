"""
inference.py — AI Supply Chain Attack Detector
Baseline inference script using OpenAI client against all 3 tasks.

Required env vars:
    HF_TOKEN or API_KEY   — Hugging Face / API key
    API_BASE_URL          — LLM API endpoint
    MODEL_NAME            — model identifier
"""
import os
import json
import textwrap
from typing import Optional, List
from openai import OpenAI

API_KEY = os.getenv("HF_TOKEN") or os.getenv("API_KEY")
API_BASE_URL = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
MODEL_NAME = os.getenv("MODEL_NAME", "Qwen/Qwen2.5-72B-Instruct")
MAX_STEPS = 5
MAX_TOKENS = 512
TEMPERATURE = 0.2
SUCCESS_THRESHOLD = 0.5
TASKS = ["typosquat", "modelcard", "poisoning"]
ENV_NAME = "supply-chain-detector"

SYSTEM_PROMPT = textwrap.dedent("""
You are an expert AI supply chain security analyst.
Analyze the provided content and detect security threats.

You MUST respond ONLY with a valid JSON object — no markdown, no preamble:
{
  "analysis": "your detailed analysis",
  "threats_found": ["threat 1", "threat 2"],
  "severity": "clean|low|medium|high|critical",
  "explanation": "why you assessed this severity"
}

Guidelines:
- Typosquatting: look for misspelled package names (torchh, numpyy, 0penai, etc.)
- Model cards: look for anonymous authors, no license, impossible scores, trigger phrases
- Dataset poisoning: look for trigger phrases, label inversions, statistical anomalies
- If nothing suspicious: threats_found=[], severity="clean"
""").strip()


def log_start(task: str, env: str, model: str) -> None:
    print(f"[START] task={task} env={env} model={model}", flush=True)


def log_step(step: int, action: str, reward: float, done: bool, error: Optional[str]) -> None:
    error_val = error if error else "null"
    done_val = str(done).lower()
    print(f"[STEP] step={step} action={action} reward={reward:.2f} done={done_val} error={error_val}", flush=True)


def log_end(success: bool, steps: int, score: float, rewards: List[float]) -> None:
    rewards_str = ",".join(f"{r:.2f}" for r in rewards)
    print(f"[END] success={str(success).lower()} steps={steps} score={score:.3f} rewards={rewards_str}", flush=True)


def call_model(client: OpenAI, content: str, instructions: str, step: int) -> dict:
    user_msg = f"Instructions: {instructions}\n\nContent:\n{content}\n\nStep: {step}\nRespond ONLY with JSON."
    try:
        resp = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_msg},
            ],
            max_tokens=MAX_TOKENS,
            temperature=TEMPERATURE,
        )
        raw = resp.choices[0].message.content.strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        return json.loads(raw.strip())
    except Exception as e:
        return {"analysis": f"error: {e}", "threats_found": [], "severity": "clean", "explanation": ""}


def run_task_local(client: OpenAI, task_name: str) -> dict:
    """Run inference against the local environment directly (no HTTP needed)."""
    # Import environment directly
    try:
        from server.supply_chain_environment import SupplyChainEnvironment, ALL_SAMPLES, INSTRUCTIONS, GRADERS
    except ImportError:
        print(f"[ERROR] Could not import environment", flush=True)
        return {"task": task_name, "score": 0.0, "success": False, "steps": 0}

    env = SupplyChainEnvironment(task=task_name)
    obs = env.reset()

    log_start(task=task_name, env=ENV_NAME, model=MODEL_NAME)

    rewards = []
    step = 0
    done = False

    while not done and step < MAX_STEPS:
        step += 1
        try:
            result = call_model(client, obs.content, obs.instructions, step)
            from models import SupplyChainAction
            action = SupplyChainAction(
                analysis=result.get("analysis", ""),
                threats_found=result.get("threats_found", []),
                severity=result.get("severity", "clean"),
                explanation=result.get("explanation", ""),
            )
            obs = env.step(action)
            reward = obs.reward
            done = obs.done

            action_summary = f"threats={len(action.threats_found)},severity={action.severity}"
            log_step(step=step, action=action_summary, reward=reward, done=done, error=None)
            rewards.append(reward)

        except Exception as e:
            log_step(step=step, action="error", reward=0.0, done=True, error=str(e))
            rewards.append(0.0)
            done = True

    avg_score = sum(rewards) / len(rewards) if rewards else 0.0
    success = avg_score >= SUCCESS_THRESHOLD
    log_end(success=success, steps=step, score=avg_score, rewards=rewards)
    return {"task": task_name, "score": avg_score, "success": success, "steps": step}


def main():
    if not API_KEY:
        raise ValueError("HF_TOKEN or API_KEY environment variable must be set")

    client = OpenAI(api_key=API_KEY, base_url=API_BASE_URL)
    results = []

    for task in TASKS:
        print(f"\n{'='*60}", flush=True)
        print(f"Running task: {task}", flush=True)
        print('='*60, flush=True)
        result = run_task_local(client, task)
        results.append(result)

    print(f"\n{'='*60}", flush=True)
    print("FINAL RESULTS", flush=True)
    print('='*60, flush=True)
    for r in results:
        status = "PASS" if r["success"] else "FAIL"
        print(f"[{status}] {r['task']:<12} score={r['score']:.3f} steps={r['steps']}", flush=True)

    overall = sum(r["score"] for r in results) / len(results)
    print(f"\nOverall average score: {overall:.3f}", flush=True)


if __name__ == "__main__":
    main()