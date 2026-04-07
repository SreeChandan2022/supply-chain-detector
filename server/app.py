"""
server/app.py — AI Supply Chain Attack Detector
Uses openenv.core create_app to expose the environment as a FastAPI server.
"""
import os

try:
    from openenv.core.env_server import create_app
except ImportError:
    # Fallback: manual FastAPI app if openenv not installed
    from fastapi import FastAPI
    create_app = None

try:
    from ..models import SupplyChainAction, SupplyChainObservation
    from .supply_chain_environment import SupplyChainEnvironment
except ImportError:
    from models import SupplyChainAction, SupplyChainObservation
    from server.supply_chain_environment import SupplyChainEnvironment

TASK = os.getenv("SUPPLY_CHAIN_TASK", "typosquat")


def create_supply_chain_env():
    return SupplyChainEnvironment(task=TASK)


if create_app is not None:
    app = create_app(
        create_supply_chain_env,
        SupplyChainAction,
        SupplyChainObservation,
        env_name="supply-chain-detector",
    )
else:
    # Fallback FastAPI app
    from fastapi import FastAPI
    from pydantic import BaseModel

    app = FastAPI(title="AI Supply Chain Attack Detector", version="1.0.0")
    _env = SupplyChainEnvironment(task=TASK)

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.post("/reset")
    def reset():
        obs = _env.reset()
        return obs.model_dump()

    @app.post("/step")
    def step(action: SupplyChainAction):
        obs = _env.step(action)
        return {"observation": obs.model_dump(), "reward": obs.reward, "done": obs.done, "info": {}}

    @app.get("/state")
    def state():
        return _env.state.model_dump()

    @app.get("/tasks")
    def tasks():
        return {"tasks": ["typosquat", "modelcard", "poisoning"]}


def main():
    import uvicorn
    uvicorn.run("server.app:app", host="0.0.0.0", port=7860, reload=False)


if __name__ == "__main__":
    main()