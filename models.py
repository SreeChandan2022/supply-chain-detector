"""
Pydantic models for the AI Supply Chain Attack Detector environment.
"""
from pydantic import BaseModel, Field
from typing import List, Optional


class SupplyChainAction(BaseModel):
    analysis: str = Field(description="Agent's detailed analysis of the content")
    threats_found: List[str] = Field(default_factory=list, description="List of identified threats")
    severity: str = Field(default="clean", description="clean | low | medium | high | critical")
    explanation: str = Field(default="", description="Justification for the severity assessment")


class SupplyChainObservation(BaseModel):
    task_id: str = Field(description="Unique sample identifier")
    task_type: str = Field(description="typosquat | modelcard | poisoning")
    content: str = Field(description="The content to analyze")
    instructions: str = Field(description="Task-specific instructions for the agent")
    step: int = Field(default=0, description="Current step number")
    reward: float = Field(default=0.0, description="Last reward received")
    done: bool = Field(default=False, description="Whether episode is complete")


class SupplyChainState(BaseModel):
    task: str = Field(default="typosquat")
    step: int = Field(default=0)
    done: bool = Field(default=False)
    episode_id: str = Field(default="")
    current_sample_id: Optional[str] = Field(default=None)