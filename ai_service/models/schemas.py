"""Pydantic request/response models."""
from pydantic import BaseModel, Field
from typing import Optional


class ChatRequest(BaseModel):
    session_id: str = Field(..., description="PeliCap capture session UUID")
    message: str    = Field(..., min_length=1, max_length=4000)
    conversation_id: Optional[str] = Field(None, description="Omit to start a new conversation")
    is_live: bool = Field(True, description="False when viewing a historical (stopped) session")


class ExplainPacketRequest(BaseModel):
    packet: dict = Field(..., description="Parsed packet JSON from /api/packets")
    session_id: str


class ExplainFlowRequest(BaseModel):
    flow: dict = Field(..., description="Flow JSON from /api/search or /api/flows/{id}")
    session_id: str


class AutoAnalyzeRequest(BaseModel):
    session_id: str
    is_live: bool = Field(True, description="False when viewing a historical (stopped) session")


class UsageResponse(BaseModel):
    input_tokens_hour:  int
    output_tokens_hour: int
    input_tokens_day:   int
    output_tokens_day:  int


class HealthResponse(BaseModel):
    groq:    str
    backend: str
    status:  str
