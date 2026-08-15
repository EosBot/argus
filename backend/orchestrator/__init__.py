"""ARGUS Orchestrator — central investigation planning and execution engine.

This package implements the Prometheus Orchestrator for ARGUS:
- ReAct loop planner (reasoning + acting cycle)
- Investigation plan creator (DAG of agent tasks)
- Agent dispatcher (Celery + Redis for background execution)
- Monitor loop (5s heartbeat checking agent status)
- Dynamic adaptation (replan on failure or new leads)
- Correlation engine (cross-agent finding correlation)
- State machine (investigation lifecycle)

Usage::

    from backend.orchestrator import InvestigationOrchestrator
    orch = InvestigationOrchestrator()
    plan = await orch.create_plan("investigate target.com")
    await orch.execute_plan(plan)
"""

from backend.orchestrator.state_machine import InvestigationStatus, InvestigationStateMachine
from backend.orchestrator.planner import ReActPlanner, InvestigationPlan, PlanStep, StepType
from backend.orchestrator.dispatcher import AgentDispatcher, DispatchResult
from backend.orchestrator.monitor import MonitorLoop, InvestigationProgress, AgentHeartbeat
from backend.orchestrator.adapter import DynamicAdapter, AdaptationDecision
from backend.orchestrator.correlation import CorrelationEngine, CorrelationReport, CorrelationFinding
from backend.orchestrator.orchestrator import PrometheusOrchestrator

__all__ = [
    "InvestigationStatus",
    "InvestigationStateMachine",
    "ReActPlanner",
    "InvestigationPlan",
    "PlanStep",
    "StepType",
    "AgentDispatcher",
    "DispatchResult",
    "MonitorLoop",
    "InvestigationProgress",
    "AgentHeartbeat",
    "DynamicAdapter",
    "AdaptationDecision",
    "CorrelationEngine",
    "CorrelationReport",
    "CorrelationFinding",
    "PrometheusOrchestrator",
]
