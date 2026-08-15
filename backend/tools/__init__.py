"""ARGUS 2.0 — Tool Registry & Intelligence Package.

This package provides intelligent tool management for the ARGUS backend:

    - ToolRegistry: Central registry for supported investigation tools
    - ToolSelection: LLM-powered tool selection based on task description
    - FallbackChain: Automatic retry with fallback when tools fail
    - EntityExtraction: Regex + NER pipeline for entity extraction
    - IOCParser: IOC parsing and categorization (wraps argus_engine/intel/ioc_extractor.py)
    - AnomalyDetection: Z-score based anomaly detection for scan results

All tools expose async interfaces with graceful degradation when LLM is unavailable.
"""

from backend.tools.registry import ToolRegistry, get_tool_registry, ToolMetadata
from backend.tools.selection import ToolSelection, SelectionResult
from backend.tools.fallback import FallbackChain, FallbackResult
from backend.tools.entity_extraction import EntityExtraction, ExtractedEntity
from backend.tools.ioc_parser import IOCParser, IOCResult
from backend.tools.anomaly import AnomalyDetection, AnomalyResult

__all__ = [
    "ToolRegistry",
    "get_tool_registry",
    "ToolMetadata",
    "ToolSelection",
    "SelectionResult",
    "FallbackChain",
    "FallbackResult",
    "EntityExtraction",
    "ExtractedEntity",
    "IOCParser",
    "IOCResult",
    "AnomalyDetection",
    "AnomalyResult",
]
