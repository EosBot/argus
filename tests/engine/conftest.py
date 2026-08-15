"""Shared pytest fixtures for ARGUS OSINT test suite."""

import os
import sys
import tempfile
import shutil
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure the argus_engine package is importable
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


@pytest.fixture
def tmp_dir():
    """Provide a temporary directory that is cleaned up after the test."""
    d = tempfile.mkdtemp()
    yield Path(d)
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def mock_env_vars(tmp_dir):
    """Set up mock environment variables for testing."""
    env_vars = {
        "OPENAI_API_KEY": "test-openai-key",
        "GOOGLE_API_KEY": "test-google-key",
        "ANTHROPIC_API_KEY": "test-anthropic-key",
        "OLLAMA_BASE_URL": "http://localhost:11434",
        "OPENROUTER_API_KEY": "test-openrouter-key",
        "TOR_CONTROL_PASSWORD": "test-tor-password",
    }
    old_env = {k: os.environ.get(k) for k in env_vars}
    os.environ.update(env_vars)
    yield env_vars
    for k, v in old_env.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


@pytest.fixture
def mock_requests():
    """Mock the requests library."""
    with patch("requests.get") as mock_get:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {}
        mock_response.text = ""
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response
        yield mock_get


@pytest.fixture
def mock_stem():
    """Mock the stem library for Tor control."""
    with patch("stem.control.Controller") as mock_controller:
        mock_instance = MagicMock()
        mock_controller.from_port.return_value.__enter__ = MagicMock(return_value=mock_instance)
        mock_controller.from_port.return_value.__exit__ = MagicMock(return_value=False)
        yield mock_controller


@pytest.fixture
def mock_ddg():
    """Mock DuckDuckGo search."""
    with patch("duckduckgo_search.DDGS") as mock_ddgs:
        mock_instance = MagicMock()
        mock_ddgs.return_value.__enter__ = MagicMock(return_value=mock_instance)
        mock_ddgs.return_value.__exit__ = MagicMock(return_value=False)
        yield mock_instance


@pytest.fixture
def mock_exa():
    """Mock Exa search."""
    with patch("exa_py.Exa") as mock_exa_cls:
        mock_instance = MagicMock()
        mock_exa_cls.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def mock_engram():
    """Mock engram MCP tools."""
    with patch("engram.mem_save", return_value={"status": "ok"}), \
         patch("engram.mem_search", return_value=[]), \
         patch("engram.mem_context", return_value={}):
        yield


@pytest.fixture
def mock_tor_health():
    """Mock Tor health check socket."""
    with patch("socket.create_connection") as mock_sock:
        mock_conn = MagicMock()
        mock_sock.return_value = mock_conn
        yield mock_sock
