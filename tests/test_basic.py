"""Basic sanity tests for llama_predator — offline, no network."""
import importlib.util
import sys
import types
from unittest.mock import MagicMock, patch

# Load the standalone script as a module
spec = importlib.util.spec_from_file_location("llama_predator", "llama_predator.py")
mod = importlib.util.module_from_spec(spec)


class _FakeRequests(types.ModuleType):
    Session = MagicMock
    exceptions = MagicMock()
    exceptions.RequestException = Exception


sys.modules.setdefault("requests", _FakeRequests("requests"))
sys.modules.setdefault("urllib3", MagicMock())
sys.modules.setdefault("urllib3.exceptions", MagicMock())

spec.loader.exec_module(mod)


def test_finding_severity_keys():
    mod.findings.clear()
    mod.finding("HIGH", "test title", "test detail")
    assert len(mod.findings) == 1
    f = mod.findings[0]
    assert f["severity"] == "HIGH"
    assert f["title"] == "test title"
    mod.findings.clear()


def test_rand_text_length():
    for n in (8, 32, 128):
        t = mod.rand_text(n)
        assert len(t) == n


def test_rand_text_weird():
    t = mod.rand_text(50, weird=True)
    assert len(t) == 50


def test_make_body_completion():
    body = mod.make_body("/completion", "hello")
    assert "prompt" in body or "messages" in body


def test_make_body_chat():
    body = mod.make_body("/v1/chat/completions", "hello")
    assert "messages" in body


def test_prompt_key():
    assert mod.prompt_key("/completion") == "prompt"
    assert mod.prompt_key("/v1/chat/completions") == "messages"
