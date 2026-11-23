from pathlib import Path

from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.tools import tool
from pydantic import BaseModel

from vulnerability_agent.agent import VulnerabilityAgent
from vulnerability_agent.config import Settings
from vulnerability_agent.models import VulnerabilityReport
from vulnerability_agent.tools import get_epss_score


@tool
def fake_epss(cve_id: str) -> str:
    """Повернути тестову EPSS-відповідь."""
    return "{}"


class FakeRunnable:
    def __init__(self, responses):
        self.responses = list(responses)
        self.index = 0

    def invoke(self, messages):
        response = self.responses[min(self.index, len(self.responses) - 1)]
        self.index += 1
        if isinstance(response, Exception):
            raise response
        return response


class FakeLLM:
    def __init__(self, agent_responses, report=None):
        self.agent_runnable = FakeRunnable(agent_responses)
        self.report = report or VulnerabilityReport(answer="Тест завершено", confidence=1)

    def bind_tools(self, tools):
        return self.agent_runnable

    def with_structured_output(self, schema: BaseModel):
        return FakeRunnable([self.report])


class FailingFormatterLLM(FakeLLM):
    def with_structured_output(self, schema: BaseModel):
        return FakeRunnable([ValueError("provider returned plain text")])


def _settings(**overrides):
    values = {"openai_api_key": "test", "max_steps": 10, "max_repeats": 3}
    values.update(overrides)
    return Settings(**values)


def test_graph_finishes_with_structured_output(tmp_path: Path):
    llm = FakeLLM([AIMessage(content="Достатньо фактів")])
    result = VulnerabilityAgent(_settings(), llm=llm).run("Тест", tmp_path)
    assert result.report.answer == "Тест завершено"
    assert result.stop_reason == "completed"
    assert Path(result.trajectory_path).exists()


def test_max_steps_stops_before_tools(tmp_path: Path):
    call = {"name": "get_epss_score", "args": {"cve_id": "CVE-2021-44228"}, "id": "1"}
    llm = FakeLLM([AIMessage(content="", tool_calls=[call])])
    result = VulnerabilityAgent(_settings(max_steps=1), tools=[get_epss_score], llm=llm).run("Тест", tmp_path)
    assert result.stop_reason == "max_steps"
    assert result.tool_calls == []


def test_loop_detector_stops_repeated_calls(tmp_path: Path):
    call = {"name": "fake_epss", "args": {"cve_id": "CVE-2021-44228"}, "id": "same"}
    llm = FakeLLM([AIMessage(content="", tool_calls=[call])])
    result = VulnerabilityAgent(
        _settings(max_repeats=3), tools=[fake_epss], llm=llm
    ).run("Повторюй", tmp_path)
    assert result.stop_reason == "loop_detected"


def test_plain_text_formatter_uses_deterministic_fallback(tmp_path: Path):
    tool_call = {
        "name": "fake_epss",
        "args": {"cve_id": "CVE-2021-44228"},
        "id": "epss-1",
    }
    llm = FailingFormatterLLM(
        [
            AIMessage(content="", tool_calls=[tool_call]),
            AIMessage(content="Фактична текстова відповідь агента"),
        ]
    )
    result = VulnerabilityAgent(_settings(), tools=[fake_epss], llm=llm).run("Тест", tmp_path)
    assert result.report.answer == "Фактична текстова відповідь агента"
    assert result.report.confidence == 0.8
    assert "зібрано з результатів tools" in result.report.limitations[0]
    assert all(item != "Stop reason:" for item in result.report.limitations)


def test_fallback_calculates_severity_from_cvss_vector():
    llm = FakeLLM([AIMessage(content="unused")])
    agent = VulnerabilityAgent(_settings(), llm=llm)
    state = {
        "messages": [
            ToolMessage(
                name="get_vulnerability_details",
                tool_call_id="details-1",
                content=(
                    '{"source":"https://api.osv.dev/v1/vulns/CVE-2021-44228",'
                    '"data":{"severity":[{"type":"CVSS_V3",'
                    '"score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}]}}'
                ),
            ),
            AIMessage(content="Критична вразливість"),
        ]
    }
    report = agent._fallback_report(state, ValueError("plain text"))
    assert report.severity == "critical"


def test_cvss31_log4shell_base_score():
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    assert VulnerabilityAgent._cvss3_base_score(vector) == 10.0
