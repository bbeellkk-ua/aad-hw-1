"""Live test cases і збір результатів домашньої роботи."""

import json
from pathlib import Path

from vulnerability_agent.agent import VulnerabilityAgent
from vulnerability_agent.config import Settings


TEST_CASES = [
    {
        "id": "TC-001", "complexity": "simple",
        "query": "Знайди відомі вразливості Django 3.2.1 у PyPI.",
        "expected": "OSV-пошук конкретної версії пакета.",
    },
    {
        "id": "TC-002", "complexity": "medium",
        "query": "Надай деталі CVE-2021-44228 і поясни вектор атаки.",
        "expected": "Деталі CVE з посиланнями на джерела.",
    },
    {
        "id": "TC-003", "complexity": "complex",
        "query": "Досліди CVE-2021-44228: severity, CISA KEV, EPSS та мітігації.",
        "expected": "Агрегація details, KEV та EPSS із мітігаціями.",
    },
    {
        "id": "TC-004", "complexity": "validation",
        "query": "Перевір у CISA KEV identifier CVE-невідомо.",
        "expected": "Tool validation error або уточнення коректного CVE.",
    },
]


def main() -> None:
    settings = Settings.from_env()
    agent = VulnerabilityAgent(settings)
    results = []
    for case in TEST_CASES:
        try:
            run = agent.run(case["query"], Path("artifacts/trajectories"))
            results.append(
                {
                    "test_id": case["id"], "query": case["query"],
                    "expected": case["expected"], "actual": run.report.model_dump(),
                    "status": "success" if run.stop_reason == "completed" else "partial",
                    "steps": run.steps, "tool_calls": run.tool_calls,
                    "elapsed_ms": run.elapsed_ms, "complexity": case["complexity"],
                    "max_steps_reached": run.stop_reason == "max_steps",
                    "timeout_reached": run.stop_reason == "timeout",
                    "stop_reason": run.stop_reason,
                }
            )
        except Exception as exc:
            results.append(
                {"test_id": case["id"], "query": case["query"], "expected": case["expected"],
                 "actual": "Error: %s" % exc, "status": "error", "steps": -1,
                 "tool_calls": [], "elapsed_ms": 0, "complexity": case["complexity"]}
            )
    Path("test_results.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print("Збережено test_results.json: %d test cases" % len(results))


if __name__ == "__main__":
    main()
