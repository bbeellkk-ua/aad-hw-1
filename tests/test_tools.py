import json

import pytest
from pydantic import ValidationError

from vulnerability_agent.tools import (
    CisaKevInput,
    EpssInput,
    PackageVulnerabilityInput,
    VulnerabilityDetailsInput,
    get_epss_score,
    search_package_vulnerabilities,
)


@pytest.mark.parametrize(
    "model,kwargs",
    [
        (PackageVulnerabilityInput, {"ecosystem": "PyPI", "package_name": "", "version": "1.0"}),
        (VulnerabilityDetailsInput, {"vulnerability_id": "not-a-cve"}),
        (CisaKevInput, {"cve_id": "GHSA-test-test-test"}),
        (EpssInput, {"cve_id": "CVE-2024-X"}),
    ],
)
def test_tool_schemas_reject_invalid_values(model, kwargs):
    with pytest.raises(ValidationError):
        model(**kwargs)


def test_search_package_vulnerabilities(httpx_mock):
    httpx_mock.add_response(
        method="POST", url="https://api.osv.dev/v1/query",
        json={"vulns": [{"id": "GHSA-test", "aliases": ["CVE-2024-1234"], "summary": "Test"}]},
    )
    result = json.loads(search_package_vulnerabilities.invoke(
        {"ecosystem": "PyPI", "package_name": "demo", "version": "1.0"}
    ))
    assert result["ok"] is True
    assert result["data"]["count"] == 1


def test_epss_score(httpx_mock):
    httpx_mock.add_response(
        method="GET", url="https://api.first.org/data/v1/epss?cve=CVE-2021-44228",
        json={"data": [{"cve": "CVE-2021-44228", "epss": "0.9", "percentile": "0.99"}]},
    )
    result = json.loads(get_epss_score.invoke({"cve_id": "CVE-2021-44228"}))
    assert result["data"]["epss"] == "0.9"
