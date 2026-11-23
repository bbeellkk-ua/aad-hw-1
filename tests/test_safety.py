import time

import pytest

from vulnerability_agent.safety import AgentTimeoutError, Deadline, LoopDetector


def test_loop_detector_only_stops_consecutive_equal_calls():
    detector = LoopDetector(max_repeats=3)
    assert detector.check("epss", {"cve": "CVE-2021-44228"}) is False
    assert detector.check("kev", {"cve": "CVE-2021-44228"}) is False
    assert detector.check("epss", {"cve": "CVE-2021-44228"}) is False
    assert detector.check("epss", {"cve": "CVE-2021-44228"}) is False
    assert detector.check("epss", {"cve": "CVE-2021-44228"}) is True


def test_deadline_raises_after_timeout():
    deadline = Deadline(0.01)
    time.sleep(0.02)
    with pytest.raises(AgentTimeoutError, match="тайм-аут"):
        deadline.check()
