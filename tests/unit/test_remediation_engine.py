"""Remediation decision logic and execution.

These tests pin down the behaviour that matters operationally: which actions a
given incident triggers, when the engine is allowed to act without a human, and
what happens when an integration is unavailable. An autonomy bug in this engine
quarantines a production device on a false positive, so the boundaries are
tested explicitly rather than assumed.
"""

import pytest

from src.automation.remediation.engine import RemediationAction, RemediationEngine


class FakeIseClient:
    """Stands in for Cisco ISE. Records calls so intent can be asserted."""

    def __init__(self, succeed: bool = True):
        self.succeed = succeed
        self.quarantined: list[tuple[str, str]] = []

    def quarantine_endpoint(self, mac_address: str, reason: str = "") -> bool:
        self.quarantined.append((mac_address, reason))
        return self.succeed


class FakeDlpClient:
    """Stands in for Symantec DLP."""

    def __init__(self, succeed: bool = True):
        self.succeed = succeed
        self.quarantined_files: list[str] = []

    def quarantine_file(self, incident_id: str) -> bool:
        self.quarantined_files.append(incident_id)
        return self.succeed


def actions_for(incident, **kwargs):
    return RemediationEngine().decide_remediation(incident, **kwargs)


def action_names(actions):
    return [a["action"] for a in actions]


class TestDecisionLogic:
    def test_data_exfiltration_isolates_the_device_and_the_files(self):
        actions = actions_for(
            {"type": "data_exfiltration", "severity": "high", "confidence": 0.95}
        )
        names = action_names(actions)
        assert RemediationAction.QUARANTINE_DEVICE.value in names
        assert RemediationAction.BLOCK_FILE.value in names

    def test_unauthorized_access_kills_the_session_before_blocking_the_ip(self):
        """Order matters: an active session survives an IP block."""
        actions = actions_for(
            {"type": "unauthorized_access", "severity": "high", "confidence": 0.9}
        )
        names = action_names(actions)
        assert names.index(RemediationAction.TERMINATE_SESSION.value) < names.index(
            RemediationAction.BLOCK_IP.value
        )

    def test_malware_only_quarantines(self):
        actions = actions_for(
            {"type": "malware_detected", "severity": "critical", "confidence": 0.99}
        )
        assert RemediationAction.QUARANTINE_DEVICE.value in action_names(actions)
        assert RemediationAction.BLOCK_FILE.value not in action_names(actions)

    def test_incident_type_matching_is_case_insensitive(self):
        upper = actions_for(
            {"type": "DATA_EXFILTRATION", "severity": "high", "confidence": 0.9}
        )
        lower = actions_for(
            {"type": "data_exfiltration", "severity": "high", "confidence": 0.9}
        )
        assert action_names(upper) == action_names(lower)

    @pytest.mark.parametrize("severity", ["high", "critical"])
    def test_severe_incidents_always_page_a_human(self, severity):
        actions = actions_for(
            {"type": "unknown_thing", "severity": severity, "confidence": 0.1}
        )
        assert RemediationAction.ALERT_SECURITY_TEAM.value in action_names(actions)

    @pytest.mark.parametrize("severity", ["low", "medium"])
    def test_minor_incidents_do_not_page_anyone(self, severity):
        actions = actions_for(
            {"type": "unknown_thing", "severity": severity, "confidence": 0.99}
        )
        assert RemediationAction.ALERT_SECURITY_TEAM.value not in action_names(actions)

    def test_an_unrecognised_low_severity_incident_produces_nothing(self):
        assert actions_for({"type": "something_new", "severity": "low", "confidence": 0.9}) == []

    def test_a_missing_incident_type_does_not_crash(self):
        assert actions_for({"severity": "low", "confidence": 0.5}) == []


class TestAutonomyBoundary:
    """Autonomy needs high confidence AND high severity. Either alone is not enough."""

    def test_high_confidence_and_high_severity_acts_alone(self):
        actions = actions_for(
            {"type": "malware", "severity": "critical", "confidence": 0.95}
        )
        quarantine = next(
            a for a in actions if a["action"] == RemediationAction.QUARANTINE_DEVICE.value
        )
        assert quarantine["autonomous"] is True

    def test_high_confidence_but_low_severity_waits_for_a_human(self):
        actions = actions_for(
            {"type": "malware", "severity": "low", "confidence": 0.99}
        )
        quarantine = next(
            a for a in actions if a["action"] == RemediationAction.QUARANTINE_DEVICE.value
        )
        assert quarantine["autonomous"] is False

    def test_high_severity_but_low_confidence_waits_for_a_human(self):
        actions = actions_for(
            {"type": "malware", "severity": "critical", "confidence": 0.4}
        )
        quarantine = next(
            a for a in actions if a["action"] == RemediationAction.QUARANTINE_DEVICE.value
        )
        assert quarantine["autonomous"] is False

    def test_the_threshold_is_inclusive_at_its_boundary(self):
        at = actions_for({"type": "malware", "severity": "high", "confidence": 0.80})
        below = actions_for({"type": "malware", "severity": "high", "confidence": 0.799})
        assert at[0]["autonomous"] is True
        assert below[0]["autonomous"] is False

    def test_the_threshold_can_be_tightened_per_call(self):
        actions = actions_for(
            {"type": "malware", "severity": "high", "confidence": 0.85},
            confidence_threshold=0.95,
        )
        assert actions[0]["autonomous"] is False

    def test_blocking_an_ip_needs_more_confidence_than_quarantining(self):
        """Blocking an IP can take out a shared NAT gateway, so it is held to a
        higher bar than isolating one endpoint."""
        actions = actions_for(
            {"type": "unauthorized_access", "severity": "high", "confidence": 0.82}
        )
        terminate = next(
            a for a in actions if a["action"] == RemediationAction.TERMINATE_SESSION.value
        )
        block_ip = next(
            a for a in actions if a["action"] == RemediationAction.BLOCK_IP.value
        )
        assert terminate["autonomous"] is True
        assert block_ip["autonomous"] is False

    def test_alerting_a_human_is_always_allowed(self):
        actions = actions_for(
            {"type": "malware", "severity": "critical", "confidence": 0.01}
        )
        alert = next(
            a for a in actions if a["action"] == RemediationAction.ALERT_SECURITY_TEAM.value
        )
        assert alert["autonomous"] is True
        assert alert["confidence"] == 1.0


class TestExecution:
    def test_quarantine_calls_ise_with_the_mac_and_a_reason(self):
        ise = FakeIseClient()
        engine = RemediationEngine(ise_client=ise)
        result = engine.execute_remediation(
            {"action": RemediationAction.QUARANTINE_DEVICE.value},
            {"mac_address": "00:11:22:33:44:55", "type": "malware"},
        )
        assert result["success"] is True
        assert ise.quarantined[0][0] == "00:11:22:33:44:55"
        assert "malware" in ise.quarantined[0][1]

    def test_quarantine_reports_failure_when_ise_refuses(self):
        engine = RemediationEngine(ise_client=FakeIseClient(succeed=False))
        result = engine.execute_remediation(
            {"action": RemediationAction.QUARANTINE_DEVICE.value},
            {"mac_address": "00:11:22:33:44:55"},
        )
        assert result["success"] is False

    def test_quarantine_degrades_gracefully_without_an_ise_client(self):
        """No integration configured must not look like a successful action."""
        result = RemediationEngine().execute_remediation(
            {"action": RemediationAction.QUARANTINE_DEVICE.value},
            {"mac_address": "00:11:22:33:44:55"},
        )
        assert result["success"] is False
        assert "ISE client not available" in result["message"]

    def test_quarantine_without_a_mac_address_fails_clearly(self):
        engine = RemediationEngine(ise_client=FakeIseClient())
        result = engine.execute_remediation(
            {"action": RemediationAction.QUARANTINE_DEVICE.value}, {"type": "malware"}
        )
        assert result["success"] is False
        assert "MAC" in result["message"]

    def test_blocking_a_file_calls_dlp_with_the_incident_id(self):
        dlp = FakeDlpClient()
        engine = RemediationEngine(dlp_client=dlp)
        result = engine.execute_remediation(
            {"action": RemediationAction.BLOCK_FILE.value},
            {"dlp_incident_id": "INC-4471"},
        )
        assert result["success"] is True
        assert dlp.quarantined_files == ["INC-4471"]

    def test_blocking_a_file_without_a_dlp_client_fails(self):
        result = RemediationEngine().execute_remediation(
            {"action": RemediationAction.BLOCK_FILE.value},
            {"dlp_incident_id": "INC-4471"},
        )
        assert result["success"] is False

    def test_an_unknown_action_is_reported_not_silently_ignored(self):
        result = RemediationEngine().execute_remediation(
            {"action": "launch_the_missiles"}, {}
        )
        assert result["success"] is False
        assert "Unknown action" in result["message"]

    def test_an_integration_that_raises_does_not_crash_the_engine(self):
        class Exploding:
            def quarantine_endpoint(self, *a, **k):
                raise ConnectionError("ISE unreachable")

        engine = RemediationEngine(ise_client=Exploding())
        result = engine.execute_remediation(
            {"action": RemediationAction.QUARANTINE_DEVICE.value},
            {"mac_address": "00:11:22:33:44:55"},
        )
        assert result["success"] is False
        assert "ISE unreachable" in result["message"]

    def test_every_execution_is_recorded_for_audit(self):
        """A security tool that acts without an audit trail is not deployable."""
        engine = RemediationEngine(ise_client=FakeIseClient())
        incident = {"mac_address": "00:11:22:33:44:55", "type": "malware"}
        engine.execute_remediation(
            {"action": RemediationAction.QUARANTINE_DEVICE.value}, incident
        )
        engine.execute_remediation(
            {"action": RemediationAction.ALERT_SECURITY_TEAM.value}, incident
        )

        assert len(engine.action_history) == 2
        assert engine.action_history[0]["incident"] == incident
        assert engine.action_history[0]["result"]["success"] is True


class TestEndToEnd:
    def test_a_confirmed_exfiltration_is_decided_and_executed(self):
        ise, dlp = FakeIseClient(), FakeDlpClient()
        engine = RemediationEngine(ise_client=ise, dlp_client=dlp)
        incident = {
            "type": "data_exfiltration",
            "severity": "critical",
            "confidence": 0.97,
            "mac_address": "00:11:22:33:44:55",
            "dlp_incident_id": "INC-9001",
        }

        actions = engine.decide_remediation(incident)
        results = [engine.execute_remediation(a, incident) for a in actions]

        assert all(a["autonomous"] for a in actions)
        assert all(r["success"] for r in results)
        assert ise.quarantined and dlp.quarantined_files
        assert len(engine.action_history) == len(actions)
