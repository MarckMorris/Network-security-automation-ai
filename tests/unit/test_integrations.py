"""Cisco ISE and Symantec DLP clients, against a mocked HTTP layer.

Both vendors are licensed products that cannot be spun up in CI, so the contract
is pinned at the HTTP boundary with `responses`. That still catches the failures
that actually occur in the field: wrong URL, missing auth header, and an
unreachable appliance being reported as success.
"""

from __future__ import annotations

import pytest
import requests
import responses

from src.integrations.cisco_ise.client import CiscoISEClient
from src.integrations.symantec_dlp.client import SymantecDLPClient

ISE_URL = "https://ise.example.com:9060"
DLP_URL = "https://dlp.example.com"
DLP_LOGIN = f"{DLP_URL}/ProtectManager/webservices/v2/authentication/login"

ENDPOINT_PAYLOAD = {
    "SearchResult": {
        "total": 1,
        "resources": [{"id": "ep-123", "name": "00:11:22:33:44:55"}],
    }
}
ENDPOINT_DETAIL = {"ERSEndPoint": {"id": "ep-123", "mac": "00:11:22:33:44:55"}}


@pytest.fixture
def ise():
    return CiscoISEClient(ISE_URL, "admin", "secret", verify_ssl=False)


@pytest.fixture
def dlp():
    with responses.RequestsMock() as mock:
        mock.add(responses.POST, DLP_LOGIN, json={"token": "tok-abc"}, status=200)
        yield SymantecDLPClient(DLP_URL, "admin", "secret", verify_ssl=False)


class TestIseClientConstruction:
    def test_trailing_slash_is_normalised(self):
        assert CiscoISEClient(ISE_URL + "/", "a", "b").base_url == ISE_URL

    def test_basic_auth_is_configured(self, ise):
        assert ise.session.auth is not None

    def test_json_content_type_is_set(self, ise):
        assert ise.session.headers["Content-Type"] == "application/json"


class TestIseEndpointLookup:
    @responses.activate
    def test_finds_an_endpoint_by_mac(self, ise):
        responses.add(
            responses.GET,
            f"{ISE_URL}/ers/config/endpoint",
            json=ENDPOINT_PAYLOAD,
            status=200,
        )
        responses.add(
            responses.GET,
            f"{ISE_URL}/ers/config/endpoint/ep-123",
            json=ENDPOINT_DETAIL,
            status=200,
        )
        assert ise.get_endpoint("00:11:22:33:44:55") is not None

    @responses.activate
    def test_queries_with_a_mac_equality_filter(self, ise):
        """ISE returns every endpoint if the filter is malformed, which would
        quarantine the wrong device."""
        responses.add(
            responses.GET,
            f"{ISE_URL}/ers/config/endpoint",
            json={"SearchResult": {"total": 0, "resources": []}},
            status=200,
        )
        ise.get_endpoint("00:11:22:33:44:55")
        assert "mac.EQ.00%3A11%3A22%3A33%3A44%3A55" in responses.calls[0].request.url

    @responses.activate
    def test_an_unknown_mac_returns_none(self, ise):
        responses.add(
            responses.GET,
            f"{ISE_URL}/ers/config/endpoint",
            json={"SearchResult": {"total": 0, "resources": []}},
            status=200,
        )
        assert ise.get_endpoint("00:00:00:00:00:00") is None

    @responses.activate
    def test_a_server_error_returns_none_rather_than_raising(self, ise):
        responses.add(
            responses.GET, f"{ISE_URL}/ers/config/endpoint", status=500
        )
        assert ise.get_endpoint("00:11:22:33:44:55") is None

    @responses.activate
    def test_an_unreachable_appliance_returns_none(self, ise):
        responses.add(
            responses.GET,
            f"{ISE_URL}/ers/config/endpoint",
            body=requests.exceptions.ConnectionError("no route to host"),
        )
        assert ise.get_endpoint("00:11:22:33:44:55") is None


class TestIseQuarantine:
    @responses.activate
    def test_quarantine_puts_the_endpoint_into_a_group(self, ise):
        responses.add(
            responses.GET, f"{ISE_URL}/ers/config/endpoint", json=ENDPOINT_PAYLOAD
        )
        responses.add(
            responses.GET,
            f"{ISE_URL}/ers/config/endpoint/ep-123",
            json=ENDPOINT_DETAIL,
        )
        responses.add(
            responses.PUT, f"{ISE_URL}/ers/config/endpoint/ep-123", json={}, status=200
        )

        assert ise.quarantine_endpoint("00:11:22:33:44:55", reason="malware") is True
        put = [c for c in responses.calls if c.request.method == "PUT"][0]
        assert "malware" in put.request.body.decode()

    @responses.activate
    def test_an_unknown_endpoint_is_never_reported_as_quarantined(self, ise):
        """The most dangerous false positive in the whole system."""
        responses.add(
            responses.GET,
            f"{ISE_URL}/ers/config/endpoint",
            json={"SearchResult": {"total": 0, "resources": []}},
        )
        assert ise.quarantine_endpoint("00:00:00:00:00:00") is False

    @responses.activate
    def test_a_rejected_update_returns_false(self, ise):
        responses.add(
            responses.GET, f"{ISE_URL}/ers/config/endpoint", json=ENDPOINT_PAYLOAD
        )
        responses.add(
            responses.GET,
            f"{ISE_URL}/ers/config/endpoint/ep-123",
            json=ENDPOINT_DETAIL,
        )
        responses.add(
            responses.PUT, f"{ISE_URL}/ers/config/endpoint/ep-123", status=403
        )
        assert ise.quarantine_endpoint("00:11:22:33:44:55") is False


class TestDlpClient:
    def test_authenticates_on_construction_and_stores_the_token(self, dlp):
        assert dlp.token == "tok-abc"

    def test_the_bearer_token_is_attached_to_the_session(self, dlp):
        assert dlp.session.headers["Authorization"] == "Bearer tok-abc"

    @responses.activate
    def test_bad_credentials_fail_fast_instead_of_returning_a_half_alive_client(self):
        """Better to refuse to construct than to hand back a client whose every
        later call will 401 somewhere deep in a remediation path."""
        responses.add(responses.POST, DLP_LOGIN, status=401)
        with pytest.raises(requests.exceptions.HTTPError):
            SymantecDLPClient(DLP_URL, "admin", "wrong", verify_ssl=False)

    @responses.activate
    def test_incidents_are_fetched_from_the_v2_endpoint(self, dlp):
        responses.add(
            responses.GET,
            f"{DLP_URL}/ProtectManager/webservices/v2/incidents",
            json={"incidents": [{"incidentId": 1}, {"incidentId": 2}]},
            status=200,
        )
        assert len(dlp.get_incidents()) == 2

    @responses.activate
    def test_an_error_returns_an_empty_list_not_a_crash(self, dlp):
        responses.add(
            responses.GET,
            f"{DLP_URL}/ProtectManager/webservices/v2/incidents",
            status=500,
        )
        assert dlp.get_incidents() == []

    @responses.activate
    def test_incident_details_return_none_when_missing(self, dlp):
        responses.add(
            responses.GET,
            f"{DLP_URL}/ProtectManager/webservices/v2/incidents/404",
            status=404,
        )
        assert dlp.get_incident_details(404) is None
