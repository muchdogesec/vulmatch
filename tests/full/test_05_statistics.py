from datetime import date
from unittest.mock import patch
from tests.utils import Transport
from vulmatch.server.statistics import StatisticsHelper


def test_statistics(client, api_schema):
    helper = StatisticsHelper()
    helper.now = date(2025, 1, 1)
    with patch("vulmatch.server.statistics.StatisticsHelper") as mock_helper:
        mock_helper.return_value = helper
        resp = client.get("/api/statistics/")
    assert resp.status_code == 200
    data = resp.json()

    api_schema["/api/statistics/"]["GET"].validate_response(
        Transport.get_st_response(resp)
    )
    assert data["summary"] == {
        "generated_on": "2025-01-01",
        "latest": {
            "cve": "CVE-2024-56803",
            "created_at": "2024-12-31T23:15:41.553Z",
        },
        "earliest": {
            "cve": "CVE-2024-0443",
            "created_at": "2024-01-12T00:15:45.230Z",
        },
    }
    assert data.pop("cwes")
    assert data.pop("attacks")
