from datetime import date
from unittest.mock import patch

import pytest
from tests.utils import Transport
from vulmatch.server.statistics import StatisticsHelper


@pytest.fixture
def patched_helper():
    helper = StatisticsHelper()
    helper.now = date(2025, 1, 1)
    with patch("vulmatch.server.statistics.StatisticsHelper") as mock_helper:
        mock_helper.return_value = helper
        yield helper


def test_statistics(client, api_schema, patched_helper):
    resp = client.get("/api/v1/statistics/")
    assert resp.status_code == 200
    data = resp.json()

    api_schema["/api/v1/statistics/"]["GET"].validate_response(
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
    assert data.pop("epss")


def test_attack_stats(client, api_schema, patched_helper):
    resp = client.get("/api/v1/attack/statistics/")
    assert resp.status_code == 200
    data = resp.json()

    api_schema["/api/v1/attack/statistics/"]["GET"].validate_response(
        Transport.get_st_response(resp)
    )
    assert data[0] == {
        "attack_id": "T1556",
        "total_cve_count": 23,
        "by_year": [{"year": "2024", "cve_count": 23}],
    }
    assert len(data) >= 93


def test_cwe_stats(client, api_schema, patched_helper):
    resp = client.get("/api/v1/cwe/statistics/")
    assert resp.status_code == 200
    data = resp.json()

    api_schema["/api/v1/cwe/statistics/"]["GET"].validate_response(
        Transport.get_st_response(resp)
    )
    assert data[0] == {
        "cwe_id": "CWE-476",
        "total_cve_count": 64,
        "by_year": [{"year": "2024", "cve_count": 64}],
    }
    assert len(data) >= 100


def test_kev_stats(client, api_schema, patched_helper):
    resp = client.get("/api/v1/kev/statistics/")
    assert resp.status_code == 200
    data = resp.json()

    api_schema["/api/v1/kev/statistics/"]["GET"].validate_response(
        Transport.get_st_response(resp)
    )
    print(data)
    assert data == {
        "created_since": {"d1": 4, "d7": 5, "d30": 6, "d365": 10},
        "by_year": [{"year": "2025", "count": 5}, {"year": "2024", "count": 11}],
    }


def test_epss_stats(client, api_schema, patched_helper):
    resp = client.get("/api/v1/epss/statistics/")
    assert resp.status_code == 200
    data = resp.json()

    api_schema["/api/v1/epss/statistics/"]["GET"].validate_response(
        Transport.get_st_response(resp)
    )
    print(data)
    assert data == [
        {"range_group": "undefined", "count": 3},
        {"range_group": "0.0 -  0.1", "count": 552},
        {"range_group": "0.2 -  0.3", "count": 3},
        {"range_group": "0.3 -  0.4", "count": 1},
        {"range_group": "0.4 -  0.5", "count": 1},
        {"range_group": "0.6 -  0.7", "count": 1},
        {"range_group": "0.7 -  0.8", "count": 1},
        {"range_group": "0.8 -  0.9", "count": 1},
        {"range_group": "0.9 -  1.0", "count": 4},
    ]


def test_cve_stats(client, api_schema, patched_helper):
    resp = client.get("/api/v1/cve/statistics/")
    assert resp.status_code == 200
    data = resp.json()

    api_schema["/api/v1/cve/statistics/"]["GET"].validate_response(
        Transport.get_st_response(resp)
    )
    print(data)
    assert data == {
        "total_count": 567,
        "modified_since": {"d1": 412, "d7": 484, "d30": 485, "d365": 567},
        "created_since": {"d1": 103, "d7": 438, "d30": 438, "d365": 567},
        "by_year": [{"year": "2024", "count": 567}],
        "cvss_v2": [
            {"range_group": "undefined", "count": 512},
            {"range_group": "2.7 -  2.8", "count": 2},
            {"range_group": "3.3 -  3.4", "count": 2},
            {"range_group": "4.0 -  4.1", "count": 15},
            {"range_group": "5.0 -  5.1", "count": 7},
            {"range_group": "5.2 -  5.3", "count": 2},
            {"range_group": "5.8 -  5.9", "count": 1},
            {"range_group": "6.5 -  6.6", "count": 19},
            {"range_group": "7.5 -  7.6", "count": 7},
        ],
        "cvss_v3": [
            {"range_group": "undefined", "count": 64},
            {"range_group": "2.4 -  2.5", "count": 1},
            {"range_group": "3.3 -  3.4", "count": 1},
            {"range_group": "3.5 -  3.6", "count": 3},
            {"range_group": "4.0 -  4.1", "count": 1},
            {"range_group": "4.3 -  4.4", "count": 16},
            {"range_group": "4.6 -  4.7", "count": 2},
            {"range_group": "4.7 -  4.8", "count": 6},
            {"range_group": "4.8 -  4.9", "count": 7},
            {"range_group": "4.9 -  5.0", "count": 1},
            {"range_group": "5.2 -  5.3", "count": 2},
            {"range_group": "5.3 -  5.4", "count": 22},
            {"range_group": "5.4 -  5.5", "count": 23},
            {"range_group": "5.5 -  5.6", "count": 120},
            {"range_group": "5.9 -  6.0", "count": 5},
            {"range_group": "6.0 -  6.1", "count": 1},
            {"range_group": "6.1 -  6.2", "count": 13},
            {"range_group": "6.3 -  6.4", "count": 4},
            {"range_group": "6.4 -  6.5", "count": 1},
            {"range_group": "6.5 -  6.6", "count": 23},
            {"range_group": "6.8 -  6.9", "count": 2},
            {"range_group": "7.0 -  7.1", "count": 5},
            {"range_group": "7.1 -  7.2", "count": 12},
            {"range_group": "7.2 -  7.3", "count": 3},
            {"range_group": "7.3 -  7.4", "count": 3},
            {"range_group": "7.4 -  7.5", "count": 1},
            {"range_group": "7.5 -  7.6", "count": 39},
            {"range_group": "7.6 -  7.7", "count": 2},
            {"range_group": "7.8 -  7.9", "count": 85},
            {"range_group": "8.0 -  8.1", "count": 1},
            {"range_group": "8.1 -  8.2", "count": 2},
            {"range_group": "8.2 -  8.3", "count": 2},
            {"range_group": "8.3 -  8.4", "count": 1},
            {"range_group": "8.5 -  8.6", "count": 2},
            {"range_group": "8.6 -  8.7", "count": 1},
            {"range_group": "8.8 -  8.9", "count": 26},
            {"range_group": "9.1 -  9.2", "count": 1},
            {"range_group": "9.3 -  9.4", "count": 3},
            {"range_group": "9.4 -  9.5", "count": 1},
            {"range_group": "9.6 -  9.7", "count": 2},
            {"range_group": "9.8 -  9.9", "count": 55},
            {"range_group": "10.0 -  10.1", "count": 2},
        ],
        "cvss_v4": [
            {"range_group": "undefined", "count": 526},
            {"range_group": "2.1 -  2.2", "count": 1},
            {"range_group": "5.1 -  5.2", "count": 4},
            {"range_group": "5.3 -  5.4", "count": 20},
            {"range_group": "6.9 -  7.0", "count": 12},
            {"range_group": "8.7 -  8.8", "count": 2},
            {"range_group": "9.3 -  9.4", "count": 2},
        ],
    }
