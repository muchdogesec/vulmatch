import random
import pytest

from tests.full.utils import is_sorted


@pytest.mark.parametrize("path", ["kev", "epss"])
def test_list_obvjects(client, path):
    url = f"/api/v1/{path}/objects/"
    resp = client.get(url)
    resp_data = resp.json()
    assert all(
        cve["type"] == "report" for cve in resp_data["objects"]
    ), "response.objects[*].type must always be report"
    assert (
        len({cpe["id"] for cpe in resp_data["objects"]})
        == resp_data["page_results_count"]
    ), "response contains duplicates"
    for obj in resp_data["objects"]:
        assert obj["labels"][0] == path


@pytest.mark.parametrize(
    ["path", "cve_id", "expected_stix_ids"],
    [
        [
            "kev",
            "CVE-2024-21887",
            (
                "report--96b95278-dcae-51fd-8407-dfe78e4e2b68",
                "report--22a2712f-078a-5dde-a56e-851b3e9e6342",
            ),
        ],
        [
            "kev",
            "CVE-2024-3393",
            (
                "report--9554b1d8-deb9-5f17-966a-4f998dd5bf46",  # vulncheck kev
                "report--9f381c8b-2df2-5da3-af0f-0f8dcc197ea3",  # cisa kev
            ),
        ],
        [
            "kev",
            "CVE-2023-7028",
            (
                "report--f212926e-9612-549c-b346-4cd6766a6480",
                "report--c15f1fa2-8487-5284-8ef7-eeacc1dd99b3",
            ),
        ],
        ["epss", "CVE-2024-3393", ("report--aba63890-dc05-5555-a139-d95849d268b8",)],
        ["epss", "CVE-2024-21887", ("report--5e1456ce-5fe2-55b5-8b1e-60a41b34be84",)],
        ["epss", "CVE-2023-7028", ("report--fc6e3286-cff0-5f27-83b7-02f9f6fe25be",)],
    ],
)
def test_kev_or_epss_retrieve(client, path, cve_id, expected_stix_ids):
    url = f"/api/v1/{path}/objects/"
    resp = client.get(url, query_params=dict(cve_id=cve_id))
    resp_data = resp.json()
    assert {obj["id"] for obj in resp_data["objects"]} == set(expected_stix_ids)


@pytest.mark.parametrize("min_score", [random.randint(0, 110) / 10 for i in range(15)])
def test_epss_min_score(client, min_score):
    url = f"/api/v1/epss/objects/"
    resp = client.get(url, query_params=dict(epss_min_score=min_score))
    resp_data = resp.json()
    assert all(
        report["type"] == "report" and report["labels"][0] == "epss"
        for report in resp_data["objects"]
    ), "response.objects[*].type must always be report"
    assert (
        len({cpe["id"] for cpe in resp_data["objects"]})
        == resp_data["page_results_count"]
    ), "response contains duplicates"
    for obj in resp_data["objects"]:
        assert (
            float(obj["x_epss"][0]["epss"]) >= min_score
        ), "score must be greater than epss_min_score param"


@pytest.mark.parametrize(
    ["path", "sort_param"],
    [
        ["kev", "modified_descending"],
        ["epss", "modified_descending"],
        ["kev", "modified_ascending"],
        ["epss", "modified_ascending"],
        ["kev", "created_descending"],
        ["epss", "created_descending"],
        ["kev", "created_ascending"],
        ["epss", "created_ascending"],
        ["epss", "epss_score_descending"],
    ],
)
def test_sort(client, path, sort_param: str):
    url = f"/api/v1/{path}/objects/"
    resp = client.get(url, query_params=dict(sort=sort_param))
    resp_data = resp.json()
    assert all(
        report["type"] == "report" and report["labels"][0] == path
        for report in resp_data["objects"]
    ), "response.objects[*].type must always be report"
    assert (
        len({cpe["id"] for cpe in resp_data["objects"]})
        == resp_data["page_results_count"]
    ), "response contains duplicates"
    param, _, direction = sort_param.rpartition("_")

    def key_fn(obj):
        if param == "epss_score":
            return float(obj["x_epss"][0]["epss"])
        return obj[param]

    reversed = direction == "descending"
    assert is_sorted(
        resp_data["objects"], key=key_fn, reverse=reversed
    ), "object not sorted"


@pytest.mark.parametrize(
    "sort_param",
    [
        "modified_ascending",
        "modified_descending",
        "created_descending",
        "created_ascending",
    ],
)
def test_sort_exploits(client, sort_param: str):
    url = f"/api/v1/kev/exploits/"
    resp = client.get(url, query_params=dict(sort=sort_param))
    resp_data = resp.json()
    assert (
        len({cpe["id"] for cpe in resp_data["objects"]})
        == resp_data["page_results_count"]
    ), "response contains duplicates"
    param, _, direction = sort_param.rpartition("_")

    def key_fn(obj):
        return obj[param]

    reversed = direction == "descending"
    assert is_sorted(
        resp_data["objects"], key=key_fn, reverse=reversed
    ), "object not sorted"


@pytest.mark.parametrize(
    ["cve_ids", "expected_ids"],
    [
        [
            ["CVE-2024-3393", "CVE-2024-11972"],
            {
                "exploit--74a0d3ec-2235-5d3a-b081-4e277892a7e1",
                "exploit--42d4dee3-2645-581a-89b2-73b0245776c8",
                "exploit--a12cf1f9-701c-56e5-b63b-b96aa1839b48",
                "exploit--7b8f29c8-bf2e-5c66-9ff7-147b04e47802",
            },
        ],
        [["CVE-2024-3393"], {"exploit--74a0d3ec-2235-5d3a-b081-4e277892a7e1"}],
        [
            ["CVE-2024-11972"],
            {
                "exploit--7b8f29c8-bf2e-5c66-9ff7-147b04e47802",
                "exploit--a12cf1f9-701c-56e5-b63b-b96aa1839b48",
                "exploit--42d4dee3-2645-581a-89b2-73b0245776c8",
            },
        ],
    ],
)
def test_list_exploits(client, cve_ids, expected_ids):
    url = f"/api/v1/kev/exploits/"
    resp = client.get(url, query_params=dict(cve_id=",".join(cve_ids or [])))
    resp_data = resp.json()
    print({obj["id"] for obj in resp_data["objects"]})
    print({obj["name"] for obj in resp_data["objects"]})
    assert {obj["id"] for obj in resp_data["objects"]} == set(expected_ids)


def test_epss_retrieve(client):
    cve_id = "CVE-2023-7028"
    url = f"/api/v1/epss/objects/{cve_id}/"
    resp = client.get(url)
    resp_data = resp.json()
    epss_obj = resp_data["objects"][0]
    assert epss_obj == {
        "created": "2024-01-12T14:15:49.420Z",
        "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        "extensions": {
            "extension-definition--efd26d23-d37d-5cf2-ac95-a101e46ce11d": {
                "extension_type": "toplevel-property-extension"
            }
        },
        "external_references": [
            {
                "source_name": "cve",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-7028",
                "external_id": "CVE-2023-7028",
            },
            {"source_name": "arango_cve_processor", "external_id": "cve-epss"},
        ],
        "id": "report--fc6e3286-cff0-5f27-83b7-02f9f6fe25be",
        "labels": ["epss"],
        "modified": "2025-09-06T00:00:00.000Z",
        "name": "EPSS Scores: CVE-2023-7028",
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--152ecfe1-5015-522b-97e4-86b60c57036d",
        ],
        "object_refs": ["vulnerability--8ca41376-d05c-5f2c-9a8a-9f7e62a5f81f"],
        "published": "2024-01-12T14:15:49.42Z",
        "spec_version": "2.1",
        "type": "report",
        "x_epss": [
            {"date": "2025-09-06", "epss": 0.93864, "percentile": 0.99862},
            {"date": "2025-09-05", "epss": 0.93864, "percentile": 0.99862},
            {"date": "2025-09-04", "epss": 0.93864, "percentile": 0.99862},
            {"date": "2025-09-03", "epss": 0.93845, "percentile": 0.99863},
            {"date": "2025-09-02", "epss": 0.93845, "percentile": 0.99863},
            {"date": "2025-09-01", "epss": 0.93845, "percentile": 0.99864},
        ],
    }
