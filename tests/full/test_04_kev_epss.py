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
        ["kev", "CVE-2024-21887", ("report--96b95278-dcae-51fd-8407-dfe78e4e2b68",)],
        [
            "kev",
            "CVE-2024-3393",
            (
                "report--1c0c4245-72cb-5379-b1bb-4a3d22683636",  # vulncheck kev
                "report--9f381c8b-2df2-5da3-af0f-0f8dcc197ea3",  # cisa kev
            ),
        ],
        ["kev", "CVE-2023-7028", ("report--f212926e-9612-549c-b346-4cd6766a6480",)],
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
            float(obj["x_epss"][-1]["epss"]) >= min_score
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
        ["kev", "name_descending"],
        ["epss", "name_descending"],
        ["kev", "name_ascending"],
        ["epss", "name_ascending"],
        ["epss", "epss_score_ascending"],
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
            return float(obj["x_epss"][-1]["epss"])
        return obj[param]

    reversed = direction == "descending"
    assert is_sorted(
        resp_data["objects"], key=key_fn, reverse=reversed
    ), "object not sorted"

@pytest.mark.parametrize(
    "sort_param",
    [
        "name_ascending",
        "name_descending",
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
    ['cve_ids', 'expected_ids'],
    [
        [None, {'exploit--74a0d3ec-2235-5d3a-b081-4e277892a7e1', 'exploit--42d4dee3-2645-581a-89b2-73b0245776c8', 'exploit--a12cf1f9-701c-56e5-b63b-b96aa1839b48', 'exploit--7b8f29c8-bf2e-5c66-9ff7-147b04e47802'}],
        [['CVE-2024-3393', 'CVE-2024-11972'], {'exploit--74a0d3ec-2235-5d3a-b081-4e277892a7e1', 'exploit--42d4dee3-2645-581a-89b2-73b0245776c8', 'exploit--a12cf1f9-701c-56e5-b63b-b96aa1839b48', 'exploit--7b8f29c8-bf2e-5c66-9ff7-147b04e47802'}],
        [['CVE-2024-3393'], {'exploit--74a0d3ec-2235-5d3a-b081-4e277892a7e1'}],
        [['CVE-2024-11972'], {'exploit--7b8f29c8-bf2e-5c66-9ff7-147b04e47802', 'exploit--a12cf1f9-701c-56e5-b63b-b96aa1839b48', 'exploit--42d4dee3-2645-581a-89b2-73b0245776c8'}],
    ]
)
def test_list_exploits(client, cve_ids, expected_ids):
    url = f"/api/v1/kev/exploits/"
    resp = client.get(url, query_params=dict(cve_id=','.join(cve_ids or [])))
    resp_data = resp.json()
    print({obj["id"] for obj in resp_data["objects"]})
    print({obj["name"] for obj in resp_data["objects"]})
    assert {obj["id"] for obj in resp_data["objects"]} == set(expected_ids)