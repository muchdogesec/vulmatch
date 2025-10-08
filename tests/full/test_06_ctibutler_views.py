import random
import pytest


@pytest.mark.parametrize(
    "path",
    [
        "attack/objects",
        "capec/objects",
        "cwe/objects",
        "kev/objects",
        "cve/objects",
        "kev/exploits",
    ],
)
@pytest.mark.parametrize(
    "page,page_size",
    [
        (random.randint(1, 10), random.choice([None, 13, 50, 105, 1000]))
        for _ in range(10)
    ],
)
def test_paging_generic(client, settings, path, page, page_size):
    url = f"/api/v1/{path}/"
    params = dict(page=page, page_size=page_size)
    if not page_size:
        del params["page_size"]
    resp = client.get(url, query_params=params)
    resp_data = resp.json()
    assert resp_data["page_number"] == page
    if page_size:
        assert resp_data["page_size"] == min(settings.MAXIMUM_PAGE_SIZE, page_size)
    assert resp_data["total_results_count"] >= resp_data["page_results_count"]
    assert resp_data["page_results_count"] <= resp_data["page_size"]


@pytest.mark.parametrize(
    "path,path_id,stix_id",
    [
        ["cwe", "CWE-24", "weakness--0021e0ca-b8bf-5625-b106-d35c48f66fea"],
        ["capec", "CAPEC-87", "attack-pattern--00268a75-3243-477d-9166-8c78fddf6df6"],
        ["attack", "T1557", "attack-pattern--035bb001-ab69-4a0b-9f6c-2de8b09e1b9d"],
        ##
        [
            "cwe",
            "weakness--0021e0ca-b8bf-5625-b106-d35c48f66fea",
            "weakness--0021e0ca-b8bf-5625-b106-d35c48f66fea",
        ],
        [
            "capec",
            "attack-pattern--00268a75-3243-477d-9166-8c78fddf6df6",
            "attack-pattern--00268a75-3243-477d-9166-8c78fddf6df6",
        ],
        ## bad case
        ["cwe", "CwE-24", "weakness--0021e0ca-b8bf-5625-b106-d35c48f66fea"],
        ["capec", "CapEC-87", "attack-pattern--00268a75-3243-477d-9166-8c78fddf6df6"],
        ["attack", "t1557", "attack-pattern--035bb001-ab69-4a0b-9f6c-2de8b09e1b9d"],
    ],
)
def test_retrieve(client, path, path_id, stix_id):
    resp = client.get(f"/api/v1/{path}/objects/{path_id}/")
    assert resp.status_code == 200
    resp_data = resp.json()
    assert resp_data["total_results_count"] == 1
    assert resp_data["objects"][0]["id"] == stix_id


@pytest.mark.parametrize(
    "path,path_id,expected",
    [
        [
            "cwe",
            "CWE-24",
            {
                "relationship--4505690a-3974-52e2-a829-89bf7594df7e",
                "weakness--0021e0ca-b8bf-5625-b106-d35c48f66fea",
                "vulnerability--dcf08dd8-a521-5940-9d7d-9224627d48dc",
            },
        ],
        [
            "capec",
            "CAPEC-87",
            {
                "attack-pattern--00268a75-3243-477d-9166-8c78fddf6df6",
                "vulnerability--8fc6b6d4-1b2e-5f2e-b26d-ffb3ce4e44c6",
                "relationship--b1d43d4f-a42b-5be5-b5c8-aa9ddfd4438a",
            },
        ],
        [
            "attack",
            "T1557",
            {
                "attack-pattern--035bb001-ab69-4a0b-9f6c-2de8b09e1b9d",
                "vulnerability--0c6ac7fb-b877-5611-9d6a-69dcbdc0b6d1",
                "vulnerability--d7228346-a7b0-5195-b49b-26faf9aa4748",
                "relationship--8af4183b-ae76-5feb-8ee7-b86b41d144d9",
                "vulnerability--0ee1423b-5559-5af6-a169-4a8677103281",
                "relationship--dd741f2b-6792-5e50-acee-468114fc104d",
                "relationship--9ae26c64-d41b-58fb-802f-023c4cade75e",
            },
        ],
        ## bad case
        [
            "attack",
            "T1557",
            {
                "attack-pattern--035bb001-ab69-4a0b-9f6c-2de8b09e1b9d",
                "vulnerability--0c6ac7fb-b877-5611-9d6a-69dcbdc0b6d1",
                "vulnerability--d7228346-a7b0-5195-b49b-26faf9aa4748",
                "relationship--8af4183b-ae76-5feb-8ee7-b86b41d144d9",
                "vulnerability--0ee1423b-5559-5af6-a169-4a8677103281",
                "relationship--dd741f2b-6792-5e50-acee-468114fc104d",
                "relationship--9ae26c64-d41b-58fb-802f-023c4cade75e",
            },
        ],
        [
            "capec",
            "CapEC-87",
            {
                "attack-pattern--00268a75-3243-477d-9166-8c78fddf6df6",
                "vulnerability--8fc6b6d4-1b2e-5f2e-b26d-ffb3ce4e44c6",
                "relationship--b1d43d4f-a42b-5be5-b5c8-aa9ddfd4438a",
            },
        ],
        [
            "attack",
            "t1110.004",
            {
                "attack-pattern--b2d03cea-aec1-45ca-9744-9ee583c1e1cc",
                "vulnerability--bb844678-a5f3-5b5e-a1dd-72bc4abf50ac",
                "relationship--42fb7f70-c45c-5695-ba5f-8ef7b469a0aa",
            },
        ],
    ],
)
def test_bundle(client, path, path_id, expected):
    resp = client.get(f"/api/v1/{path}/objects/{path_id}/bundle/")
    assert resp.status_code == 200
    resp_data = resp.json()
    assert len(expected) == resp_data["total_results_count"]
    assert {obj["id"] for obj in resp_data["objects"]} == set(expected)
