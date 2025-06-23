import random
import pytest



@pytest.mark.parametrize(
    "path",
    [
        "attack",
        "capec",
        "cwe",
        "kev",
        "cve",
        "cpe",
    ]
)
@pytest.mark.parametrize(
    "page,page_size",
    [
        (random.randint(1, 10), random.choice([None, 13, 50, 105, 1000])) for _ in range(10)
    ]
)

def test_paging_generic(client, settings, path, page, page_size):
    url = f"/api/v1/{path}/objects/"
    params = dict(page=page, page_size=page_size)
    if not page_size:
        del params["page_size"]
    resp = client.get(url, query_params=params)
    resp_data = resp.json()
    assert resp_data["page_number"] == page
    if page_size:
        assert resp_data["page_size"] == min(
            settings.MAXIMUM_PAGE_SIZE, page_size
        )
    assert resp_data["total_results_count"] >= resp_data["page_results_count"]
    assert resp_data["page_results_count"] <= resp_data["page_size"]


@pytest.mark.parametrize(
    "path,path_id,stix_id",
    [
        ["cwe", "CWE-24", "weakness--0021e0ca-b8bf-5625-b106-d35c48f66fea"],
        ["capec", "CAPEC-87", "attack-pattern--00268a75-3243-477d-9166-8c78fddf6df6"],
        ["attack", "T1037", "attack-pattern--03259939-0b57-482f-8eb5-87c0e0d54334"],
        ##
        # ["cwe", "weakness--0021e0ca-b8bf-5625-b106-d35c48f66fea", "weakness--0021e0ca-b8bf-5625-b106-d35c48f66fea"],
        # ["capec", "attack-pattern--00268a75-3243-477d-9166-8c78fddf6df6", "attack-pattern--00268a75-3243-477d-9166-8c78fddf6df6"],
        # ["attack","attack-pattern--03259939-0b57-482f-8eb5-87c0e0d54334", "attack-pattern--03259939-0b57-482f-8eb5-87c0e0d54334"],
        ## bad case
        ["cwe", "CwE-24", "weakness--0021e0ca-b8bf-5625-b106-d35c48f66fea"],
        ["capec", "CapEC-87", "attack-pattern--00268a75-3243-477d-9166-8c78fddf6df6"],
        ["attack", "t1037", "attack-pattern--03259939-0b57-482f-8eb5-87c0e0d54334"],
    ]
)
def test_retrieve(client, path, path_id, stix_id):
    resp = client.get(f"/api/v1/{path}/objects/{path_id}/")
    assert resp.status_code == 200
    resp_data = resp.json()
    assert resp_data['objects'][0]['id'] == stix_id



@pytest.mark.parametrize(
    "path,path_id,stix_id",
    [
        ["cwe", "CWE-24", "weakness--0021e0ca-b8bf-5625-b106-d35c48f66fea"],
        ["capec", "CAPEC-87", "attack-pattern--00268a75-3243-477d-9166-8c78fddf6df6"],
        ["attack", "T1037", "attack-pattern--03259939-0b57-482f-8eb5-87c0e0d54334"],
        ## bad case
        ["cwe", "CwE-24", "weakness--0021e0ca-b8bf-5625-b106-d35c48f66fea"],
        ["capec", "CapEC-87", "attack-pattern--00268a75-3243-477d-9166-8c78fddf6df6"],
        ["attack", "t1037", "attack-pattern--03259939-0b57-482f-8eb5-87c0e0d54334"],
    ]
)
def test_relationships(client, path, path_id, stix_id):
    resp = client.get(f"/api/v1/{path}/objects/{path_id}/relationships/")
    assert resp.status_code == 200
    resp_data = resp.json()
    for obj in resp_data['relationships']:
        assert obj['type'] == 'relationship'
        assert stix_id in (obj['target_ref'], obj['source_ref'])