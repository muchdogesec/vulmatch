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
    "path,path_id,expected",
    [
        ["cwe", "CWE-24", {'relationship--fb2c6916-0cae-59df-b2bb-501af201777c'}],
        ["capec", "CAPEC-87", {'relationship--6f56852c-bebc-5b89-b5bf-e91e139404f6'}],
        ["attack", "T1037", {'relationship--665f6ba3-58d4-5ba2-a338-95072527d5fc'}],
        ## bad case
        ["cwe", "CwE-24", {'relationship--fb2c6916-0cae-59df-b2bb-501af201777c'}],
        ["capec", "attack-pattern--00268a75-3243-477d-9166-8c78fddf6df6", {'relationship--6f56852c-bebc-5b89-b5bf-e91e139404f6'}],
        ["attack", "t1037", {'relationship--665f6ba3-58d4-5ba2-a338-95072527d5fc'}],
    ]
)
def test_relationships(client, path, path_id, expected):
    resp = client.get(f"/api/v1/{path}/objects/{path_id}/relationships/")
    assert resp.status_code == 200
    resp_data = resp.json()
    assert {obj['id'] for obj in resp_data['relationships']} == set(expected)


@pytest.mark.parametrize(
    "path,path_id,expected",
    [
        ["cwe", "CWE-24", {'relationship--fb2c6916-0cae-59df-b2bb-501af201777c', 'vulnerability--dcf08dd8-a521-5940-9d7d-9224627d48dc', 'weakness--0021e0ca-b8bf-5625-b106-d35c48f66fea'}],
        ["capec", "CAPEC-87", {'attack-pattern--00268a75-3243-477d-9166-8c78fddf6df6', 'relationship--6f56852c-bebc-5b89-b5bf-e91e139404f6', 'vulnerability--8fc6b6d4-1b2e-5f2e-b26d-ffb3ce4e44c6'}],
        ["attack", "T1037", {'attack-pattern--03259939-0b57-482f-8eb5-87c0e0d54334', 'relationship--665f6ba3-58d4-5ba2-a338-95072527d5fc', 'vulnerability--024e52d0-9888-5beb-87f0-80249127ef0f'}],
        ## bad case
        ["cwe", "CwE-24", {'relationship--fb2c6916-0cae-59df-b2bb-501af201777c', 'vulnerability--dcf08dd8-a521-5940-9d7d-9224627d48dc', 'weakness--0021e0ca-b8bf-5625-b106-d35c48f66fea'}],
        ["capec", "CapEC-87", {'attack-pattern--00268a75-3243-477d-9166-8c78fddf6df6', 'relationship--6f56852c-bebc-5b89-b5bf-e91e139404f6', 'vulnerability--8fc6b6d4-1b2e-5f2e-b26d-ffb3ce4e44c6'}],
        ["attack", "t1037", {'attack-pattern--03259939-0b57-482f-8eb5-87c0e0d54334', 'relationship--665f6ba3-58d4-5ba2-a338-95072527d5fc', 'vulnerability--024e52d0-9888-5beb-87f0-80249127ef0f'}],
    ]
)
def test_bundle(client, path, path_id, expected):
    resp = client.get(f"/api/v1/{path}/objects/{path_id}/bundle/")
    assert resp.status_code == 200
    resp_data = resp.json()
    assert {obj['id'] for obj in resp_data['objects']} == set(expected)

