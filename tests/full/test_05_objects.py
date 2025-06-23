import pytest





@pytest.mark.parametrize(
        "endpoint",
        [
            "smos",
            "sros",
            "scos",
            "sdos",
        ]
)
def test_paths_no_dup(client, endpoint):
    url = f'/api/v1/objects/{endpoint}/'
    resp = client.get(url)
    assert resp.status_code == 200, url
    data = resp.json()
    assert data['page_results_count'] <= data['total_results_count']
    object_refs = {obj['id'] for obj in data['objects']}
    dd = [obj['id'] for obj in data['objects']]
    for d in object_refs:
        dd.remove(d)
    assert len(object_refs) == data['page_results_count'], f"data contains duplicate ids"


@pytest.mark.parametrize(
    "object_id",
    [
        "vulnerability--b82ec506-3b53-5bf9-91e6-584249b7b378",
        "vulnerability--4720d8ec-be50-5604-a5a2-ac94d2b0f8b7",
        "vulnerability--024e52d0-9888-5beb-87f0-80249127ef0f",
    ]
)
def test_object_retrieve(client, object_id):
    url = f'/api/v1/objects/{object_id}/'
    resp = client.get(url)
    assert resp.status_code == 200, url
    data = resp.json()
    assert data['total_results_count'] == 1, "object must return only 1 object"
    assert data['objects'][0]['id'] == object_id, "unexpected stix object id"