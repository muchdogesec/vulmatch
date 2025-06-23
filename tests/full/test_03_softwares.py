import pytest



@pytest.mark.parametrize(
    ["filters", "expected_count"],
    [
        [dict(vendor="zoom"), 165],
        [dict(vendor="zoo"), 165],
        [dict(vendor="zoom", version="3.5.14940.0430"), 1],
        [dict(target_sw="windows", version="3.5.14940.0430"), 1],
        [dict(target_sw="windows", vendor="zoom"), 164],
        [dict(product_type="hardware"), 87],
        [dict(product_type="hardware", product="qfx5130"), 1],
        [dict(product_type="application"), 1575],
        [dict(product_type="operating-system"), 332],
    ],
)
def test_struct_filter(client, filters, expected_count):
    url = f"/api/v1/cpe/objects/"
    resp = client.get(url, query_params=filters)
    resp_data = resp.json()
    assert all(
        cve["type"] == "software" for cve in resp_data["objects"]
    ), "response.objects[*].type must always be software"
    assert (
        len({cpe["id"] for cpe in resp_data["objects"]})
        == resp_data["page_results_count"]
    ), "response contains duplicates"
    assert resp_data["total_results_count"] == expected_count
    for obj in resp_data["objects"]:
        for filter_key, filter_value in filters.items():
            if filter_key == "product_type":
                filter_key, filter_value = "part", filter_value[:1]
            assert filter_value in obj["x_cpe_struct"][filter_key]


@pytest.mark.parametrize(
    ["cpe_match_string", "expected_count"],
    [
        ["cpe:2.3:h:juniper", 69],
        ["cpe:2.3:h:juniper:srx320", 1],
        ["zoom", 165],
        ["zoo", 165],
        ["3.5.14940.0430", 1],
        ["windows", 167],
        ["linux", 29],
        ["qfx5130", 1],
    ],
)
def test_cpe_match_string(client, cpe_match_string, expected_count):
    url = f"/api/v1/cpe/objects/"
    resp = client.get(url, query_params=dict(cpe_match_string=cpe_match_string))
    resp_data = resp.json()
    assert all(
        cve["type"] == "software" for cve in resp_data["objects"]
    ), "response.objects[*].type must always be software"
    assert (
        len({cpe["id"] for cpe in resp_data["objects"]})
        == resp_data["page_results_count"]
    ), "response contains duplicates"
    assert resp_data["total_results_count"] == expected_count
    for obj in resp_data["objects"]:
        assert cpe_match_string in obj["cpe"]


@pytest.mark.parametrize(
    "cpe_name",
    [
        "cpe:2.3:a:mongodb:c_driver:1.15.0:*:*:*:*:mongodb:*:*",
        "cpe:2.3:a:gitlab:gitlab:17.6.0:*:*:*:enterprise:*:*:*",
        "cpe:2.3:a:ays-pro:quiz_maker:1.1.0:*:*:*:*:wordpress:*:*",
        "cpe:2.3:o:juniper:junos:23.1:-:*:*:*:*:*:*",
        "cpe:2.3:a:ays-pro:quiz_maker:5.2.1:*:*:*:*:wordpress:*:*",
        "cpe:2.3:a:ays-pro:quiz_maker:5.1.3:*:*:*:*:wordpress:*:*",
        "cpe:2.3:a:ays-pro:quiz_maker:5.1.1:*:*:*:*:wordpress:*:*",
        "cpe:2.3:a:relax-and-recover:relax-and-recover:1.7.19:*:*:*:*:*:*:*",
        "cpe:2.3:a:ays-pro:quiz_maker:4.6.7:*:*:*:*:wordpress:*:*",
        "cpe:2.3:a:ivanti:policy_secure:22.2:r3:*:*:*:*:*:*",
        "cpe:2.3:o:juniper:junos:20.3:r2:*:*:*:*:*:*",
        "cpe:2.3:a:relax-and-recover:relax-and-recover:2.2:*:*:*:*:*:*:*",
        "cpe:2.3:o:juniper:junos_os_evolved:21.3:-:*:*:*:*:*:*",
        "cpe:2.3:a:ays-pro:quiz_maker:6.2.7.1:*:*:*:*:wordpress:*:*",
    ],
)
def test_retrieve_cpe(client, cpe_name):
    url = f"/api/v1/cpe/objects/{cpe_name}/"
    resp = client.get(url)
    resp_data = resp.json()
    assert all(
        cve["type"] == "software" for cve in resp_data["objects"]
    ), "response.objects[*].type must always be software"
    assert resp_data["total_results_count"] == 1, "there must be exactly one match"
    assert resp_data["objects"][0]["cpe"] == cpe_name

@pytest.mark.parametrize(
    ["cpe_name", 'relationship_type', 'expected_count'],
    [
        ["cpe:2.3:a:mongodb:c_driver:1.15.0:*:*:*:*:mongodb:*:*", None, 4],
        ["cpe:2.3:a:gitlab:gitlab:17.6.0:*:*:*:enterprise:*:*:*", None, 36],
        ["cpe:2.3:a:ays-pro:quiz_maker:1.1.0:*:*:*:*:wordpress:*:*", None, 4],
        ["cpe:2.3:o:juniper:junos:23.1:-:*:*:*:*:*:*", None, 4],
        ["cpe:2.3:a:ays-pro:quiz_maker:5.2.1:*:*:*:*:wordpress:*:*", None, 4],
        ["cpe:2.3:a:ays-pro:quiz_maker:5.1.3:*:*:*:*:wordpress:*:*", None, 4],
        ####
        ["cpe:2.3:a:mongodb:c_driver:1.15.0:*:*:*:*:mongodb:*:*", 'in-pattern', 3],
        ["cpe:2.3:a:gitlab:gitlab:17.6.0:*:*:*:enterprise:*:*:*", 'in-pattern', 21],
        ["cpe:2.3:a:ays-pro:quiz_maker:1.1.0:*:*:*:*:wordpress:*:*", 'in-pattern', 3],
        ["cpe:2.3:o:juniper:junos:23.1:-:*:*:*:*:*:*", 'in-pattern', 3],
        ["cpe:2.3:a:ays-pro:quiz_maker:5.2.1:*:*:*:*:wordpress:*:*", 'in-pattern', 3],
        ["cpe:2.3:a:ays-pro:quiz_maker:5.1.3:*:*:*:*:wordpress:*:*", 'in-pattern', 3],
        #####
        ["cpe:2.3:a:mongodb:c_driver:1.15.0:*:*:*:*:mongodb:*:*", 'vulnerable-to', 3],
        ["cpe:2.3:a:gitlab:gitlab:17.6.0:*:*:*:enterprise:*:*:*", 'vulnerable-to', 21],
        ["cpe:2.3:a:ays-pro:quiz_maker:1.1.0:*:*:*:*:wordpress:*:*", 'vulnerable-to', 3],
        ["cpe:2.3:o:juniper:junos:23.1:-:*:*:*:*:*:*", 'vulnerable-to', 3],
        ["cpe:2.3:a:ays-pro:quiz_maker:5.2.1:*:*:*:*:wordpress:*:*", 'vulnerable-to', 3],
        ["cpe:2.3:a:ays-pro:quiz_maker:5.1.3:*:*:*:*:wordpress:*:*", 'vulnerable-to', 3],
    ],
)
def test_relationships(client, cpe_name, relationship_type, expected_count):
    url = f"/api/v1/cpe/objects/{cpe_name}/relationships/"
    filters = {}
    if relationship_type:
        filters.update(relationship_type=relationship_type)
    resp = client.get(url, query_params=filters)
    resp_data = resp.json()
    assert (
        len({cpe["id"] for cpe in resp_data["relationships"]})
        == resp_data["page_results_count"]
    ), "response contains duplicates"
    assert resp_data["total_results_count"] == expected_count
    if relationship_type:
        if relationship_type == 'vulnerable-to':
            should, shouldnt = 'exploits', 'relies-on'
        else:
            should, shouldnt = 'relies-on', 'exploits'
        assert any([obj['relationship_type'] == should for obj in resp_data["relationships"] if obj['type'] == 'relationship'])
        assert all([obj['relationship_type'] != shouldnt for obj in resp_data["relationships"] if obj['type'] == 'relationship'])


        
