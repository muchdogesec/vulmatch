import random
import pytest



@pytest.mark.parametrize(
    ["filters", "expected_count"],
    [
        [dict(vendor="zoom", product="zoom"), 151],
        [dict(vendor="zoom", product='meeting_software_development_kit'), 7],
        [dict(vendor="zoom", product='meeting_software_development_kit', target_sw='windows'), 7],
        [dict(vendor="zoom", product='meeting_software_development_kit', target_sw='linux'), 0],
        [dict(vendor="zoom", product="zoom", version="3.5.14940.0430"), 1],
        [dict(product_type="hardware", vendor='juniper', product="junos"), 0],
        [dict(product_type="operating-system", vendor='juniper', product="junos"), 139],
        [dict(vendor="zoom", product='meeting_software_development_kit', product_type="application"), 7],
    ],
)
def test_struct_filter(client, filters, expected_count):
    url = f"/api/v1/cpe/objects/"
    resp = client.get(url, query_params=filters)
    resp_data = resp.json()
    assert resp.status_code == 200, resp_data
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
    "filters",
    [
        dict(vendor="zoom"),
        dict(vendor="zoo"),
        dict(vendor="zoom", version="3.5.14940.0430"),
        dict(target_sw="windows", version="3.5.14940.0430"),
        dict(target_sw="windows", vendor="zoom"),
        dict(product_type="hardware"),
        dict(product_type="hardware", product="qfx5130"),
        dict(product_type="application"),
        dict(product_type="operating-system"),
    ],
)
def test_endpoint_fails_if_no_vendor_product(client, filters):
    url = f"/api/v1/cpe/objects/"
    resp = client.get(url, query_params=filters)
    assert resp.status_code == 400, "request should fail"


@pytest.mark.parametrize(
    ["cpe_match_string", "expected_count"],
    [
        ["zoom", 151],
        ["zoo", 151],
        ["3.5.14940.0430", 1],
        ["windows", 151],
        ["linux", 0],
        ["qfx5130", 0],
    ],
)
def test_cpe_match_string(client, cpe_match_string, expected_count):
    url = f"/api/v1/cpe/objects/"
    resp = client.get(url, query_params=dict(cpe_match_string=cpe_match_string, product='zoom', vendor='zoom'))
    resp_data = resp.json()
    assert resp.status_code == 200, resp_data
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
    assert resp.status_code == 200, resp_data
    assert all(
        cve["type"] == "software" for cve in resp_data["objects"]
    ), "response.objects[*].type must always be software"
    assert resp_data["total_results_count"] == 1, "there must be exactly one match"
    assert resp_data["objects"][0]["cpe"] == cpe_name

@pytest.mark.parametrize(
    ["cpe_name", 'include_cves_not_vulnerable', 'expected_count'],
    [
        ["cpe:2.3:a:mongodb:c_driver:1.15.0:*:*:*:*:mongodb:*:*", None, 5],
        ["cpe:2.3:a:gitlab:gitlab:17.6.0:*:*:*:enterprise:*:*:*", None, 41],
        ["cpe:2.3:a:ays-pro:quiz_maker:1.1.0:*:*:*:*:wordpress:*:*", None, 5],
        ["cpe:2.3:o:juniper:junos:23.1:-:*:*:*:*:*:*", None, 5],
        ["cpe:2.3:a:ays-pro:quiz_maker:5.2.1:*:*:*:*:wordpress:*:*", None, 5],
        ["cpe:2.3:a:ays-pro:quiz_maker:5.1.3:*:*:*:*:wordpress:*:*", None, 5],
        ####
        ["cpe:2.3:a:mongodb:c_driver:1.15.0:*:*:*:*:mongodb:*:*", True, 5],
        ["cpe:2.3:a:gitlab:gitlab:17.6.0:*:*:*:enterprise:*:*:*", True, 41],
        ["cpe:2.3:a:ays-pro:quiz_maker:1.1.0:*:*:*:*:wordpress:*:*", True, 5],
        ["cpe:2.3:o:juniper:junos:23.1:-:*:*:*:*:*:*", True, 5],
        ["cpe:2.3:a:ays-pro:quiz_maker:5.2.1:*:*:*:*:wordpress:*:*", True, 5],
        ["cpe:2.3:a:ays-pro:quiz_maker:5.1.3:*:*:*:*:wordpress:*:*", True, 5],
        #####
        ["cpe:2.3:a:mongodb:c_driver:1.15.0:*:*:*:*:mongodb:*:*", False, 4],
        ["cpe:2.3:a:gitlab:gitlab:17.6.0:*:*:*:enterprise:*:*:*", False, 26],
        ["cpe:2.3:a:ays-pro:quiz_maker:1.1.0:*:*:*:*:wordpress:*:*", False, 4],
        ["cpe:2.3:o:juniper:junos:23.1:-:*:*:*:*:*:*", False, 4],
        ["cpe:2.3:a:ays-pro:quiz_maker:5.2.1:*:*:*:*:wordpress:*:*", False, 4],
        ["cpe:2.3:a:ays-pro:quiz_maker:5.1.3:*:*:*:*:wordpress:*:*", False, 4],
    ],
)
def test_bundle(client, cpe_name, include_cves_not_vulnerable, expected_count):
    url = f"/api/v1/cpe/objects/{cpe_name}/bundle/"
    filters = {}
    if include_cves_not_vulnerable != None:
        filters.update(include_cves_not_vulnerable=include_cves_not_vulnerable)
    else:
        include_cves_not_vulnerable = True
    
    resp = client.get(url, query_params=filters)
    assert resp.status_code == 200, resp.json()
    resp_data = resp.json()
    assert (
        len({cpe["id"] for cpe in resp_data["objects"]})
        == resp_data["page_results_count"]
    ), "response contains duplicates"
    assert resp_data["total_results_count"] == expected_count
    if not include_cves_not_vulnerable:
        assert all([obj['relationship_type'] != 'relies-on' for obj in resp_data["objects"] if obj['type'] == 'relationship'])


@pytest.mark.parametrize(
    "page,page_size",
    [
        (random.randint(1, 10), random.choice([None, 13, 50, 105, 1000])) for _ in range(10)
    ]
)

def test_paging(client, settings, page, page_size):
    url = f"/api/v1/cpe/objects/"
    params = dict(page=page, page_size=page_size, product='zoom', vendor='zoom')
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

        
