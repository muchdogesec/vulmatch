import random
import pytest


@pytest.mark.parametrize(
    ["filters", "expected_count"],
    [
        [dict(vendor="zoom", product="zoom"), 151],
        [dict(vendor="zoom", product="meeting_software_development_kit"), 7],
        [
            dict(
                vendor="zoom",
                product="meeting_software_development_kit",
                target_sw="windows",
            ),
            7,
        ],
        [
            dict(
                vendor="zoom",
                product="meeting_software_development_kit",
                target_sw="linux",
            ),
            0,
        ],
        [dict(vendor="zoom", product="zoom", version="3.5.14940.0430"), 1],
        [dict(product_type="hardware", vendor="juniper", product="junos"), 0],
        [
            dict(product_type="operating-system", vendor="juniper", product="junos"),
            1064,
        ],
        [
            dict(
                vendor="zoom",
                product="meeting_software_development_kit",
                product_type="application",
            ),
            7,
        ],
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
    resp = client.get(
        url,
        query_params=dict(
            cpe_match_string=cpe_match_string, product="zoom", vendor="zoom"
        ),
    )
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
    assert resp.status_code == 200, resp_data
    resp_data = resp.json()
    assert resp_data["type"] == "software"
    assert resp_data["cpe"] == cpe_name


@pytest.mark.parametrize(
    ["cpe_name", "filters", "expected_count"],
    [
        ["cpe:2.3:a:mongodb:c_driver:1.15.0:*:*:*:*:mongodb:*:*", None, 13],
        [
            "cpe:2.3:a:mongodb:c_driver:1.15.0:*:*:*:*:mongodb:*:*",
            dict(include_cves_vulnerable=False),
            8,
        ],
        ["cpe:2.3:a:ays-pro:quiz_maker:1.1.0:*:*:*:*:wordpress:*:*", None, 13],
        [
            "cpe:2.3:a:ays-pro:quiz_maker:1.1.0:*:*:*:*:wordpress:*:*",
            dict(include_cves_vulnerable=False),
            8,
        ],
        ["cpe:2.3:o:juniper:junos:23.1:-:*:*:*:*:*:*", None, 13],
        [
            "cpe:2.3:o:juniper:junos:23.1:-:*:*:*:*:*:*",
            dict(include_cves_vulnerable=False),
            8,
        ],
        ["cpe:2.3:a:ays-pro:quiz_maker:5.2.1:*:*:*:*:wordpress:*:*", None, 13],
        [
            "cpe:2.3:a:ays-pro:quiz_maker:5.2.1:*:*:*:*:wordpress:*:*",
            dict(include_cves_vulnerable=False),
            8,
        ],
        #####
        [
            "cpe:2.3:h:huawei:secospace_usg6600:-:*:*:*:*:*:*:*",
            dict(include_cves_vulnerable=False),
            37,
        ],
        [
            "cpe:2.3:h:huawei:secospace_usg6600:-:*:*:*:*:*:*:*",
            dict(include_cves_not_vulnerable=False),
            8,
        ],
        [
            "cpe:2.3:h:huawei:secospace_usg6600:-:*:*:*:*:*:*:*",
            dict(include_cves_not_vulnerable=True),
            37,
        ],
        ["cpe:2.3:h:huawei:secospace_usg6600:-:*:*:*:*:*:*:*", None, 37],
    ],
)
def test_bundle(client, cpe_name, filters, expected_count):
    url = f"/api/v1/cpe/objects/{cpe_name}/bundle/"
    filters = filters or {}

    resp = client.get(url, query_params=filters)
    assert resp.status_code == 200, resp.json()
    resp_data = resp.json()
    assert (
        len({cpe["id"] for cpe in resp_data["objects"]})
        == resp_data["page_results_count"]
    ), "response contains duplicates"
    assert resp_data["total_results_count"] == expected_count
    if not filters.get("include_cves_not_vulnerable", True):
        assert all(
            [
                obj["relationship_type"] != "relies-on"
                for obj in resp_data["objects"]
                if obj["type"] == "relationship"
            ]
        )


@pytest.mark.parametrize(
    "types,expected_count",
    [
        [("software",), 1],
        [("vulnerability",), 1],
        [("indicator",), 1],
        [("relationship",), 2],
        [("software", "indicator"), 2],
        [("software", "vulnerability"), 2],
        [("relationship", "vulnerability"), 3],
        [None, 13],
        [("software", "relationship", "indicator", "vulnerability"), 5],
        [("software", "relationship", "indicator", "vulnerability", "grouping"), 6],
    ],
)
def test_bundle_types(client, types, expected_count):
    url = f"/api/v1/cpe/objects/cpe:2.3:a:ays-pro:quiz_maker:5.2.1:*:*:*:*:wordpress:*:*/bundle/"
    filters = {}
    if types:
        filters.update(types=",".join(types))
        types = set(types)
    else:
        types = {
            "software",
            "relationship",
            "indicator",
            "vulnerability",
            "grouping",
            "marking-definition",
            "extension-definition",
            "identity",
        }
    resp = client.get(url, query_params=filters)
    assert resp.status_code == 200, resp.json()
    resp_data = resp.json()
    assert types.issuperset({r["type"] for r in resp_data["objects"]})
    assert resp_data["total_results_count"] == expected_count


@pytest.mark.parametrize(
    "page,page_size",
    [
        (random.randint(1, 10), random.choice([None, 13, 50, 105, 1000]))
        for _ in range(10)
    ],
)
def test_paging(client, settings, page, page_size):
    url = f"/api/v1/cpe/objects/"
    params = dict(page=page, page_size=page_size, product="zoom", vendor="zoom")
    if not page_size:
        del params["page_size"]
    resp = client.get(url, query_params=params)
    resp_data = resp.json()
    assert resp_data["page_number"] == page
    if page_size:
        assert resp_data["page_size"] == min(settings.MAXIMUM_PAGE_SIZE, page_size)
    assert resp_data["total_results_count"] >= resp_data["page_results_count"]
    assert resp_data["page_results_count"] <= resp_data["page_size"]
