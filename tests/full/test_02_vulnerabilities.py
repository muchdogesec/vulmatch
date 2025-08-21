import random
import pytest

from .utils import is_sorted

CVE_BUNDLE_DEFAULT_OBJECTS = [
    "extension-definition--ad995824-2901-5f6e-890b-561130a239d4",
    "extension-definition--82cad0bb-0906-5885-95cc-cafe5ee0a500",
    "extension-definition--2c5c13af-ee92-5246-9ba7-0b958f8cd34a",
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--562918ee-d5da-5579-b6a1-fae50cc6bad3",
    "identity--562918ee-d5da-5579-b6a1-fae50cc6bad3",
]
CVE_SORT_FIELDS = [
    "modified_descending",
    "modified_ascending",
    "created_ascending",
    "created_descending",
    "name_ascending",
    "name_descending",
    "epss_score_ascending",
    "epss_score_descending",
    "cvss_base_score_ascending",
    "cvss_base_score_descending",
]


@pytest.mark.parametrize(
    ["filters", "expected_ids"],
    [
        pytest.param(
            dict(weakness_id="CWE-552"),
            [
                "vulnerability--3dd99f0e-efde-508a-91ba-9556aebc937a",
            ],
            id="cwe filter",
        ),
        pytest.param(
            dict(weakness_id="cwE-552,cwe-74"),
            [
                # cwe-552
                "vulnerability--3dd99f0e-efde-508a-91ba-9556aebc937a",
                # cwe-74
                "vulnerability--f361b90a-21dd-5f91-9f24-292e81f65836",
                "vulnerability--ca8776c0-66e6-5737-b606-64d2aa1b79dd",
                "vulnerability--62625225-3b4b-5183-9534-43c640c24fa1",
                "vulnerability--683e6155-30cf-578d-aec3-b478042b8d46",
                "vulnerability--e3c3c6ea-edae-5113-a0f5-80d2cda67dd4",
                "vulnerability--baec2c44-8c12-56bb-82ce-befaff798931",
                "vulnerability--ca8706cf-2d9d-5347-a9f4-c8df396eef87",
                "vulnerability--dfd4f7a5-9702-5fe4-8d43-7a901e09f759",
                "vulnerability--014fc553-e064-5f2f-be36-1d47cbde8811",
                "vulnerability--aa0aa8e6-b537-54f0-9132-219290009f90",
                "vulnerability--ce32c27e-7509-54c0-bf4c-e2d41023d0d2",
            ],
            id="cwe filter multi - case insensitive",
        ),
        pytest.param(
            dict(vuln_status="Awaiting Analysis", weakness_id="CWE-74"),
            [
                "vulnerability--baec2c44-8c12-56bb-82ce-befaff798931",
                "vulnerability--ca8706cf-2d9d-5347-a9f4-c8df396eef87",
                "vulnerability--dfd4f7a5-9702-5fe4-8d43-7a901e09f759",
                "vulnerability--014fc553-e064-5f2f-be36-1d47cbde8811",
                "vulnerability--aa0aa8e6-b537-54f0-9132-219290009f90",
            ],
            id="vuln_status+weakness_id filter",
        ),
        pytest.param(
            dict(vuln_status="Received"),
            [
                "vulnerability--b82ec506-3b53-5bf9-91e6-584249b7b378",
                "vulnerability--3e69a3f9-816f-5f78-924c-006094850d30",
                "vulnerability--3c4b3602-bc94-55bf-9f5c-83f6e69467a9",
                "vulnerability--62625225-3b4b-5183-9534-43c640c24fa1",
                "vulnerability--683e6155-30cf-578d-aec3-b478042b8d46",
                "vulnerability--503936e0-c432-5f97-b621-280e5545cd5a",
                "vulnerability--6c95d9b1-069d-5490-8536-524aff406261",
                "vulnerability--f3ba4e6a-8cff-52b1-87ba-38df5240c679",
                "vulnerability--64381396-fcd4-5785-900f-57f7ef70bfbc",
                "vulnerability--6b580482-5602-5b40-8dd3-a3539fdd9fa5",
            ],
            id="vuln_status filter 2",
        ),
        pytest.param(
            dict(
                stix_id="vulnerability--baec2c44-8c12-56bb-82ce-befaff798931,vulnerability--ca8776c0-66e6-5737-b606-64d2aa1b79dd"
            ),
            [
                "vulnerability--baec2c44-8c12-56bb-82ce-befaff798931",
                "vulnerability--ca8776c0-66e6-5737-b606-64d2aa1b79dd",
            ],
            id="stix_id filter",
        ),
        pytest.param(
            dict(
                stix_id="vulnerability--90fd6537-fece-54e1-b698-4205e636ed3d,vulnerability--f361b90a-21dd-5f91-9f24-292e81f65836",
            ),
            [
                "vulnerability--f361b90a-21dd-5f91-9f24-292e81f65836",
                "vulnerability--90fd6537-fece-54e1-b698-4205e636ed3d",
            ],
            id="has_kev neutral + stix_id",
        ),
        pytest.param(
            dict(
                has_kev=True,
                stix_id="vulnerability--90fd6537-fece-54e1-b698-4205e636ed3d,vulnerability--f361b90a-21dd-5f91-9f24-292e81f65836",
            ),
            [
                "vulnerability--90fd6537-fece-54e1-b698-4205e636ed3d",
            ],
            id="has_kev positive + stix_id",
        ),
        pytest.param(
            dict(
                has_kev=False,
                stix_id="vulnerability--90fd6537-fece-54e1-b698-4205e636ed3d,vulnerability--f361b90a-21dd-5f91-9f24-292e81f65836",
            ),
            [
                "vulnerability--f361b90a-21dd-5f91-9f24-292e81f65836",
            ],
            id="has_kev negative + stix_id",
        ),
        pytest.param(
            dict(capec_id="caPEc-87"),
            ["vulnerability--8fc6b6d4-1b2e-5f2e-b26d-ffb3ce4e44c6"],
            id="capec_id case insensitive",
        ),
        pytest.param(
            dict(capec_id="caPEc-87,CAPeC-600"),
            [
                "vulnerability--8fc6b6d4-1b2e-5f2e-b26d-ffb3ce4e44c6",
                "vulnerability--bb844678-a5f3-5b5e-a1dd-72bc4abf50ac",
            ],
            id="capec_id multiple",
        ),
        pytest.param(
            dict(attack_id="T1027.009"),
            [
                "vulnerability--b82ec506-3b53-5bf9-91e6-584249b7b378",
                "vulnerability--4720d8ec-be50-5604-a5a2-ac94d2b0f8b7",
                "vulnerability--024e52d0-9888-5beb-87f0-80249127ef0f",
            ],
            id="attack_id case insensitive",
        ),
        pytest.param(
            dict(attack_id="T1027.009,T1003"),
            [
                "vulnerability--3dd99f0e-efde-508a-91ba-9556aebc937a",
                "vulnerability--b82ec506-3b53-5bf9-91e6-584249b7b378",
                "vulnerability--4720d8ec-be50-5604-a5a2-ac94d2b0f8b7",
                "vulnerability--024e52d0-9888-5beb-87f0-80249127ef0f",
            ],
            id="attack_id multiple",
        ),
        pytest.param(
            dict(attack_id="T1027.009,T1003", weakness_id="CWE-552"),
            ["vulnerability--3dd99f0e-efde-508a-91ba-9556aebc937a"],
            id="attack_id multiple + weakness_id",
        ),
        pytest.param(
            dict(
                cpes_in_pattern="cpe:2.3:a:mongodb:c_driver:1.15.0:*:*:*:*:mongodb:*:*"
            ),
            ["vulnerability--690cbb55-ccbf-56d3-8467-05990c12eda2"],
            id="cpes_in_pattern",
        ),
        pytest.param(
            dict(
                cpes_vulnerable="cpe:2.3:a:mongodb:c_driver:1.15.0:*:*:*:*:mongodb:*:*"
            ),
            ["vulnerability--690cbb55-ccbf-56d3-8467-05990c12eda2"],
            id="cpes_vulnerable",
        ),
        pytest.param(
            dict(
                cpes_vulnerable="cpe:2.3:a:gitlab:gitlab:17.6.0:*:*:*:enterprise:*:*:*,cpe:2.3:a:mongodb:c_driver:1.15.0:*:*:*:*:mongodb:*:*"
            ),
            [
                "vulnerability--690cbb55-ccbf-56d3-8467-05990c12eda2",
                "vulnerability--053796db-e34c-5e96-8a10-4f317962fd30",
                "vulnerability--70fc0123-3c86-5e4c-b3dc-a9fff4b16546",
                "vulnerability--79a5a175-0530-5554-8598-c3ce67f64f26",
                "vulnerability--8ca41376-d05c-5f2c-9a8a-9f7e62a5f81f",
                "vulnerability--f47fa004-825f-5bd9-8c03-07465e1e7ad2",
            ],
            id="cpes_vulnerable x2",
        ),
        pytest.param(
            dict(cpes_vulnerable="cpe:2.3:h:juniper:mx5:-:*:*:*:*:*:*:*"),
            [],
            id="cpes_vulnerable 3",
        ),
        pytest.param(
            dict(cpes_in_pattern="cpe:2.3:h:juniper:mx5:-:*:*:*:*:*:*:*"),
            [
                "vulnerability--0b2df06c-dff3-5366-a402-afc855f0fb06",
                "vulnerability--0fda7712-f026-5a75-a562-bd70d03e8b1e",
            ],
            id="cpes_in_pattern 3",
        ),
    ],
)
def test_filters_generic(client, filters: dict, expected_ids: list[str]):
    expected_ids = set(expected_ids)
    url = f"/api/v1/cve/objects/"
    resp = client.get(url, query_params=filters)
    resp_data = resp.json()
    assert all(
        cve["type"] == "vulnerability" for cve in resp_data["objects"]
    ), "response.objects[*].type must always be vulnerability"
    assert {cve["id"] for cve in resp_data["objects"]} == expected_ids
    assert resp_data["total_results_count"] == len(expected_ids)


def test_has_kev(client, ):
    expected_ids = set([
        "vulnerability--0143ea6c-4085-57f1-bac0-18b57a88cffb",
        "vulnerability--90fd6537-fece-54e1-b698-4205e636ed3d",
        "vulnerability--8ca41376-d05c-5f2c-9a8a-9f7e62a5f81f",
        "vulnerability--0cd2c4ea-93fa-5a6c-a607-674016cf4ac4",
        "vulnerability--c9f9c6ce-26aa-5061-a5d0-218874181eae",
        'vulnerability--10a94cae-1727-5bf0-aff3-2a6c67cb00c3',
    ])
    url = f"/api/v1/cve/objects/"
    resp = client.get(url, query_params=dict(has_kev=True))
    resp_data = resp.json()
    assert all(
        cve["type"] == "vulnerability" for cve in resp_data["objects"]
    ), "response.objects[*].type must always be vulnerability"
    assert {cve["id"] for cve in resp_data["objects"]}.issuperset(expected_ids)
    assert resp_data["total_results_count"] >= len(expected_ids)

def random_cve_values(client, key, count):
    url = f"/api/v1/cve/objects/"
    resp = client.get(url)
    data = resp.json()
    return [post[key] for post in random.choices(data["objects"], k=count)]


@pytest.mark.parametrize(
    "cvss_base_score_min", [random.randint(0, 100) / 10 for i in range(15)]
)
def test_cvss_base_score_min(client, cvss_base_score_min):
    url = f"/api/v1/cve/objects/"
    resp = client.get(url, query_params=dict(cvss_base_score_min=cvss_base_score_min))
    vulnerabilities = resp.json()["objects"]
    for cve in vulnerabilities:
        cvss = list(cve["x_cvss"].values())
        if not cvss:
            continue
        assert cvss[-1]["base_score"] >= cvss_base_score_min


def more_created_filters(client, prop, count):
    filters = []
    createds = random_cve_values(client, prop, 50)
    for i in range(count):
        mmin = mmax = None
        if random.random() > 0.7:
            mmax = random.choice(createds)
        if random.random() < 0.3:
            mmin = random.choice(createds)
        if mmin or mmax:
            filters.append([mmin, mmax])
    return filters


def minmax_test(client, param_name, param_min, param_max):
    filters = {}
    if param_min:
        filters.update({f"{param_name}_min": param_min})
    if param_max:
        filters.update({f"{param_name}_max": param_max})

    assert param_max or param_min, "at least one of two filters required"

    url = f"/api/v1/cve/objects/"
    resp = client.get(url, query_params=filters)
    assert resp.status_code == 200
    resp_data = resp.json()
    for d in resp_data["objects"]:
        param_value = d[param_name]
        if param_min:
            assert (
                param_value >= param_min
            ), f"{param_name} ({param_value})  must not be less than {param_name}_min : {filters}"
        if param_max:
            assert (
                param_value <= param_max
            ), f"{param_name} ({param_value}) must not be greater than {param_name}_max : {filters}"


def test_extra_created_filters(client, subtests):
    for dmin, dmax in more_created_filters(client, "created", 50) + more_created_filters(client, "modified", 50):
        with subtests.test(
            "randomly_generated created_* query", created_min=dmin, created_max=dmax
        ):
            minmax_test(client, "created", dmin, dmax)

        with subtests.test(
            "randomly_generated modified_* query", modified_min=dmin, modified_max=dmax
        ):
            minmax_test(client, "modified", dmin, dmax)


@pytest.mark.parametrize(
    "cve_id",
    [
        "CVE-2024-52047",
        "CVE-2024-13078",
        "CVE-2024-13079",
        "CVE-2024-56803",
        "CVE-2024-56063",
        "CVE-2024-56062",
        "CVE-2024-13085",
        "CVE-2024-13084",
        "CVE-2024-13083",
        "CVE-2024-13082",
        "CVE-2024-13081",
        "CVE-2024-13080",
        "CVE-2024-13077",
        "CVE-2024-56802",
        "CVE-2024-53647",
        "CVE-2024-52050",
        "CVE-2024-25133",
        "CVE-2024-13072",
        "CVE-2024-13070",
        "CVE-2024-3393",
        "CVE-2024-12977",
        "CVE-2024-12976",
        "CVE-2024-12981",
        "CVE-2024-12978",
        "CVE-2023-7028",
        "CVE-2024-21887",
        "CVE-2023-46805",
        "CVE-2023-31025",
    ],
)
def test_retrieve_vulnerability(client, cve_id):
    url = f"/api/v1/cve/objects/{cve_id}/"
    resp = client.get(url)
    resp_data = resp.json()
    assert resp_data["total_results_count"] == 1
    assert resp_data["objects"][0]["name"] == cve_id


@pytest.mark.parametrize(
    ["cve_id", "filters", "expected_count"],
    [
        ["CVE-2024-12978", None, 10],
        ["CVE-2024-53647", None, 34],
        ["CVE-2023-31025", None, 22],
        ##
        ["CVE-2024-53647", dict(include_capec=False), 20],
        ["CVE-2024-53647", dict(include_attack=False), 24],
        ["CVE-2023-31025", dict(include_capec=False), 22],
        ["CVE-2023-31025", dict(include_epss=False), 21],
    ],
)
def test_bundle(client, cve_id, filters, expected_count):
    url = f"/api/v1/cve/objects/{cve_id}/bundle/"
    resp = client.get(url, query_params=filters)
    resp_data = resp.json()
    objects = {obj["id"] for obj in resp_data["objects"]}
    assert resp_data["total_results_count"] == expected_count
    assert (
        len(objects) == resp_data["page_results_count"]
    ), "response contains duplicates"
    assert objects.issuperset(
        CVE_BUNDLE_DEFAULT_OBJECTS
    ), "result must contain default objects"


@pytest.mark.parametrize(
    ["cve_id", "expected_count"],
    [
        ["CVE-2024-12978", 1],
        ["CVE-2024-53647", 13],
        ["CVE-2023-31025", 3],
    ],
)
def test_relationships(client, cve_id, expected_count):
    url = f"/api/v1/cve/objects/{cve_id}/relationships/"
    resp = client.get(url)
    resp_data = resp.json()
    objects = {obj["id"] for obj in resp_data["relationships"]}
    assert resp_data["total_results_count"] == expected_count
    assert (
        len(objects) == resp_data["page_results_count"]
    ), "response contains duplicates"


@pytest.mark.parametrize("sort_param", CVE_SORT_FIELDS)
def test_sort(client, sort_param):
    url = f"/api/v1/cve/objects/"
    resp = client.get(url, query_params=dict(sort=sort_param))
    assert resp.status_code == 200
    resp_data = resp.json()
    assert all(
        cve["type"] == "vulnerability" for cve in resp_data["objects"]
    ), "response.objects[*].type must always be vulnerability"

    param, _, direction = sort_param.rpartition("_")
    sort_objects_to_consider = resp_data["objects"][:50]

    def get_epss_scores(cve_ids):
        resp = client.get(
            f"/api/v1/epss/objects/",
            query_params=dict(cve_id=",".join(cve_ids)),
        )
        return {
            obj["external_references"][0]["external_id"]: float(
                obj["x_epss"][-1]["epss"]
            )
            for obj in resp.json()["objects"]
        }

    cve_epss_score_map = get_epss_scores(
        [cve["name"] for cve in sort_objects_to_consider]
    )

    def key_fn(obj):
        if param == "epss_score":
            return cve_epss_score_map.get(obj["name"], 0)
        if param == "cvss_base_score":
            try:
                return float(obj["x_cvss"][-1]["base_score"])
            except:
                return 0
        return obj[param]

    revered = direction == "descending"
    assert is_sorted(
        sort_objects_to_consider, key=key_fn, reverse=revered
    ), "objects not sorted"


@pytest.mark.parametrize(
    "cve_id",
    [
        "CVE-2024-52047",
        "CVE-2024-13078",
        "CVE-2024-13079",
        "CVE-2024-56803",
        "CVE-2024-56063",
        "CVE-2024-56062",
        "CVE-2024-13085",
        "CVE-2024-13084",
        "CVE-2024-13083",
        "CVE-2024-13082",
        "CVE-2024-13081",
    ]
)
def test_versions(client, cve_id):
    resp = client.get(f"/api/v1/cve/objects/{cve_id}/versions/")
    assert resp.status_code == 200
    assert {'versions', 'latest'} == set(resp.data.keys())
    assert resp.data['latest'] == resp.data['versions'][0]