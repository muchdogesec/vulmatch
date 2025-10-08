import random
import pytest

from .utils import is_sorted

CVE_BUNDLE_DEFAULT_OBJECTS = [
    "extension-definition--ad995824-2901-5f6e-890b-561130a239d4",
    "extension-definition--82cad0bb-0906-5885-95cc-cafe5ee0a500",
    "extension-definition--2c5c13af-ee92-5246-9ba7-0b958f8cd34a",
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--562918ee-d5da-5579-b6a1-fae50cc6bad3",
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
    "x_opencti_cvss_v2_base_score_ascending",
    "x_opencti_cvss_v2_base_score_descending",
    "x_opencti_cvss_base_score_ascending",
    "x_opencti_cvss_base_score_descending",
    "x_opencti_cvss_v4_base_score_ascending",
    "x_opencti_cvss_v4_base_score_descending",
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
                x_opencti_cisa_kev=True,
                stix_id="vulnerability--90fd6537-fece-54e1-b698-4205e636ed3d,vulnerability--f361b90a-21dd-5f91-9f24-292e81f65836",
            ),
            [
                "vulnerability--90fd6537-fece-54e1-b698-4205e636ed3d",
            ],
            id="has_kev positive + stix_id",
        ),
        pytest.param(
            dict(
                x_opencti_cisa_kev=False,
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
                x_cpes_not_vulnerable="cpe:2.3:a:mongodb:c_driver:1.15.0:*:*:*:*:mongodb:*:*"
            ),
            [],
            id="x_cpes_not_vulnerable",
        ),
        pytest.param(
            dict(
                x_cpes_vulnerable="cpe:2.3:a:mongodb:c_driver:1.15.0:*:*:*:*:mongodb:*:*"
            ),
            ["vulnerability--690cbb55-ccbf-56d3-8467-05990c12eda2"],
            id="x_cpes_vulnerable",
        ),
        pytest.param(
            dict(
                x_cpes_vulnerable="cpe:2.3:a:gitlab:gitlab:17.6.0:*:*:*:enterprise:*:*:*,cpe:2.3:a:mongodb:c_driver:1.15.0:*:*:*:*:mongodb:*:*"
            ),
            [
                "vulnerability--690cbb55-ccbf-56d3-8467-05990c12eda2",
            ],
            id="x_cpes_vulnerable x2",
        ),
        pytest.param(
            dict(x_cpes_vulnerable="cpe:2.3:h:juniper:mx5:-:*:*:*:*:*:*:*"),
            [],
            id="x_cpes_vulnerable 3",
        ),
        pytest.param(
            dict(x_cpes_not_vulnerable="cpe:2.3:h:juniper:mx5:-:*:*:*:*:*:*:*"),
            [
                "vulnerability--0b2df06c-dff3-5366-a402-afc855f0fb06",
                "vulnerability--0fda7712-f026-5a75-a562-bd70d03e8b1e",
            ],
            id="x_cpes_not_vulnerable 3",
        ),
        pytest.param(
            dict(epss_score_min="0.1"),
            [
                "vulnerability--10a94cae-1727-5bf0-aff3-2a6c67cb00c3",
                "vulnerability--90fd6537-fece-54e1-b698-4205e636ed3d",
                "vulnerability--3d320b63-8035-56b7-9d7f-fe98feedf0cb",
                "vulnerability--2fecb4e8-21da-5b10-bc08-f35a6c7daadb",
                "vulnerability--7f541ed1-94d4-50f9-9f3d-34b8473a47cb",
                "vulnerability--ad1294fa-26ee-5877-afa4-c93d7e7a9d32",
                "vulnerability--5891c202-96ab-5931-8684-808471d994c1",
                "vulnerability--c9f9c6ce-26aa-5061-a5d0-218874181eae",
                "vulnerability--aad38a2e-7afa-5c55-8a92-f5e3b47daffc",
                "vulnerability--8ca41376-d05c-5f2c-9a8a-9f7e62a5f81f",
                "vulnerability--d7b810e0-1806-55b7-b473-f7d50532006d",
                "vulnerability--0cd2c4ea-93fa-5a6c-a607-674016cf4ac4",
            ],
            id="epss_score_min 1",
        ),
        pytest.param(
            dict(epss_score_min="0.8"),
            [
                "vulnerability--10a94cae-1727-5bf0-aff3-2a6c67cb00c3",
                "vulnerability--c9f9c6ce-26aa-5061-a5d0-218874181eae",
                "vulnerability--8ca41376-d05c-5f2c-9a8a-9f7e62a5f81f",
                "vulnerability--d7b810e0-1806-55b7-b473-f7d50532006d",
                "vulnerability--0cd2c4ea-93fa-5a6c-a607-674016cf4ac4",
            ],
            id="epss_score_min 2",
        ),
        pytest.param(
            dict(epss_percentile_min="0.9"),
            [
                "vulnerability--8ca41376-d05c-5f2c-9a8a-9f7e62a5f81f",
                "vulnerability--2fecb4e8-21da-5b10-bc08-f35a6c7daadb",
                "vulnerability--90fd6537-fece-54e1-b698-4205e636ed3d",
                "vulnerability--10a94cae-1727-5bf0-aff3-2a6c67cb00c3",
                "vulnerability--5891c202-96ab-5931-8684-808471d994c1",
                "vulnerability--d7b810e0-1806-55b7-b473-f7d50532006d",
                "vulnerability--3d320b63-8035-56b7-9d7f-fe98feedf0cb",
                "vulnerability--0cd2c4ea-93fa-5a6c-a607-674016cf4ac4",
                "vulnerability--c9f9c6ce-26aa-5061-a5d0-218874181eae",
                "vulnerability--ad1294fa-26ee-5877-afa4-c93d7e7a9d32",
                "vulnerability--7f541ed1-94d4-50f9-9f3d-34b8473a47cb",
                "vulnerability--aad38a2e-7afa-5c55-8a92-f5e3b47daffc",
            ],
            id="epss_percentile_min 1",
        ),
        pytest.param(
            dict(epss_percentile_min="0.8"),
            [
                "vulnerability--8d86bec6-8a68-5b16-8f4d-c7a8a8fe5900",
                "vulnerability--ad1294fa-26ee-5877-afa4-c93d7e7a9d32",
                "vulnerability--c9f9c6ce-26aa-5061-a5d0-218874181eae",
                "vulnerability--aad38a2e-7afa-5c55-8a92-f5e3b47daffc",
                "vulnerability--ca136d1d-40fb-50c2-b1c0-fcba4b6a497b",
                "vulnerability--90fd6537-fece-54e1-b698-4205e636ed3d",
                "vulnerability--23f18e19-ad0d-5ad5-97ac-34eb1afaadb9",
                "vulnerability--2fecb4e8-21da-5b10-bc08-f35a6c7daadb",
                "vulnerability--7f541ed1-94d4-50f9-9f3d-34b8473a47cb",
                "vulnerability--8ca41376-d05c-5f2c-9a8a-9f7e62a5f81f",
                "vulnerability--83f3761d-2e25-5e82-8c6b-c950dc9674a9",
                "vulnerability--0cd2c4ea-93fa-5a6c-a607-674016cf4ac4",
                "vulnerability--e5a3f441-87f7-5944-af72-c46369e7873a",
                "vulnerability--aaa02bb7-1f80-548d-bd05-031a28c975c7",
                "vulnerability--3d320b63-8035-56b7-9d7f-fe98feedf0cb",
                "vulnerability--5891c202-96ab-5931-8684-808471d994c1",
                "vulnerability--10a94cae-1727-5bf0-aff3-2a6c67cb00c3",
                "vulnerability--16623214-ad93-5163-99e0-33404eb563fc",
                "vulnerability--d7b810e0-1806-55b7-b473-f7d50532006d",
            ],
            id="epss_percentile_min 2",
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


@pytest.mark.parametrize(
    "vuln_status",
    [
        "Received",
        "Rejected",
        "Analyzed",
        "Awaiting Analysis",
        "Modified",
    ],
)
def test_vuln_status(client, vuln_status):
    filters = dict()
    if vuln_status:
        filters.update(vuln_status=vuln_status)
    url = f"/api/v1/cve/objects/"
    resp = client.get(url, query_params=filters)
    resp_data = resp.json()
    assert all(
        cve["type"] == "vulnerability" for cve in resp_data["objects"]
    ), "response.objects[*].type must always be vulnerability"
    fn = lambda x: [
        y["description"]
        for y in x["external_references"]
        if y["source_name"] == "vulnStatus"
    ][0]
    assert set(map(fn, resp_data["objects"])).issubset(
        {vuln_status}
    ), f"all objects must have vulnStatus == `{vuln_status}`"


def test_x_opencti_cisa_kev(
    client,
):
    expected_ids = {
        "vulnerability--0143ea6c-4085-57f1-bac0-18b57a88cffb",
        "vulnerability--90fd6537-fece-54e1-b698-4205e636ed3d",
        "vulnerability--8ca41376-d05c-5f2c-9a8a-9f7e62a5f81f",
        "vulnerability--0cd2c4ea-93fa-5a6c-a607-674016cf4ac4",
        "vulnerability--c9f9c6ce-26aa-5061-a5d0-218874181eae",
        "vulnerability--10a94cae-1727-5bf0-aff3-2a6c67cb00c3",
    }
    url = f"/api/v1/cve/objects/"
    resp = client.get(url, query_params=dict(x_opencti_cisa_kev=True))
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
    "filter_value", [random.randint(0, 100) / 10 for i in range(15)]
)
@pytest.mark.parametrize(
    "filter_key",
    [
        "x_opencti_cvss_v2_base_score",
        "x_opencti_cvss_base_score",
        "x_opencti_cvss_v4_base_score",
    ],
)
def test_cvss_base_score_min(client, filter_key, filter_value):
    url = f"/api/v1/cve/objects/"
    resp = client.get(url, query_params={filter_key + "_min": filter_value})
    vulnerabilities = resp.json()["objects"]
    for cve in vulnerabilities:
        assert cve.get(filter_key, 0) >= filter_value


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
    for dmin, dmax in more_created_filters(
        client, "created", 50
    ) + more_created_filters(client, "modified", 50):
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
    assert resp.status_code == 200
    resp_data = resp.json()
    assert resp_data["name"] == cve_id


@pytest.mark.parametrize(
    ["cve_id", "filters", "expected_count"],
    [
        ["CVE-2024-12978", None, 20],
        ["CVE-2024-53647", None, 104],
        ["CVE-2023-31025", None, 24],
        ##
        ["CVE-2024-53647", dict(include_capec=False), 50],
        ["CVE-2024-53647", dict(include_attack=False), 82],
        ["CVE-2023-31025", dict(include_capec=False), 24],
        ["CVE-2023-31025", dict(include_epss=False), 23],
        ["CVE-2024-53197", dict(include_kev=True), 5160],
        [
            "CVE-2024-53197",
            dict(include_kev=False),
            5158,
        ],  # subtract cisa and vulncheck kev (5160 - 2)
        [
            "CVE-2024-53197",
            dict(include_kev=False, include_epss=False),
            5157,
        ],  # subtract cisa and vulncheck kev (5160 - 2) and one epss report (5158 - 1)
        ["CVE-2024-53197", dict(include_x_cpes_not_vulnerable=False), 5160],
        ["CVE-2024-53197", dict(include_x_cpes_vulnerable=False), 17],
        [
            "CVE-2024-53197",
            dict(include_x_cpes_vulnerable=False, include_kev=False),
            15,
        ],
        [
            "CVE-2024-53197",
            dict(
                include_x_cpes_vulnerable=False, include_kev=False, include_epss=False
            ),
            14,
        ],
    ],
)
def test_bundle(client, cve_id, filters, expected_count):
    url = f"/api/v1/cve/objects/{cve_id}/bundle/"
    resp = client.get(url, query_params=filters)
    resp_data = resp.json()
    object_ids = {obj["id"] for obj in resp_data["objects"]}
    assert resp_data["total_results_count"] == expected_count
    assert (
        len(object_ids) == resp_data["page_results_count"]
    ), "response contains duplicates"
    assert object_ids.issuperset(
        CVE_BUNDLE_DEFAULT_OBJECTS
    ), f"result must contain default objects"


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
                obj["x_epss"][0]["epss"]
            )
            for obj in resp.json()["objects"]
        }

    cve_epss_score_map = get_epss_scores(
        [cve["name"] for cve in sort_objects_to_consider]
    )

    def key_fn(obj):
        if param == "epss_score":
            return cve_epss_score_map.get(obj["name"], default)
        if "cvss" in param:
            return obj.get(param, 0)
        return obj[param]

    revered = direction == "descending"
    default = 10 if revered else 0
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
    ],
)
def test_versions(client, cve_id):
    resp = client.get(f"/api/v1/cve/objects/{cve_id}/versions/")
    assert resp.status_code == 200
    assert {"versions", "latest"} == set(resp.data.keys())
    assert resp.data["latest"] == resp.data["versions"][0]


def test_navigator(client):
    cve_id = "CVE-2024-56803"
    resp = client.get(f"/api/v1/cve/objects/{cve_id}/navigator/")
    assert resp.status_code == 200
    assert resp.json() == {
        "description": "Techniques CVE-2024-56803 is exploited by",
        "name": "CVE-2024-56803",
        "domain": "enterprise-attack",
        "versions": {"layer": "4.5", "navigator": "5.1.0"},
        "techniques": [
            {"techniqueID": "T1027.006", "score": 100, "showSubtechniques": True},
            {"techniqueID": "T1027.009", "score": 100, "showSubtechniques": True},
            {"techniqueID": "T1564.009", "score": 100, "showSubtechniques": True},
        ],
        "gradient": {"colors": ["#ffffff", "#ff6666"], "minValue": 0, "maxValue": 100},
        "legendItems": [],
        "metadata": [
            {
                "name": "stix_id",
                "value": "vulnerability--b82ec506-3b53-5bf9-91e6-584249b7b378",
            },
            {"name": "cve_id", "value": "CVE-2024-56803"},
        ],
        "links": [{"label": "vulmatch", "url": "https://app.vulmatch.com"}],
        "layout": {"layout": "side"},
    }


def test_navigator__fails(client):
    cve_id = "CVE-2026-56803"
    resp = client.get(f"/api/v1/cve/objects/{cve_id}/navigator/")
    assert resp.status_code == 404


@pytest.mark.parametrize("min_score", [x / 20 for x in range(0, 20)])
def test_epss_score_min(client, min_score):
    resp = client.get(
        f"/api/v1/cve/objects/", query_params=dict(epss_score_min=min_score)
    )
    assert resp.status_code == 200
    for cve in resp.data["objects"]:
        assert cve.get("x_opencti_epss_score", 0) >= min_score


@pytest.mark.parametrize("min_percentile", [x / 20 for x in range(0, 20)])
def test_epss_percentile_min(client, min_percentile):
    resp = client.get(
        f"/api/v1/cve/objects/", query_params=dict(epss_percentile_min=min_percentile)
    )
    assert resp.status_code == 200
    for cve in resp.data["objects"]:
        assert cve.get("x_opencti_epss_percentile", 0) >= min_percentile


@pytest.mark.parametrize(
    "filters,expected_ids",
    [
        (
            None,
            [
                "identity--64dfee48-e209-5e25-bad4-dcc80d221a85",
                "identity--74a17a7d-4559-56ac-882c-abd4e64618bf",
                "identity--ac18951b-427a-56a7-9ca2-b9ba414c9708",
                "identity--5ed2f6ab-d27e-5cff-9e4f-056dd36be502",
                "identity--a572da7d-cac6-5e37-abee-184f7b03b815",
                "identity--a84148fc-e7c0-5007-9bd6-e91d53b46f97",
                "identity--2a31dab1-be63-538a-b6fb-5d7c60b7f9b5",
                "identity--31974714-735f-5bd7-872f-09d92126f94e",
                "identity--2d63a748-daeb-5c11-a121-948a7d78e1c0",
                "identity--9092b7ea-75a6-5459-bf2f-3da759bd34a9",
                "identity--5ce49a66-a966-5f76-98f5-3f397dde31bb",
                "identity--37df4a90-2dcb-5a06-bc4f-104e2c080807",
                "identity--fd1062d3-9675-575f-8fc9-b8c3da931026",
                "identity--b1e77389-b06c-5d05-9077-8221a7fa6223",
                "identity--5db48ebd-e120-511c-a5ea-4b69ef872425",
                "identity--1e4d4d72-2010-572f-ac94-85bdf2ac3529",
                "identity--cb19f1c9-2cff-55c1-9782-eeabef1a6566",
                "identity--f54381f2-378c-502c-94a4-b314a8bc5fda",
                "identity--9a326c24-d2a5-5ac7-bd5c-bf22f11f4163",
                "identity--cd00e3bf-6784-5972-9539-468b9f63483e",
                "identity--13120cf7-b197-5280-a1c4-feb9f63a5ad0",
                "identity--de53d769-414b-5744-9f69-7e6ad92edba8",
                "identity--b099e12f-e96e-5f45-88e3-56cf2152a88c",
                "identity--d71c6b17-8860-557e-91fc-602fed648208",
                "identity--f8f12490-69f1-5f2d-bee3-600249d5998b",
                "identity--a9546a6d-7e78-5367-847d-8d10e8a77bc9",
                "identity--3759e3ac-4da9-5c8c-a506-bbd312f35b07",
                "identity--a50227ba-6e4e-5158-a0c1-e0f2dbb870ff",
                "identity--bf10c45b-3fbe-544a-b446-3719385b0b8b",
                "identity--3644753d-7db4-5c2f-af5e-4dc9b8d196ba",
                "identity--62c68901-68ea-5732-8339-de64564cc422",
                "identity--d1a7d194-0a3b-5bb1-ac5f-45da6a391b1d",
                "identity--998eaac5-239e-54e8-91f1-c6033ef07ea8",
                "identity--a106f448-a5f1-5236-a07a-390817820ab2",
                "identity--7b1bfc27-312f-541c-80ba-55f4e3d79ccd",
            ],
        ),
        (
            dict(name="security"),
            [
                "identity--74a17a7d-4559-56ac-882c-abd4e64618bf",
                "identity--ac18951b-427a-56a7-9ca2-b9ba414c9708",
                "identity--5ed2f6ab-d27e-5cff-9e4f-056dd36be502",
                "identity--5ce49a66-a966-5f76-98f5-3f397dde31bb",
                "identity--1e4d4d72-2010-572f-ac94-85bdf2ac3529",
                "identity--f54381f2-378c-502c-94a4-b314a8bc5fda",
                "identity--9a326c24-d2a5-5ac7-bd5c-bf22f11f4163",
                "identity--de53d769-414b-5744-9f69-7e6ad92edba8",
                "identity--f8f12490-69f1-5f2d-bee3-600249d5998b",
                "identity--a50227ba-6e4e-5158-a0c1-e0f2dbb870ff",
                "identity--d1a7d194-0a3b-5bb1-ac5f-45da6a391b1d",
            ],
        ),
        (dict(name="secure"), []),
        (dict(name="miTre"), ["identity--64dfee48-e209-5e25-bad4-dcc80d221a85"]),
        (
            dict(
                name="security",
                id="identity--74a17a7d-4559-56ac-882c-abd4e64618bf,identity--5ed2f6ab-d27e-5cff-9e4f-056dd36be502",
            ),
            [
                "identity--74a17a7d-4559-56ac-882c-abd4e64618bf",
                "identity--5ed2f6ab-d27e-5cff-9e4f-056dd36be502",
            ],
        ),
    ],
)
def test_list_cnas(client, filters: dict, expected_ids: list[str]):
    expected_ids = set(expected_ids)
    url = f"/api/v1/cna/objects/"
    resp = client.get(url, query_params=filters)
    resp_data = resp.json()
    assert all(
        cve["type"] == "identity" for cve in resp_data["objects"]
    ), "response.objects[*].type must always be identity"
    assert {cve["id"] for cve in resp_data["objects"]} == expected_ids
    assert resp_data["total_results_count"] == len(expected_ids)


@pytest.mark.parametrize(
    "created_by_ref",
    [
        "identity--3644753d-7db4-5c2f-af5e-4dc9b8d196ba",
        "identity--3759e3ac-4da9-5c8c-a506-bbd312f35b07",
        "identity--d71c6b17-8860-557e-91fc-602fed648208",
        "identity--2d63a748-daeb-5c11-a121-948a7d78e1c0",
        "identity--64dfee48-e209-5e25-bad4-dcc80d221a85",
        "identity--9092b7ea-75a6-5459-bf2f-3da759bd34a9",
        "identity--5ed2f6ab-d27e-5cff-9e4f-056dd36be502",
        "identity--ac18951b-427a-56a7-9ca2-b9ba414c9708",
    ],
)
def test_created_by_ref(client, created_by_ref):
    url = f"/api/v1/cve/objects/"
    resp = client.get(url, query_params=dict(created_by_ref=created_by_ref))
    resp_data = resp.json()
    assert resp_data["objects"]
    for cve in resp_data["objects"]:
        assert cve["type"] == "vulnerability"
        assert cve["created_by_ref"] == created_by_ref
