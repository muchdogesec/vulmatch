import random
import time
from unittest.mock import patch
from urllib.parse import urlencode
import uuid
import schemathesis
import pytest
from schemathesis.core.transport import Response as SchemathesisResponse
from vulmatch.wsgi import application as wsgi_app
from rest_framework.response import Response as DRFResponse
from hypothesis import settings
from hypothesis import strategies
from schemathesis.specs.openapi.checks import negative_data_rejection, positive_data_acceptance

schema = schemathesis.openapi.from_wsgi("/api/schema/?format=json", wsgi_app)
schema.config.base_url = "http://localhost:8005/"

@pytest.fixture(autouse=True)
def non_eager_celery():
    from vulmatch.worker.celery import app
    app.conf.task_always_eager = False
    yield

object_ids = [
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
        "cpe:2.3:a:mongodb:c_driver:1.15.0:*:*:*:*:mongodb:*:*",
        "cpe:2.3:a:gitlab:gitlab:17.6.0:*:*:*:enterprise:*:*:*",
        "cpe:2.3:a:ays-pro:quiz_maker:1.1.0:*:*:*:*:wordpress:*:*",
        "cpe:2.3:o:juniper:junos:23.1:-:*:*:*:*:*:*",
        "cpe:2.3:a:ays-pro:quiz_maker:5.2.1:*:*:*:*:wordpress:*:*",
        "cpe:2.3:a:ays-pro:quiz_maker:5.1.3:*:*:*:*:wordpress:*:*",
        "CWE-24",
        "weakness--0021e0ca-b8bf-5625-b106-d35c48f66fea" "CAPEC-87",
        "attack-pattern--00268a75-3243-477d-9166-8c78fddf6df6" "T1037",
        "attack-pattern--03259939-0b57-482f-8eb5-87c0e0d54334",
    ]
    
object_ids_st = strategies.sampled_from(
    object_ids
)

@pytest.fixture(autouse=True)
def override_transport(monkeypatch):
    ## patch transport.get
    from schemathesis import transport
    from tests.utils import Transport
    monkeypatch.setattr(transport, "get", lambda _: Transport())

@pytest.mark.django_db(transaction=True)
@schema.given(
    object_id=strategies.sampled_from([x for x in object_ids if '--' in x]),
    capec_id=object_ids_st,
    attack_id=object_ids_st,
    cwe_id=object_ids_st,
    cve_id=object_ids_st,
    cpe_id=object_ids_st,
)
@schema.exclude(method="POST").exclude(path='/api/healthcheck/service/').exclude(path="/api/v1/cve/objects/{cve_id}/").parametrize()
def test_api(case: schemathesis.Case, **kwargs):
    for k, v in kwargs.items():
        if k in case.path_parameters:
            case.path_parameters[k] = v
    case.call_and_validate(excluded_checks=[negative_data_rejection, positive_data_acceptance])

@schema.include(path="/api/v1/cve/objects/{cve_id}/").parametrize()
def test_retrieve_cve(case: schemathesis.Case, **kwargs):
    case.path_parameters['cve_id'] = random.choice(object_ids)
    case.call_and_validate(excluded_checks=[negative_data_rejection, positive_data_acceptance])


@pytest.mark.django_db(transaction=True)
@schema.include(method="POST").parametrize()
@patch('vulmatch.worker.tasks.CustomTask.run')
def test_imports(mock, case: schemathesis.Case):
    case.call_and_validate(excluded_checks=[negative_data_rejection, positive_data_acceptance])
