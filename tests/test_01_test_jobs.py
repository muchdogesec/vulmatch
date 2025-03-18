import io
import os
import time
from types import SimpleNamespace
import unittest, pytest
from urllib.parse import urljoin

from tests.utils import remove_unknown_keys, wait_for_jobs

base_url = os.environ["SERVICE_BASE_URL"]
import requests


@pytest.mark.parametrize(["path", "payload"], [
    pytest.param("cve", dict(last_modified_earliest="2024-12-31", last_modified_latest="2024-12-31"), id="import cves 1"),
    pytest.param("cve", dict(last_modified_earliest="2024-12-27", last_modified_latest="2024-12-28"), id="import cves 2"),
    pytest.param("cve", dict(last_modified_earliest="2024-01-12", last_modified_latest="2024-01-12"), id="import cves 3"),
    pytest.param("arango-cve-processor/cve-cwe", dict()),
    pytest.param("arango-cve-processor/cve-capec", dict(created_min="2024-12-31")),
    pytest.param("arango-cve-processor/cve-attack", dict(created_min="2024-12-31")),
    pytest.param("arango-cve-processor/cve-epss", dict()),
    pytest.param("arango-cve-processor/cve-kev", dict()),
])
def test_task(path, payload):
    new_task_resp = requests.post(urljoin(base_url, f"api/v1/{path}/"), json=payload)

    assert new_task_resp.status_code == 201
    task_data = new_task_resp.json()

    job_data = wait_for_jobs(task_data["id"])