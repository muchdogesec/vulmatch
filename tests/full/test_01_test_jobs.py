import pytest


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
def test_task(db, client, path, payload):
    new_task_resp = client.post(f"/api/v1/{path}/", data=payload, content_type="application/json")

    assert new_task_resp.status_code == 201
    task_data = new_task_resp.json()
    job_id =  task_data['id']
    job_resp = client.get(f"/api/v1/jobs/{job_id}/")
    assert job_resp.status_code == 200
    assert job_resp.data['state'] == 'completed'