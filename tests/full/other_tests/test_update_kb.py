from unittest.mock import patch

import pytest

from vulmatch.server import models


class TestKBSyncView:
    # Assuming JobType.SYNC_KNOWLEDGEBASE is added to vulmatch/server/models.py

    def test_update_kb_returns_job(self, client, celery_no_eager):
        # Test for capec
        resp = client.patch("/api/v1/tasks/sync-knowledgebases/capec/")
        assert resp.status_code == 201
        data = resp.json()
        assert data["type"] == "sync-knowledgebase"
        assert data["parameters"]["knowledgebase"] == "capec"

        # Test for cwe
        resp = client.patch("/api/v1/tasks/sync-knowledgebases/cwe/")
        assert resp.status_code == 201
        data = resp.json()
        assert data["type"] == "sync-knowledgebase"
        assert data["parameters"]["knowledgebase"] == "cwe"

        # Test for attack-enterprise
        resp = client.patch("/api/v1/tasks/sync-knowledgebases/attack-enterprise/")
        assert resp.status_code == 201
        data = resp.json()
        assert data["type"] == "sync-knowledgebase"
        assert data["parameters"]["knowledgebase"] == "attack-enterprise"

    @pytest.mark.parametrize(
        "kb",
        [
            pytest.param("cve", id="valid but not supported"),
            pytest.param("cve-cve", id="invalid"),
        ],
    )
    def test_update_kb_fails_on_bad_knowledgebase(self, client, kb):
        resp = client.patch(f"/api/v1/tasks/sync-knowledgebases/{kb}/")
        assert resp.status_code == 404

    @patch("vulmatch.worker.tasks.kb_sync.run_on_kb_and_collection")
    def test_update_kb_calls_kbsync_success(self, mock_kbsync, client):
        mock_kbsync.return_value = 150, 25  # processed_count, updated_count

        resp = client.patch("/api/v1/tasks/sync-knowledgebases/cwe/")
        assert resp.status_code == 201

        mock_kbsync.assert_called_once()
        args, kwargs = mock_kbsync.call_args
        assert args == ("nvd_cve_vertex_collection", "cwe")
        assert "update_time" in kwargs

        job_data = resp.json()
        job = models.Job.objects.get(pk=job_data["id"])
        assert job.state == models.JobState.COMPLETED, job_data
        assert job.completion_time != None
        assert job.parameters["processed_items"] == 150
        assert job.parameters["updated_items"] == 25
        assert not job.errors

    @patch("vulmatch.worker.tasks.kb_sync.run_on_kb_and_collection")
    def test_update_kb_calls_kbsync_fails(self, mock_kbsync, client):
        mock_kbsync.side_effect = ValueError("Simulated KB sync failure")
        with pytest.raises(ValueError):
            client.patch("/api/v1/tasks/sync-knowledgebases/attack-enterprise/")

        mock_kbsync.assert_called_once()
        args, kwargs = mock_kbsync.call_args
        assert args == ("nvd_cve_vertex_collection", "attack-enterprise")
        assert "update_time" in kwargs

        job = models.Job.objects.all().last()
        assert job.state == models.JobState.FAILED
        assert len(job.errors) == 1
        assert "Simulated KB sync failure" in job.errors[0]
        assert job.completion_time != None
