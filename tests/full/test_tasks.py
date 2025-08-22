from unittest.mock import MagicMock, patch

import pytest
from vulmatch.server import models
from vulmatch.worker import tasks

@pytest.fixture
def job():
    return models.Job.objects.create(parameters={})

def test_startup_tasks():
    with patch('vulmatch.worker.tasks.refresh_products_cache') as mock_referesh_cache:
        tasks.mark_old_jobs_as_failed_and_rebuild_cache()
        mock_referesh_cache.assert_called_once()

def test_cache_refreshed_after_completion(job):
    with patch('vulmatch.worker.tasks.refresh_products_cache') as mock_referesh_cache:
        tasks.remove_temp_and_set_completed('', job.id)
        mock_referesh_cache.assert_called_once()

def test_cache_refreshed_on_task_failure(job, eager_celery):
    t = tasks.CustomTask()
    with patch('vulmatch.worker.tasks.refresh_products_cache.run') as mock_referesh_cache:
        t.on_failure(Exception(), "", [], kwargs=dict(job_id=job.id), einfo="")
        mock_referesh_cache.assert_called_once()
