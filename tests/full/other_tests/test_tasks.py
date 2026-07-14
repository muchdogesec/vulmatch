from datetime import date
from unittest.mock import patch, Mock
from io import BytesIO
import time

import pytest
from vulmatch.server import models
from vulmatch.worker import tasks


@pytest.fixture
def job():
    return models.Job.objects.create(parameters={})


def test_startup_tasks():
    with patch("vulmatch.worker.tasks.refresh_products_cache") as mock_referesh_cache:
        tasks.mark_old_jobs_as_failed_and_rebuild_cache()
        mock_referesh_cache.assert_called_once()


def test_cache_refreshed_after_completion(job):
    with patch("vulmatch.worker.tasks.refresh_products_cache") as mock_referesh_cache:
        tasks.remove_temp_and_set_completed("", job.id)
        mock_referesh_cache.assert_called_once()


def test_cache_refreshed_on_task_failure(job, eager_celery):
    t = tasks.CustomTask()
    with patch(
        "vulmatch.worker.tasks.refresh_products_cache.run"
    ) as mock_referesh_cache:
        t.on_failure(Exception(), "", [], kwargs=dict(job_id=job.id), einfo="")
        mock_referesh_cache.assert_called_once()


@patch('vulmatch.worker.tasks.pypdl.Pypdl')
def test_download_file_success(mock_pypdl, job, tmp_path):
    """Test successful file download delegates to pypdl with expected args."""
    tempdir = str(tmp_path)
    result = tasks.download_file.run('https://example.com/file.json', tempdir, job_id=job.id)

    expected_file = str(tmp_path / 'file.json')
    mock_pypdl.assert_called_once_with(max_concurrent=10)
    mock_pypdl.return_value.start.assert_called_once_with(
        url='https://example.com/file.json',
        file_path=expected_file,
        retries=5,
        block=True,
        display=False,
    )
    assert result == expected_file
    job.refresh_from_db()
    assert job.state == models.JobState.PROCESSING


@patch('vulmatch.worker.tasks.pypdl.Pypdl')
def test_download_file_keeps_processing_when_already_started(mock_pypdl, job, tmp_path):
    """Test that non-pending jobs are not state-reset by download_file."""
    job.state = models.JobState.PROCESSING
    job.save(update_fields=['state'])

    tempdir = str(tmp_path)
    tasks.download_file.run('https://example.com/file.json', tempdir, job_id=job.id)

    mock_pypdl.return_value.start.assert_called_once()
    job.refresh_from_db()
    assert job.state == models.JobState.PROCESSING


@patch('vulmatch.worker.tasks.pypdl.Pypdl')
def test_download_file_pypdl_error_fails_task(mock_pypdl, job, tmp_path, eager_celery):
    """Test download_file surfaces pypdl failures and does not implement local retry logic."""
    mock_pypdl.return_value.start.side_effect = RuntimeError('download failed')

    tempdir = str(tmp_path)
    result = tasks.download_file.delay('https://example.com/file.json', tempdir, job_id=job.id)

    assert result.failed()
    assert mock_pypdl.return_value.start.call_count == 1
    job.refresh_from_db()
    assert job.state == models.JobState.FAILED


def test_run_nvd_task_meta_then_process_then_cleanup():
    job = models.Job.objects.create(
        type=models.JobType.CVE_UPDATE,
        parameters={
            "last_modified_earliest": "2026-07-01",
            "last_modified_latest": "2026-07-02",
        },
    )

    task_chain = tasks.run_nvd_task(job.parameters, job, "cve")

    assert len(task_chain.tasks) == 3
    assert task_chain.tasks[0].task == "vulmatch.worker.tasks.resolve_meta_for_job"
    assert task_chain.tasks[1].task == "vulmatch.worker.tasks.process_resolved_bundles"
    assert task_chain.tasks[2].task == "vulmatch.worker.tasks.remove_temp_and_set_completed"
    assert task_chain.tasks[2].args[0] == tasks.get_temp_dir_for_job(job.id)


def test_resolve_meta_for_job_uses_date_range():
    job = models.Job.objects.create(
        parameters={
            "last_modified_earliest": "2026-07-01",
            "last_modified_latest": "2026-07-03",
        }
    )

    with patch("vulmatch.worker.tasks.resolve_meta", return_value=[]) as mock_resolve_meta:
        result = tasks.resolve_meta_for_job(job_id=job.id)

    assert result == []
    mock_resolve_meta.assert_called_once()
    called_job, called_dates = mock_resolve_meta.call_args.args
    assert called_job.id == job.id
    assert called_dates == [date(2026, 7, 1), date(2026, 7, 2), date(2026, 7, 3)]


def test_process_resolved_bundles_replaces_with_built_chain():
    job = models.Job.objects.create(
        parameters={
            "process": {
                "bundles": [
                    {"date": "2026-07-01", "url": "https://example.com/a.json"},
                ],
                "processed_bundles": 0,
                "total_bundles": 1,
            }
        }
    )

    built_chain = Mock(name="built_chain")
    with patch("vulmatch.worker.tasks.build_download_upload_chain", return_value=built_chain) as mock_builder:
        with patch.object(tasks.process_resolved_bundles, "replace", return_value="replaced") as mock_replace:
            result = tasks.process_resolved_bundles.run(temp_dir="/tmp/vulmatch", nvd_type="cve", job_id=job.id)

    assert result == "replaced"
    mock_builder.assert_called_once()
    mock_replace.assert_called_once_with(built_chain)


@patch("vulmatch.worker.tasks.Stix2Arango")
def test_upload_file_updates_process(mock_stix2arango, job):
    job.parameters = {
        "process": {
            "processed_bundles": 0,
            "total_bundles": 2,
        }
    }
    job.save(update_fields=["parameters"])

    bundle = {"date": "2026-07-01", "url": "https://example.com/a.json"}
    tasks.upload_file.run(
        filename="/tmp/file.json",
        collection_name="nvd_cve",
        job_id=job.id,
        params={},
        bundle=bundle,
    )

    job.refresh_from_db()
    assert "uploaded" not in job.parameters
    assert job.parameters["process"]["processed_bundles"] == 1
    assert job.parameters["process"]["total_bundles"] == 2
    assert "bundles" not in job.parameters["process"]

