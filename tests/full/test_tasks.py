from unittest.mock import MagicMock, patch, Mock, call
from io import BytesIO
import time
import requests

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


def test_read_into_success():
    """Test successful file reading from streamed response"""
    mock_response = Mock()
    mock_response.headers.get.return_value = '1024'
    mock_response.iter_content.return_value = [b'chunk1', b'chunk2', b'chunk3']
    
    fp = BytesIO()
    downloaded = tasks.read_into(mock_response, fp, chunk_size=1024, read_timeout=10)
    
    assert downloaded == 18  # len('chunk1') + len('chunk2') + len('chunk3')
    assert fp.getvalue() == b'chunk1chunk2chunk3'


def test_read_into_timeout():
    """Test that read_into raises DownloadTimeoutError on timeout"""
    mock_response = Mock()
    mock_response.headers.get.return_value = '10000'
    
    # Simulate slow chunks that cause timeout
    def slow_chunks():
        time.sleep(0.1)
        yield b'chunk1'
        time.sleep(0.1)
        yield b'chunk2'
    
    mock_response.iter_content.return_value = slow_chunks()
    
    fp = BytesIO()
    with pytest.raises(tasks.DownloadTimeoutError) as exc_info:
        tasks.read_into(mock_response, fp, chunk_size=1024, read_timeout=0.05)
    
    assert exc_info.value.downloaded_bytes > 0
    assert exc_info.value.total_bytes == 10000


def test_read_into_no_content_length():
    """Test read_into works without content-length header"""
    mock_response = Mock()
    mock_response.headers.get.return_value = None
    mock_response.iter_content.return_value = [b'data']
    
    fp = BytesIO()
    downloaded = tasks.read_into(mock_response, fp)
    
    assert downloaded == 4
    assert fp.getvalue() == b'data'


@patch('vulmatch.worker.tasks.requests.get')
@patch('vulmatch.worker.tasks.Path')
def test_download_file_success(mock_path, mock_get, job, tmp_path):
    """Test successful file download"""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.url = 'https://example.com/file.json'
    mock_response.headers.get.return_value = '100'
    mock_response.iter_content.return_value = [b'test data']
    mock_get.return_value = mock_response
    
    # Setup mock path
    mock_file = Mock()
    mock_path_instance = Mock()
    mock_path_instance.__truediv__ = Mock(return_value=mock_file)
    mock_path_instance.mkdir = Mock()
    mock_path.return_value = mock_path_instance
    mock_file.open.return_value.__enter__ = Mock(return_value=Mock())
    mock_file.open.return_value.__exit__ = Mock(return_value=False)
    
    tempdir = str(tmp_path)
    result = tasks.download_file('https://example.com/file.json', tempdir, job_id=job.id)
    
    mock_get.assert_called_once_with('https://example.com/file.json', stream=True, timeout=10)
    job.refresh_from_db()
    assert job.state == models.JobState.PROCESSING


@patch('vulmatch.worker.tasks.requests.get')
def test_download_file_404(mock_get, job, tmp_path):
    """Test download_file handles 404 errors"""
    mock_response = Mock()
    mock_response.status_code = 404
    mock_response.url = 'https://example.com/missing.json'
    mock_get.return_value = mock_response
    
    tempdir = str(tmp_path)
    result = tasks.download_file('https://example.com/missing.json', tempdir, job_id=job.id)
    
    job.refresh_from_db()
    assert 'not found' in job.errors[0]
    assert result is None


@patch('vulmatch.worker.tasks.requests.get')
def test_download_file_server_error(mock_get, job, tmp_path):
    """Test download_file handles server errors"""
    mock_response = Mock()
    mock_response.status_code = 500
    mock_response.url = 'https://example.com/error.json'
    mock_get.return_value = mock_response
    
    tempdir = str(tmp_path)
    result = tasks.download_file('https://example.com/error.json', tempdir, job_id=job.id)
    
    job.refresh_from_db()
    assert 'failed with status code: 500' in job.errors[0]
    assert result is None


@patch('vulmatch.worker.tasks.requests.get')
@patch('vulmatch.worker.tasks.Path')
def test_download_file_retries_on_request_exception(mock_path, mock_get, job, tmp_path, eager_celery):
    """Test download_file retries on RequestException"""
    # Setup mock path
    mock_file = Mock()
    mock_path_instance = Mock()
    mock_path_instance.__truediv__ = Mock(return_value=mock_file)
    mock_path_instance.mkdir = Mock()
    mock_path.return_value = mock_path_instance
    
    # First two calls raise RequestException, third succeeds
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.url = 'https://example.com/file.json'
    mock_response.headers.get.return_value = '100'
    mock_response.iter_content.return_value = [b'test data']
    
    mock_get.side_effect = [
        requests.exceptions.RequestException("Network error"),
        requests.exceptions.RequestException("Network error"),
        mock_response
    ]
    
    mock_file.open.return_value.__enter__ = Mock(return_value=Mock())
    mock_file.open.return_value.__exit__ = Mock(return_value=False)
    
    tempdir = str(tmp_path)
    result = tasks.download_file.delay('https://example.com/file.json', tempdir, job_id=job.id)
    
    # Should have been called 3 times (2 failures + 1 success)
    assert mock_get.call_count == 3
    assert result.get() == str(mock_file)


@patch('vulmatch.worker.tasks.requests.get')
@patch('vulmatch.worker.tasks.Path')
@patch('vulmatch.worker.tasks.read_into')
def test_download_file_retries_on_download_timeout(mock_read_into, mock_path, mock_get, job, tmp_path, eager_celery):
    """Test download_file retries on DownloadTimeoutError"""
    # Setup mock path
    mock_file = Mock()
    mock_path_instance = Mock()
    mock_path_instance.__truediv__ = Mock(return_value=mock_file)
    mock_path_instance.mkdir = Mock()
    mock_path.return_value = mock_path_instance
    
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.url = 'https://example.com/file.json'
    mock_get.return_value = mock_response
    
    # First two calls timeout, third succeeds
    mock_read_into.side_effect = [
        tasks.DownloadTimeoutError(1000, 10000),
        tasks.DownloadTimeoutError(2000, 10000),
        5000  # Success
    ]
    
    mock_file.open.return_value.__enter__ = Mock(return_value=Mock())
    mock_file.open.return_value.__exit__ = Mock(return_value=False)
    
    tempdir = str(tmp_path)
    result = tasks.download_file.delay('https://example.com/file.json', tempdir, job_id=job.id)
    
    # Should have been called 3 times (2 failures + 1 success)
    assert mock_read_into.call_count == 3


@patch('vulmatch.worker.tasks.requests.get')
def test_download_file_max_retries_exceeded(mock_get, job, tmp_path, eager_celery):
    """Test download_file fails after max retries"""
    mock_get.side_effect = requests.exceptions.RequestException("Network error")
    
    tempdir = str(tmp_path)
    
    # with pytest.raises(requests.exceptions.RequestException):
    r = tasks.download_file.delay('https://example.com/file.json', tempdir, job_id=job.id)
    
    # Should have been called 4 times (1 initial + 3 retries as per max_retries=3)
    assert mock_get.call_count == 4
    assert r.failed()

