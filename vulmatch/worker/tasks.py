import json
import logging
import os
from pathlib import Path
import shutil
from types import SimpleNamespace
from urllib.parse import urljoin

import requests
from vulmatch.server.arango_helpers import VulmatchDBHelper
from vulmatch.server.models import Job, JobType
from vulmatch.server import models
# from vulmatch.web import models
from celery import chain, group, shared_task, Task
# from .stixifier import vulmatchProcessor, ReportProperties
from tempfile import NamedTemporaryFile
import tempfile
from django.core.files.uploadedfile import InMemoryUploadedFile
from django.core.files.storage import default_storage
import stix2
from datetime import datetime, date, timedelta
import typing
from django.conf import settings

from vulmatch.worker.utils import add_cvss_score_to_cve_object
from .celery import app
from stix2arango.stix2arango import Stix2Arango
from arango_cve_processor.managers import RELATION_MANAGERS as CVE_RELATION_MANAGERS
from arango_cve_processor.__main__ import run_all as run_task_with_acp
import logging

if typing.TYPE_CHECKING:
    from ..import settings
POLL_INTERVAL = 1


def create_celery_task_from_job(job: Job):
    data = job.parameters
    match job.type:
        case models.JobType.CVE_UPDATE:
            task = run_nvd_task(data, job, 'cve')
        case models.JobType.CVE_PROCESSOR:
            task = run_acp_task(data, job)
    task.set_immutable(True)
    return task

def new_task(data, type, job=None) -> Job:
    job = Job.objects.create(type=type, parameters=data)
    create_celery_task_from_job(job).apply_async()
    return job

def run_acp_task(data: dict, job: Job):
    options = data.copy()
    options['database'] = settings.ARANGODB_DATABASE
    options['modes'] = [data['mode']]

    task =  acp_task.s(options, job_id=job.id)
    return (task | remove_temp_and_set_completed.si(None, job_id=job.id))

    
def run_nvd_task(data, job: Job, nvd_type='cve'):
    dates = date_range(data['last_modified_earliest'], data['last_modified_latest'])
    temp_dir = get_temp_dir_for_job(job.id)
    tasks = []
    for d in dates:
        url = urljoin(settings.CVE2STIX_BUCKET_ROOT_PATH, daily_url(d, nvd_type))
        task = download_file.si(url, temp_dir, job_id=job.id)
        task |= upload_file.s(f'nvd_{nvd_type}', stix2arango_note=f"vulmatch-{nvd_type}-date={d.strftime('%Y-%m-%d')}", job_id=job.id, params=job.parameters)
        task.set_immutable(True)
        tasks.append(task)
    tasks = chain(tasks)
    return (tasks | remove_temp_and_set_completed.si(temp_dir, job_id=job.id))

def get_temp_dir_for_job(job_id):
    return str(Path(tempfile.gettempdir())/f"vulmatch/nvd-cve--{str(job_id)}")


def date_range(start_date: date, end_date: date):
    start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
    end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
    d = start_date
    while d <= end_date:
        yield d
        d += timedelta(1)

def daily_url(d: date, type='cve'):
    dstr = d.strftime('%Y_%m_%d')
    return f"{d.strftime('%Y-%m')}/{type}-bundle-{dstr}-00_00_00-{dstr}-23_59_59.json"


class CustomTask(Task):
    def on_failure(self, exc, task_id, args, kwargs, einfo):
        job = Job.objects.get(pk=kwargs['job_id'])
        job.state = models.JobState.FAILED
        job.errors.append(f"celery task {self.name} failed with: {exc}")
        logging.exception(exc, exc_info=True)
        job.save()
        try:
            logging.info('removing directory')
            path = get_temp_dir_for_job(job.id)
            shutil.rmtree(path)
            logging.info(f'directory `{path}` removed')
        except Exception as e:
            logging.error(f'delete dir failed: {e}')
        refresh_products_cache.si().apply_async() #build cache after failure
        return super().on_failure(exc, task_id, args, kwargs, einfo)
    
    def before_start(self, task_id, args, kwargs):
        if not kwargs.get('job_id'):
            raise Exception("rejected: `job_id` not in kwargs")
        return super().before_start(task_id, args, kwargs)
    

@app.task(base=CustomTask)
def download_file(urlpath, tempdir, job_id=None):
    Path(tempdir).mkdir(parents=True, exist_ok=True)
    logging.info('downloading bundle at `%s`', urlpath)
    job = Job.objects.get(pk=job_id)
    if job.state == models.JobState.PENDING:
        job.state = models.JobState.PROCESSING
        job.save()
    resp = requests.get(urlpath)
    if resp.status_code == 200:
        filename = Path(tempdir)/resp.url.split('/')[-1]
        filename.write_bytes(resp.content)
        return str(filename)
    elif resp.status_code == 404:
        job.errors.append(f'{resp.url} not found')
    else:
        job.errors.append(f'{resp.url} failed with status code: {resp.status_code}')
    job.save()
    logging.info('error occured: %d', resp.status_code)


@app.task(base=CustomTask)
def upload_file(filename, collection_name, stix2arango_note=None, job_id=None, params=dict()):
    if not filename:
        return
    if not stix2arango_note:
        stix2arango_note = f"vulmatch-job--{job_id}"

    logging.info('uploading %s with note: %s', filename, stix2arango_note)
    s2a = Stix2Arango(
        file=str(filename),
        database=settings.ARANGODB_DATABASE,
        collection=collection_name,
        stix2arango_note=stix2arango_note,
        host_url=settings.ARANGODB_HOST_URL,
        username=settings.ARANGODB_USERNAME,
        password=settings.ARANGODB_PASSWORD,
        skip_default_indexes=True,
        is_large_file=True,
        **params
    )
    s2a.add_object_alter_fn(add_cvss_score_to_cve_object)
    s2a.run()

@app.task
def refresh_products_cache():
    collection = 'nvd_cve_vertex_collection'
    helper = VulmatchDBHelper(collection, SimpleNamespace(GET=dict(), query_params=SimpleNamespace(dict=dict)))
    new_rev = helper.db.collection(collection).revision()
    db_rev = models.ProductRevision.get_revision()
    old_rev = db_rev.revision
    if new_rev == old_rev:
        return False
    logging.info(f"revision has changed ({old_rev} -> {new_rev}), rebuilding products cache")
    logging.info(f"Last revised: {db_rev.updated}")
    query = """
        FOR doc in nvd_cve_vertex_collection OPTIONS {indexHint: "cpe_search_inv", forceIndexHint: true}
        FILTER doc.type == 'software' AND doc._is_latest == TRUE 
        COLLECT vendor = doc.x_cpe_struct.vendor, product = doc.x_cpe_struct.product WITH COUNT INTO len
        SORT NULL
        RETURN [vendor, product, len]
    """
    results = helper.execute_query(query, paginate=False)
    products: list[models.Products] = []
    for p in results:
        products.append(models.Products(vendor=p[0], product=p[1], softwares_count=p[2]))
        products[-1].set_id()
    models.Products.objects.bulk_create(products, ignore_conflicts=True, batch_size=1000)
    models.Products.objects.bulk_update(products, fields=['softwares_count'], batch_size=1000)
    models.ProductRevision.set_revision(new_rev)
    logging.info(f"product cache updated ({old_rev} -> {new_rev})")
    return True


@app.task(base=CustomTask)
def acp_task(options, job_id=None):
    job = Job.objects.get(pk=job_id)
    run_task_with_acp(**options)

@app.task(base=CustomTask)
def remove_temp_and_set_completed(path: str, job_id: str=None):
    if path:
        logging.info('removing directory: %s', path)
        shutil.rmtree(path, ignore_errors=True)
    job = Job.objects.get(pk=job_id)
    job.state = models.JobState.COMPLETED
    job.save()
    refresh_products_cache() # build cache after task completion



from celery import signals
@signals.worker_ready.connect
def mark_old_jobs_as_failed_and_rebuild_cache(**kwargs):
    Job.objects.filter(state=models.JobState.PENDING).update(state = models.JobState.FAILED, errors=["marked as failed on startup"])
    refresh_products_cache() # build cache on program start