import json
import logging
import os
from pathlib import Path
import shutil
import time
from types import SimpleNamespace
from urllib.parse import urljoin
import pypdl

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
from datetime import UTC, datetime, date, timedelta
import typing
from django.conf import settings

from vulmatch.worker.utils import add_vulmatch_extras
from .celery import app
from stix2arango.stix2arango import Stix2Arango
from arango_cve_processor.managers import RELATION_MANAGERS as CVE_RELATION_MANAGERS
from dogesec_commons.objects import kb_sync
from arango_cve_processor.__main__ import run_all as run_task_with_acp
import acvep
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
        case models.JobType.SYNC_KNOWLEDGEBASE:
            task = update_knowledgebase.si(job_id=job.id) | remove_temp_and_set_completed.si(None, job_id=job.id)
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
    temp_dir = get_temp_dir_for_job(job.id)
    task = resolve_meta_for_job.si(job_id=job.id)
    task |= process_resolved_bundles.si(temp_dir=temp_dir, nvd_type=nvd_type, job_id=job.id)
    task |= remove_temp_and_set_completed.si(temp_dir, job_id=job.id)
    return task

def resolve_meta(job: Job, dates: list[date]):
    bundles = []
    try:
        for d in dates:
            if is_v2_date(d):
                bundles.extend(get_bundles_for_meta(d))
                continue
            day_url = urljoin(settings.CVE2STIX_BUCKET_ROOT_PATH, daily_url(d))
            resp = requests.head(day_url, timeout=10)
            content_length = int(resp.headers.get("content-length", 0))
            if content_length and content_length == 2:
                continue
            if resp.status_code == 200:
                bundles.append(
                    {
                        "date": d.strftime("%Y-%m-%d"),
                        "url": day_url,
                        "size": content_length or None,
                    }
                )
            elif resp.status_code == 404: 
                if d >= date(2026, 6, 11): # see https://github.com/muchdogesec/vulmatch/issues/352:
                    raise MissingFileError(f"File not found for {day_url}")
                else:
                    job.errors.append(f"File not found for {day_url}")
            else:
                raise Exception(f"Fetch failed for {day_url}: {resp.status_code}")
    finally:
        job.parameters = job.parameters or {}
        process = job.parameters.get('process') or {}
        process['processed_bundles'] = 0
        process['total_bundles'] = len(bundles)
        process['bundles'] = bundles
        job.parameters['process'] = process
        job.save(update_fields=["parameters", "errors"])
    return bundles


def get_upload_params(job: Job):
    params = (job.parameters or {}).copy()
    params.pop('process', None)
    return params


def build_download_upload_chain(bundles: list[dict], temp_dir: str, job: Job, nvd_type: str = 'cve'):
    task_chain = []
    upload_params = get_upload_params(job)
    for bundle in bundles:
        bundle_date = datetime.strptime(bundle['date'], '%Y-%m-%d').date()
        task = download_file.si(bundle['url'], temp_dir, job_id=job.id, file_date=bundle_date)
        task |= upload_file.s(
            f'nvd_{nvd_type}',
            stix2arango_note=f"vulmatch-{nvd_type}-date={bundle['date']}",
            job_id=job.id,
            params=upload_params,
            bundle=bundle,
        )
        task.set_immutable(True)
        task_chain.append(task)
    return chain(task_chain)

def get_bundles_for_meta(d: date):
    day_url = urljoin(settings.CVE2STIX_BUCKET_ROOT_PATH, v2_url(d))
    bundles = []
    meta_url = day_url + "/meta.json"
    resp = requests.get(meta_url, timeout=10)
    if resp.status_code == 200:
        meta = resp.json()
        for bundle in meta["bundles"]:
            bundles.append(
                {
                    "date": d.isoformat(),
                    "url": urljoin(meta_url, bundle["name"]),
                    "total_objects": sum(bundle["object_counts"].values()),
                }
            )
    else:
        raise Exception(f"Failed to fetch meta.json for {d}: {resp.status_code}")
    return bundles


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

def v2_url(d: date):
    return f"v2/{d.strftime('%Y-%m')}/cves-{d.strftime('%Y%m%d')}"

def is_v2_date(d: date):
    return d >= date(2026, 7, 11) or d == date(2026, 6, 17)


class CustomTask(Task):
    def on_failure(self, exc, task_id, args, kwargs, einfo):
        job = Job.objects.get(pk=kwargs['job_id'])
        job.state = models.JobState.FAILED
        job.errors.append(f"celery task {self.name} failed with: {exc}; {args=}, {kwargs=}")
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

class MissingFileError(Exception):
    pass


@app.task(bind=True, base=CustomTask)
def download_file(self, urlpath, tempdir, job_id=None, file_date: date = None):
    tempdir = Path(tempdir)
    tempdir.mkdir(parents=True, exist_ok=True)
    logging.info("downloading bundle at `%s`", urlpath)
    job = Job.objects.get(pk=job_id)
    if job.state == models.JobState.PENDING:
        job.state = models.JobState.PROCESSING
        job.save()
    dl = pypdl.Pypdl(max_concurrent=10)
    filename = str(tempdir / urlpath.split("/")[-1])
    dl.start(
        url=urlpath,
        file_path=filename,
        retries=5,
        block=True,
        display=False,
    )
    return filename


@app.task(base=CustomTask)
def upload_file(filename, collection_name, stix2arango_note=None, job_id=None, params=dict(), bundle=None):
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
        create_collection=False,
        create_db=False,
        **params
    )
    s2a.add_object_alter_fn(add_vulmatch_extras)
    s2a.run()

    job = Job.objects.get(pk=job_id)
    job.parameters = job.parameters or {}
    process = job.parameters.get('process') or {}
    process['processed_bundles'] = process.get('processed_bundles', 0) + 1
    job.parameters['process'] = process
    job.save(update_fields=["parameters"])

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
         FOR doc in nvd_cve_vertex_collection OPTIONS {indexHint: "vulmatch_products", forceIndexHint: true}
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
    for k in ['start_date', 'end_date']:
        if k in options:
            options[k] = datetime.strptime(options[k], '%Y-%m-%d').date()
    run_task_with_acp(**options)


@app.task(base=CustomTask)
def resolve_meta_for_job(job_id=None):
    job = Job.objects.get(pk=job_id)
    dates = list(date_range(job.parameters['last_modified_earliest'], job.parameters['last_modified_latest']))
    return resolve_meta(job, dates)


@app.task(bind=True, base=CustomTask)
def process_resolved_bundles(self, temp_dir: str, nvd_type: str = 'cve', job_id=None):
    job = Job.objects.get(pk=job_id)
    process = (job.parameters or {}).get('process') or {}
    bundles = process.get('bundles', [])
    if not bundles:
        return None
    return self.replace(build_download_upload_chain(bundles, temp_dir, job, nvd_type=nvd_type))

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


@app.task(base=CustomTask, bind=True)
def update_knowledgebase(self, job_id=None):
    job = Job.objects.get(pk=job_id)
    job.parameters.update(
        processed_items=0,
        updated_items=0,
    )
    job.state = models.JobState.PROCESSING
    job.save(update_fields=["parameters", "state"])
    try:
        # In vulmatch, the main collection for STIX objects is 'nvd_cve_vertex_collection'
        collection_name = "nvd_cve_vertex_collection"
        logging.info(f"Processing {collection_name} for knowledgebase {job.parameters['knowledgebase']}")
        update_time = datetime.now(UTC).isoformat()
        # kb_sync.run_on_kb_and_collection expects the collection name and knowledgebase name
        processed_count, updated_count = kb_sync.run_on_kb_and_collection(collection_name, job.parameters['knowledgebase'], update_time=update_time)
        job.parameters['processed_items'] = processed_count
        job.parameters['updated_items'] = updated_count
        job.save(update_fields=["parameters"])
    except Exception as e:
        raise
