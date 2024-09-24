import logging
import os
from pathlib import Path
import shutil
from urllib.parse import urljoin

import requests
from vulmatch.server.models import Job, JobType
from vulmatch.server import models
# from vulmatch.web import models
from celery import group, shared_task, Task
# from .stixifier import vulmatchProcessor, ReportProperties
from tempfile import NamedTemporaryFile
import tempfile
from django.core.files.uploadedfile import InMemoryUploadedFile
from django.core.files.storage import default_storage
import stix2
from datetime import datetime, date, timedelta
import typing
from django.conf import settings
from .celery import app
from stix2arango.stix2arango import Stix2Arango
from arango_cti_processor.cti_processor import ArangoProcessor

if typing.TYPE_CHECKING:
    from ..import settings
POLL_INTERVAL = 1


def new_task(data, type) -> Job:
    job = Job.objects.create(type=type, parameters=data)
    match job.type:
        case models.JobType.ATTACK_UPDATE:
            return run_mitre_task(data, job, f'attack-{data["matrix"]}')
        case models.JobType.CWE_UPDATE:
            return run_mitre_task(data, job, 'cwe')
        case models.JobType.CAPEC_UPDATE:
            return run_mitre_task(data, job, 'capec')
        case models.JobType.CVE_UPDATE:
            return run_nvd_task(data, job, 'cve')
        case models.JobType.CPE_UPDATE:
            return run_nvd_task(data, job, 'cpe')
        case models.JobType.CTI_PROCESSOR:
            return run_acp_task(data, job)

def run_acp_task(data: dict, job: Job):
    options = data.copy()
    options['database'] = settings.ARANGODB_DATABASE
    options['relationship'] = [data['mode']]
    processor = ArangoProcessor(**options)

    task =  acp_task.s(job.id, options)
    (task | remove_temp_and_set_completed.si(None, job.id)).apply_async()
    return job



def run_mitre_task(data, job: Job, mitre_type='cve'):
    version = data['version']
    match mitre_type:
        case 'attack-enterprise':
            url = urljoin(settings.ATTACK_ENTERPRISE_BUCKET_ROOT_PATH, f"enterprise-attack-{version}.json")
            collection_name = 'mitre_attack_enterprise'
        case 'attack-mobile':
            url = urljoin(settings.ATTACK_MOBILE_BUCKET_ROOT_PATH, f"mobile-attack-{version}.json")
            collection_name = 'mitre_attack_mobile'
        case 'attack-ics':
            url = urljoin(settings.ATTACK_ICS_BUCKET_ROOT_PATH, f"ics-attack-{version}.json")
            collection_name = 'mitre_attack_ics'
        case "cwe":
            url = urljoin(settings.CWE_BUCKET_ROOT_PATH, f"cwe-bundle-v{version}.json")
            collection_name = 'mitre_cwe'
        case "capec":
            url = urljoin(settings.CAPEC_BUCKET_ROOT_PATH, f"stix-capec-v{version}.json")
            collection_name = 'mitre_capec'
        case _:
            raise NotImplementedError("Unknown type for mitre task")
    
    temp_dir = tempfile.mkdtemp(suffix=str(job.id), prefix='vulmatch')
    task = download_file.s(url, job.id, temp_dir) | upload_file.s(job.id, collection_name)
    (task | remove_temp_and_set_completed.si(temp_dir, job.id)).apply_async()
    return job

def run_nvd_task(data, job: Job, nvd_type='cve'):
    dates = date_range(data['last_modified_earliest'], data['last_modified_latest'])
    temp_dir = tempfile.mkdtemp(suffix=str(job.id), prefix='vulmatch')
    tasks = group([download_file.s(urljoin(settings.NVD_BUCKET_ROOT_PATH, daily_url(d, nvd_type)), job.id, temp_dir) | upload_file.s(job.id, f'nvd_{nvd_type}') for d in dates])
    (tasks | remove_temp_and_set_completed.si(temp_dir, job.id)).apply_async()
    return job


def date_range(start_date: date, end_date: date):
    start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
    end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
    d = start_date
    while d <= end_date:
        yield d
        d += timedelta(1)

def daily_url(d: date, type='cve'):
    dstr = d.strftime('%Y_%m_%d')
    return f"{type}/{d.strftime('%Y-%m')}/{type}-bundle-{dstr}-00_00_00-{dstr}-23_59_59.json"

@app.task
def download_file(urlpath, job_id, tempdir):
    job = Job.objects.get(pk=job_id)
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
    print('error occured: ', resp.status_code)


@app.task
def upload_file(filename, job_id, collection_name):
    if not filename:
        return
    filename = Path(filename)
    s2a = Stix2Arango(
        file=str(filename),
        database=settings.ARANGODB_DATABASE,
        collection=collection_name,
        stix2arango_note=f"vulmatch-job--{job_id}",
        ignore_embedded_relationships=False,
        host_url=settings.ARANGODB_HOST_URL,
        username=settings.ARANGODB_USERNAME,
        password=settings.ARANGODB_PASSWORD,
    )
    s2a.run()

@app.task
def acp_task(job_id, options):
    job = Job.objects.get(pk=job_id)
    try:
        processor = ArangoProcessor(**options)
        processor.run()
    except BaseException as e:
        job.errors.append(str(e))
    job.save()

@app.task
def remove_temp_and_set_completed(path: str, job_id: str):
    if path:
        logging.info('removing directory: %s', path)
        shutil.rmtree(path, ignore_errors=True)
    job = Job.objects.get(pk=job_id)
    job.state = models.JobState.COMPLETED
    job.save()

