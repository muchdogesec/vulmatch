from datetime import datetime, date
import uuid, itertools, logging, sys, typing
import django
django.setup()
from django.conf import settings

if typing.TYPE_CHECKING:
    from ..import settings


from vulmatch.server.models import Job, JobType
from .tasks import new_task, create_celery_task_from_job, app, log
from celery import group, chain
logging.basicConfig(level=logging.INFO)
from stix2arango.stix2arango import Stix2Arango

from arango_cti_processor.config import MODE_COLLECTION_MAP

START_ID = 0xabcd


CXE_START_DATE = '2024-09-01'
CXE_END_DATE = datetime.now().date().strftime('%Y-%m-%d')


ATTACK_MATRIXES = {
    'mobile':  [
        "1_0", "2_0", "3_0", "4_0", "5_0", "5_1", "5_2", "6_0", "6_1", "6_2", "6_3",
        "7_0", "7_1", "7_2", "8_0", "8_1", "8_2", "9_0", "10_0", "10_1", "11_0-beta", 
        "11_1-beta", "11_2-beta", "11_3", "12_0", "12_1", "13_0", "13_1", "14_0", "14_1", 
        "15_0", "15_1"
    ],
    'ics': [
        "8_0", "8_1", "8_2", "9_0", "10_0", "10_1", "11_0", 
        "11_1", "11_2", "11_3", "12_0", "12_1", "13_0", "13_1", "14_0", "14_1", 
        "15_0", "15_1"
    ],
    'enterprise': [
        "1_0", "2_0", "3_0", "4_0", "5_0", "5_1", "5_2", "6_0", "6_1", "6_2", "6_3",
        "7_0", "7_1", "7_2", "8_0", "8_1", "8_2", "9_0", "10_0", "10_1", "11_0", 
        "11_1", "11_2", "11_3", "12_0", "12_1", "13_0", "13_1", "14_0", "14_1", 
        "15_0", "15_1"
    ]
}
MITRE_VERSIONS = {
    JobType.CAPEC_UPDATE: [
        "3_5",
        "3_6",
        "3_7",
        "3_8",
        "3_9"
    ],
    JobType.CWE_UPDATE: [
        "4_5",
        "4_6",
        "4_7",
        "4_8",
        "4_9",
        "4_10",
        "4_11",
        "4_12",
        "4_13",
        "4_14",
        "4_15",
    ],
}

ACP_MODES = list(MODE_COLLECTION_MAP)

collections_to_create = ['mitre_capec', 'mitre_attack_mobile', 'mitre_cwe', 'mitre_attack_ics', 'nvd_cve', 'nvd_cpe', 'mitre_attack_enterprise', 'sigma_rules']

def has_run():
    try:
        return Job.objects.get(pk=uuid.UUID(int=START_ID))
    except:
        return False
    
def run_all():
    jobs: list[Job] = []
    job_counter = itertools.count(START_ID)
    def get_job(type, data):
        job = Job.objects.create(id=uuid.UUID(int=next(job_counter)), parameters=data, type=type)
        task = create_celery_task_from_job(job)
        task |= log.si(f'finished task {task}, {job.type=}, {job.parameters=}')
        task.set_immutable(True)
        return task

    #create db/collections
    for c in collections_to_create:
        Stix2Arango(settings.ARANGODB_DATABASE, collection=c, file='no-file', username=settings.ARANGODB_USERNAME, password=settings.ARANGODB_PASSWORD, host_url=settings.ARANGODB_HOST_URL)
    # run cve
    jobs.extend([
                get_job(JobType.CVE_UPDATE, dict(last_modified_earliest=CXE_START_DATE, last_modified_latest=CXE_END_DATE)),
                get_job(JobType.CPE_UPDATE, dict(last_modified_earliest=CXE_START_DATE, last_modified_latest=CXE_END_DATE))
    ])
    #run attacks
    for matrix, versions in ATTACK_MATRIXES.items():
        mitre_task = []
        for version in versions:
            mitre_task.append(
                get_job(JobType.ATTACK_UPDATE, dict(matrix=matrix, version=version))
            )
        jobs.append(chain(mitre_task))
    
    #run capec and cwe
    for mitre_job_type, versions in MITRE_VERSIONS.items():
        mitre_task = []
        for version in versions:
            mitre_task.append(
                get_job(mitre_job_type, dict(version=version))
            )
        jobs.append(chain(mitre_task))


    for job in jobs:
        job.set_immutable(True)
    
    final_chain = [group(jobs)]
    for acp_mode in ACP_MODES:
        final_chain.append(get_job(JobType.CTI_PROCESSOR, {'mode': acp_mode}))

    final_chain_result = chain(final_chain).apply_async()
    return final_chain_result.get()

if __name__ == '__main__':
    if has_run():
        logging.info("this script has already been run")
        sys.exit(0)
    run_all()



