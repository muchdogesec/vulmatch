import time
import pytest
from acvep.models import EPSSScore
from datetime import date


@pytest.mark.parametrize(
    "states,expected_ids",
    [
        (["pending"], {"9e0d79ed-94d9-42a3-aa41-4772ae922176"}),
        (["processing"], {"2583d09b-6535-4f15-9fd1-5dcb55230f08"}),
        (["pending", "processing"], {"9e0d79ed-94d9-42a3-aa41-4772ae922176", "2583d09b-6535-4f15-9fd1-5dcb55230f08"}),
        (["completed"], {"0014c5a1-7a5e-408f-88ea-83ec5a1b8af1"}),
        (["failed"], {"a1b2c3d4-5e6f-7a8b-9c0d-1e2f3a4b5c6d"}),
        (["completed", "failed"], {"0014c5a1-7a5e-408f-88ea-83ec5a1b8af1", "a1b2c3d4-5e6f-7a8b-9c0d-1e2f3a4b5c6d"}),
        ([], {"9e0d79ed-94d9-42a3-aa41-4772ae922176", "2583d09b-6535-4f15-9fd1-5dcb55230f08", "0014c5a1-7a5e-408f-88ea-83ec5a1b8af1", "a1b2c3d4-5e6f-7a8b-9c0d-1e2f3a4b5c6d"}),
    ]
)
@pytest.mark.django_db
def test_jobs_filter_by_multiple_states(client, api_schema, states, expected_ids):
    from vulmatch.server import models

    models.Job.objects.create(
        id='9e0d79ed-94d9-42a3-aa41-4772ae922176',
        type=models.JobType.CVE_UPDATE,
        state=models.JobState.PENDING,
        parameters={}
    )
    models.Job.objects.create(
        id='2583d09b-6535-4f15-9fd1-5dcb55230f08',
        type=models.JobType.CVE_PROCESSOR,
        state=models.JobState.PROCESSING,
        parameters={}
    )
    models.Job.objects.create(
        id='0014c5a1-7a5e-408f-88ea-83ec5a1b8af1',
        type=models.JobType.CVE_UPDATE,
        state=models.JobState.COMPLETED,
        parameters={}
    )
    models.Job.objects.create(
        id='a1b2c3d4-5e6f-7a8b-9c0d-1e2f3a4b5c6d',
        type=models.JobType.CVE_PROCESSOR,
        state=models.JobState.FAILED,
        parameters={}
    )

    if states:
        resp = client.get(
            f"/api/v1/jobs/?state={','.join(states)}"
        )
    else:
        resp = client.get(
            f"/api/v1/jobs/"
        )
    
    assert resp.status_code == 200
    assert resp.data["total_results_count"] == len(expected_ids)

    returned = {item["id"] for item in resp.data["jobs"]}
    assert returned == expected_ids

    from tests.utils import Transport
    api_schema["/api/v1/jobs/"]["GET"].validate_response(Transport.get_st_response(resp))