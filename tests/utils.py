from itertools import tee
from operator import lt
import os
import random
import time
from types import SimpleNamespace
import unittest, pytest
from urllib.parse import urljoin

base_url = os.environ["SERVICE_BASE_URL"]
import requests



def remove_unknown_keys(data: dict, known_keys: list):
    payload = data.copy()
    for k in list(payload.keys()):
        if k not in known_keys:
            payload.pop(k, None)
    return payload


def wait_for_jobs(job_id):
    try_count = 0
    while True:
        job_data = requests.get(f"{base_url}/api/v1/jobs/{job_id}/").json()
        job_status = job_data["state"]
        if job_status in ["completed", "failed"]:
            assert job_status == "completed", f"response: {job_data}"
            return job_data
        try_count += 1
        assert try_count < 90, "stopped after 90 retries"
        time.sleep(5)

def random_list(l: list, k=5):
    l = list(l)[:]
    random.shuffle(l)
    return l[:k]


def is_sorted(iterable, key=None, reverse=False):
    it = iterable if (key is None) else map(key, iterable)
    a, b = tee(it)
    next(b, None)
    if reverse:
        b, a = a, b
    return not any(map(lt, b, a))