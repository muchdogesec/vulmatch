from dataclasses import dataclass
from datetime import datetime, date, timedelta
import io
import logging
import requests
import gzip
import csv
from pytz import timezone
from functools import lru_cache
from typing import TypedDict

logging.basicConfig(level=logging.INFO)


class EPSS(TypedDict):
    cve: str
    date: str
    epss: float
    percentile: float

class EPSSManager:
    @classmethod
    @lru_cache(maxsize=30)
    def get_epss_date(cls, d: date):
        d_str = d.strftime("%Y-%m-%d")
        url = "https://epss.cyentia.com/epss_scores-{}.csv.gz".format(d_str)
        logging.info(f"retrieving epss from {url}")
        resp = requests.get(url)
        csv_data = gzip.decompress(resp.content).decode()
        data = dict(cls.parse_csv(csv_data, d_str))
        logging.info(f"Got {len(data)} EPSS data for {d_str}")
        return data

    @staticmethod
    def parse_csv(csv_data, date_str):
        data = csv.DictReader(io.StringIO(csv_data), ["cve", "epss", "percentile"])
        for d in data:
            cve_name = d["cve"]
            if not cve_name.startswith("CVE-"):
                continue
            yield cve_name, EPSS(
                date=date_str, epss=float(d["epss"]), percentile=float(d["percentile"])
            )

    @classmethod
    def datenow(cls):
        resp = requests.get("https://api.first.org/data/v1/epss?limit=1")
        return datetime.strptime(resp.json()["data"][0]["date"], "%Y-%m-%d").date()
