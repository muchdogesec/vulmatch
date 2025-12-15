from datetime import datetime, timedelta, timezone, date
import logging
import time
import uuid

from arango_cve_processor import config
from arango_cve_processor.tools.utils import chunked_tqdm, stix2python
from arango_cve_processor.managers.base_manager import STIXRelationManager
from stix2 import Vulnerability, Report
from acvep.models import EPSSScore


class _CveEpssWorker(STIXRelationManager, relationship_note="cve-epss", register=False):
    DESCRIPTION = """
    Creates EPSS report objects for CVEs
    """
    edge_collection = "nvd_cve_edge_collection"
    vertex_collection = "nvd_cve_vertex_collection"
    default_objects = [
        "https://raw.githubusercontent.com/muchdogesec/stix2extensions/refs/heads/main/automodel_generated/extension-definitions/properties/report-epss-scoring.json"
    ]
    CHUNK_SIZE = 10_000

    def __init__(self, processor, epss_date, **kwargs) -> None:
        super().__init__(processor, **kwargs)
        self.epss_date = epss_date

    def process(self, **kwargs):
        self.epss_data_source = EPSSScore.get_for_date(self.epss_date)
        cve_ids = [d.cve for d in self.epss_data_source]
        if self.cve_ids:
            self.cve_ids = list(set(cve_ids).intersection(self.cve_ids))
        else:
            self.cve_ids = list(cve_ids)
        return super().process(**kwargs)

    def get_objects_from_db(self, query, **binds):
        return self.arango.execute_raw_query(
            query,
            bind_vars={
                "@collection": self.collection,
                **binds,
            },
            memory_limit=100 * 1024**2,
        )

    def get_object_chunks(self, **kwargs):
        for cve_ids_chunk in chunked_tqdm(
            self.cve_ids, self.CHUNK_SIZE, "get-cve-and-existing-epss-reports"
        ):
            reports_query = """
  FOR doc IN @@collection OPTIONS {indexHint: "acvep_search_v2", forceIndexHint: true}
  FILTER doc._arango_cve_processor_note == @relationship_note
  FILTER doc.name IN @cve_ids AND doc._is_latest == TRUE
  LET cve_name = doc.external_references[0].external_id
  RETURN [cve_name, KEEP(doc, '_key', 'x_epss', '_record_created')]
        """
            cve_query = """
  FOR doc IN @@collection OPTIONS {indexHint: "acvep_search_v2", forceIndexHint: true}
  FILTER doc.type == 'vulnerability'
  FILTER doc.name IN @cve_ids
  FILTER doc._is_latest == TRUE AND doc.created >= @created_min AND doc.modified >= @modified_min 
  RETURN [doc.name, KEEP(doc, 'id', '_record_created', 'created', '_key')]
        """
            reports = dict(
                self.get_objects_from_db(
                    reports_query,
                    relationship_note=self.relationship_note,
                    cve_ids=[f"EPSS Scores: {cve_id}" for cve_id in cve_ids_chunk],
                )
            )
            cves: list[tuple[str, dict]] = self.get_objects_from_db(
                cve_query,
                cve_ids=cve_ids_chunk,
                created_min=self.created_min,
                modified_min=self.modified_min,
            )
            objects = []
            for cve_name, cve in cves:
                cve.update(name=cve_name, epss=reports.get(cve_name))
                objects.append(cve)
            yield objects

    def relate_single(self, cve_object):
        latest_report = parse_cve_epss_report(cve_object)
        if not latest_report:
            return []
        self.update_objects.append(
            self.make_opencti_properties(cve_object["_key"], latest_report["x_epss"][0])
        )
        if cve_object["epss"]:
            latest_epss: dict = latest_report["x_epss"][0].copy()
            self.update_objects.append(
                {
                    **cve_object["epss"],
                    "x_epss": latest_report["x_epss"],
                    "modified": latest_epss["date"] + "T00:00:00.000Z",
                    "_arango_cve_processor_note": self.relationship_note,
                    "_epss_score": latest_epss["epss"],
                    "_epss_percentile": latest_epss["percentile"],
                }
            )
            return []
        else:
            return [stix2python(latest_report)]

    @staticmethod
    def make_opencti_properties(key: str, epss: dict):
        return dict(
            _key=key,
            x_opencti_epss_score=epss["epss"],
            x_opencti_epss_percentile=epss["percentile"],
        )


class CveEpssManager(_CveEpssWorker, relationship_note="cve-epss"):
    DESCRIPTION = """
    Creates EPSS report objects for CVEs. Starting from start date and stopping at end date 
    """

    def __init__(self, processor, start_date, end_date, *args, **kwargs):
        self.processor = processor
        self.args = args
        self.kwargs = kwargs
        self.start_date = start_date
        latest_date_available = EPSSScore.datenow()
        end_date = end_date or latest_date_available
        self.end_date = min(end_date, latest_date_available)

    def process(self, **kwargs):
        start_date = self.start_date
        end_date = self.end_date
        for day, date in date_range(start_date, end_date):
            logging.info(
                f"Running CVE <-> EPSS Backfill for day {day}, date: {date.isoformat()} of {end_date.isoformat()}"
            )
            logging.info("================================")
            EPSSScore._sync_for_date(date)
        date = EPSSScore.get_latest_date()
        rmanager = _CveEpssWorker(self.processor, date, **self.kwargs)
        rmanager.epss_date = date
        rmanager.process(**kwargs)


def date_range(start_date: date, end_date: date):
    """Yield dates from start_date to end_date inclusive."""
    total_days = (end_date - start_date).days + 1
    for n in range(total_days):
        yield f"{n+1} of {total_days}", (start_date + timedelta(days=n))


def parse_cve_epss_report(vulnerability: Vulnerability):
    epss_data_all = EPSSScore.objects.filter(cve=vulnerability.get("name")).order_by(
        "-date"
    )
    latest_epss_data = epss_data_all.first()

    cve_id = latest_epss_data.cve
    content = f"EPSS Scores: {cve_id}"
    modified = latest_epss_data.date

    return Report(
        id="report--" + str(uuid.uuid5(config.namespace, content)),
        created=vulnerability["created"],
        modified=modified,
        published=vulnerability["created"],
        name=content,
        x_epss=[latest_epss_data.dict()],
        object_refs=[
            vulnerability["id"],
        ],
        extensions={
            "extension-definition--efd26d23-d37d-5cf2-ac95-a101e46ce11d": {
                "extension_type": "toplevel-property-extension"
            }
        },
        object_marking_refs=config.OBJECT_MARKING_REFS,
        created_by_ref=config.IDENTITY_REF,
        external_references=[
            {
                "source_name": "cve",
                "external_id": cve_id,
                "url": "https://nvd.nist.gov/vuln/detail/" + cve_id,
            },
            {
                "source_name": "arango_cve_processor",
                "external_id": "cve-epss",
            },
        ],
        labels=["epss"],
    )
