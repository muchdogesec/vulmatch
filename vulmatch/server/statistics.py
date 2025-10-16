from datetime import UTC, datetime, timedelta
import json
from typing import Literal
from rest_framework import serializers, viewsets
from pytz import timezone
from django.core.cache import cache

from vulmatch.server.arango_helpers import (
    VulmatchDBHelper,
)
from drf_spectacular.utils import (
    extend_schema_field,
    extend_schema_serializer,
    extend_schema_view,
    extend_schema,
)

from rest_framework.response import Response
import textwrap
import hashlib


@extend_schema_field({"type": "string", "example": "CVE-2024-19091"})
class CVEField(serializers.CharField):
    pass


class SummaryItemSerializer(serializers.Serializer):
    cve = CVEField()
    created_at = serializers.DateTimeField()


class SummarySerializer(serializers.Serializer):
    latest = SummaryItemSerializer(allow_null=True)
    earliest = SummaryItemSerializer(allow_null=True)
    generated_on = serializers.DateField()


class ModifiedCreatedSinceSerializer(serializers.Serializer):
    d1 = serializers.IntegerField()
    d7 = serializers.IntegerField()
    d30 = serializers.IntegerField()
    d365 = serializers.IntegerField()


@extend_schema_field({"type": "string", "example": "2024"})
class YearField(serializers.CharField):
    pass


class ByYearSerializer(serializers.Serializer):
    year = YearField()
    count = serializers.IntegerField()


class CVENumericsStatSerializer(serializers.Serializer):
    range_group = serializers.CharField()
    count = serializers.IntegerField()


@extend_schema_serializer(many=False)
class CVEStatSerializer(serializers.Serializer):
    modified_since = ModifiedCreatedSinceSerializer()
    created_since = ModifiedCreatedSinceSerializer()
    by_year = ByYearSerializer(many=True)
    cvss_v2 = CVENumericsStatSerializer(many=True)
    cvss_v3 = CVENumericsStatSerializer(many=True)
    cvss_v4 = CVENumericsStatSerializer(many=True)


@extend_schema_serializer(many=False)
class KEVStatSerializer(serializers.Serializer):
    created_since = ModifiedCreatedSinceSerializer()
    by_year = ByYearSerializer(many=True)


class CVECountsByYear(serializers.Serializer):
    year = YearField()
    cve_count = serializers.IntegerField()


class CWEStatSerializer(serializers.Serializer):
    cwe_id = serializers.CharField()
    total_cve_count = serializers.IntegerField(
        help_text="total number of cves exploited via weakness"
    )
    by_year = CVECountsByYear(many=True)


class AttackStatSerializer(CWEStatSerializer):
    attack_id = serializers.CharField()
    total_cve_count = serializers.IntegerField(
        help_text="total number of cves targeted using attack technique"
    )
    cwe_id = None



class CapecStatSerializer(CWEStatSerializer):
    capec_id = serializers.CharField()
    total_cve_count = serializers.IntegerField(
        help_text="total number of cves targeted using capec"
    )
    cwe_id = None



@extend_schema_serializer(many=False)
class StatisticsSerializer(serializers.Serializer):
    summary = SummarySerializer()
    cve = CVEStatSerializer()
    kev = KEVStatSerializer()
    cwes = CWEStatSerializer(many=True)
    attacks = AttackStatSerializer(many=True)
    capecs = CapecStatSerializer(many=True)


def make_cache_key(date, revision, query, kwargs):
    # Use a hash to avoid huge keys
    key_string = f"{date}:{revision}:{query}:{kwargs}"
    return "statistics_query_" + hashlib.sha256(key_string.encode("utf-8")).hexdigest()


class StatisticsHelper:
    now = None

    def __init__(self):
        eastern = timezone("US/Eastern")
        self.now = datetime.now(eastern).date()
        self._rev = (
            VulmatchDBHelper("", None)
            .db.collection("nvd_cve_edge_collection")
            .revision()
        )

    def execute_query(self, query, **kwargs):
        cache_key = make_cache_key(
            self.now.isoformat(), self._rev, query, json.dumps(kwargs, sort_keys=True)
        )
        result = cache.get(cache_key)
        if result is not None:
            return result

        kwargs.update(aql_options=dict(cache=True), paginate=False)

        result = VulmatchDBHelper("nvd_cve_vertex_collection", None).execute_query(
            query, **kwargs
        )
        # Cache for 24 hours (86400s), adjust as needed
        cache.set(cache_key, result, timeout=86400)
        return result

    def get_statistics(self):
        retval = dict(
            summary=self.get_earliest_and_latest_vulnerabilities(),
            cve=self.get_cve_stat(),
            kev=self.get_kev_stats(),
            epss=self.get_cve_numeric_stat("x_opencti_epss_score"),
            cwes=self.get_attack_cwe_stats(
                "cwe",
            ),
            attacks=self.get_attack_cwe_stats(
                "attack",
            ),
            capecs=self.get_attack_cwe_stats(
                "capec",
            ),
        )
        return Response(retval)

    def get_cve_stat(self):
        by_year = self._vulnerabilities_by_year()
        return dict(
            total_count=sum(map(lambda x: x["count"], by_year)),
            modified_since=self._cve_modified_or_created_since("modified"),
            created_since=self._cve_modified_or_created_since("created"),
            by_year=by_year,
            cvss_v2=self.get_cve_numeric_stat("x_opencti_cvss_v2_base_score"),
            cvss_v3=self.get_cve_numeric_stat("x_opencti_cvss_base_score"),
            cvss_v4=self.get_cve_numeric_stat("x_opencti_cvss_v4_base_score"),
        )

    def _cve_modified_or_created_since(self, prop):
        query_multi = """
        RETURN LENGTH(
            FOR doc IN nvd_cve_vertex_collection
            FILTER doc.type == 'vulnerability' AND doc[@prop] >= @date AND doc._is_latest == TRUE
            RETURN doc.type
        )
        """
        return self.get_modified_since_stats(query_multi, {"prop": prop})

    def get_modified_since_stats(self, query, binds={}):
        now = self.now
        v = {}
        for d in [1, 7, 30, 365]:
            date = (now - timedelta(days=d)).isoformat()
            key = f"d{d}"
            count_modified_since = self.execute_query(
                query,
                bind_vars=dict(**binds, date=date),
            )[0]
            v[key] = count_modified_since
        return v

    def get_kev_stats(self):
        created_since_query = """
        RETURN LENGTH(
            FOR doc IN nvd_cve_vertex_collection
            FILTER doc.created >= @date AND doc.labels == ['kev']
            RETURN DISTINCT doc.object_refs[0]
        )"""
        by_year_query = """
    FOR d IN nvd_cve_vertex_collection
    FILTER d.labels == ['kev']
    COLLECT year = LEFT(d.created, 4) WITH COUNT INTO year_count
    SORT year DESC
    RETURN {year, count: year_count}
        """
        retval = dict(
            created_since=self.get_modified_since_stats(created_since_query),
            by_year=self.execute_query(
                by_year_query,
            ),
        )
        return retval

    def get_attack_cwe_stats(self, _type: Literal["cwe", "attack"]):
        id_name = _type + "_id"
        query = """
FOR d IN nvd_cve_edge_collection OPTIONS {indexHint: 'vulmatch_stats_attack_cwe'}
FILTER d._arango_cve_processor_note == @note AND d._is_latest == TRUE
COLLECT name = d.external_references[1].external_id, year = LEFT(d.created, 4) WITH COUNT INTO cve_count
RETURN {name, year, cve_count}
"""
        stat = self.execute_query(
            query,
            bind_vars=dict(note="cve-" + _type),
        )
        retval = dict()
        for attack in stat:
            attack = attack.copy()
            attack_id = attack.pop("name")
            lst: list = retval.setdefault(
                attack_id, {id_name: attack_id, "total_cve_count": 0, "by_year": []}
            )["by_year"]
            lst.append(attack)
            retval[attack_id]["total_cve_count"] += attack["cve_count"]
        return sorted(retval.values(), key=lambda x: (x['total_cve_count'], x[id_name]), reverse=True)

    def _vulnerabilities_by_year(self):
        query = """
FOR d IN nvd_cve_vertex_collection
FILTER d.type == 'vulnerability'
COLLECT year = LEFT(d.created, 4) WITH COUNT INTO year_count
SORT year DESC
RETURN {year, count: year_count}
        """
        return self.execute_query(
            query,
        )

    def get_earliest_and_latest_vulnerabilities(self):
        query_templ = """
FOR d IN nvd_cve_vertex_collection
FILTER d.type == 'vulnerability' AND d._is_latest == TRUE
SORT d.type %direction, d._is_latest %direction, d.created %direction
LIMIT 1
RETURN { cve: d.name, created_at: d.created }
        """
        retval = dict(generated_on=self.now.isoformat())
        for direction, k in [
            ("DESC", "latest"),
            ("ASC", "earliest"),
        ]:
            query = query_templ.replace("%direction", direction)
            value = self.execute_query(
                query,
            )
            retval[k] = (value and value[0]) or None
        return retval

    def get_cve_numeric_stat(
        self,
        prop: Literal[
            "x_opencti_epss_score",
            "x_opencti_cvss_v2_base_score",
            "x_opencti_cvss_base_score",
            "x_opencti_cvss_v4_base_score",
        ],
    ):
        query = """
        FOR d IN nvd_cve_vertex_collection
            OPTIONS {indexHint: 'vulmatch_stats_epss'}
        FILTER d.type == "vulnerability" 
            AND d._is_latest == TRUE 
        COLLECT group = d[@prop] != NULL ? FLOOR(d[@prop] * 10) / 10 : NULL WITH COUNT INTO cve_count
        RETURN [
                group,
                cve_count
        ]
        """
        groups = []
        for group, cve_count in self.execute_query(query, bind_vars=dict(prop=prop)):
            if group is None:
                name = "undefined"
            else:
                name = f"{group:.1f} - {group + 0.1: .1f}"
            groups.append(dict(range_group=name, count=cve_count))
        return groups


@extend_schema_view(
    list=extend_schema(
        description=textwrap.dedent(
            """
            Use this endpoint to get high level summary of the data held in Vulmatch.

            When you make a request to the endpoint, and new summary is generated unless the `revision` or `date` (EST time) has changed.
            
            `revision` is updated if any change is made to the collection. This is the same behaviour used for caching vendor/products data on cpe endpoints.
            """
        ),
        summary="Get calculated statistics",
    )
)
class StatisticsView(viewsets.ViewSet):
    serializer_class = StatisticsSerializer(many=False)
    openapi_tags = ["Statistics"]

    def list(self, request, *args, **kwargs):
        return StatisticsHelper().get_statistics()
