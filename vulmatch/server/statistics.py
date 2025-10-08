from datetime import UTC, datetime, timedelta
from functools import lru_cache
import json
from rest_framework import serializers
from rest_framework import viewsets
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


class CVESerializer(serializers.Serializer):
    modified_since = ModifiedCreatedSinceSerializer()
    created_since = ModifiedCreatedSinceSerializer()
    by_year = serializers.ListSerializer(child=ByYearSerializer())


class KEVSerializer(serializers.Serializer):
    created_since = ModifiedCreatedSinceSerializer()
    by_year = serializers.ListSerializer(child=ByYearSerializer())


class CWESerializer(serializers.Serializer):
    cwe_id = serializers.CharField()
    year = YearField()
    cve_count = serializers.IntegerField()


class AttackSerializer(serializers.Serializer):
    attack_id = serializers.CharField()
    year = YearField()
    cve_count = serializers.IntegerField()


@extend_schema_serializer(many=False)
class StatisticsSerializer(serializers.Serializer):
    summary = SummarySerializer()
    cve = CVESerializer()
    kev = KEVSerializer()
    cwes = serializers.ListSerializer(child=CWESerializer())
    attacks = serializers.ListSerializer(child=AttackSerializer())


@lru_cache
def cached_db_query(date, revision, query, kwargs):
    kwargs = json.loads(kwargs)
    kwargs.update(aql_options=dict(cache=True), paginate=False)
    return VulmatchDBHelper("nvd_cve_vertex_collection", None).execute_query(
        query, **kwargs
    )


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
        return cached_db_query(
            self.now.isoformat(), self._rev, query, json.dumps(kwargs, sort_keys=True)
        )

    def get_statistics(self):
        retval = dict(
            summary=self.get_earliest_and_latest_vulnerabilities(),
            cve=dict(
                modified_since=self.cve_modified_or_created_since("modified"),
                created_since=self.cve_modified_or_created_since("created"),
                by_year=self.get_vulnerabilities_by_year(),
            ),
            kev=self.get_kev_stats(),
            epss=self.get_epss_stats(),
            **self.get_attack_cwe_stats(),
        )
        return Response(retval)

    def cve_modified_or_created_since(self, prop):
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
            d = f"d{d}"
            count_modified_since = self.execute_query(
                query,
                bind_vars=dict(**binds, date=date),
            )[0]
            v[d] = count_modified_since
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

    def get_attack_cwe_stats(self):
        query = """
FOR d IN nvd_cve_edge_collection OPTIONS {indexHint: 'vulmatch_stats_attack_cwe'}
FILTER d._arango_cve_processor_note == @note AND d._is_latest == TRUE
COLLECT cwe_id = d.external_references[1].external_id, year = LEFT(d.created, 4) WITH COUNT INTO cve_count
RETURN {[@name]: cwe_id, year, cve_count}
"""
        return dict(
            cwes=self.execute_query(
                query,
                bind_vars=dict(name="cwe_id", note="cve-cwe"),
            ),
            attacks=self.execute_query(
                query,
                bind_vars=dict(name="attack_id", note="cve-attack"),
            ),
        )

    def get_vulnerabilities_by_year(self):
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

    def get_epss_stats(self):
        query = """
        FOR d IN nvd_cve_vertex_collection
            OPTIONS {indexHint: 'vulmatch_stats_epss'}
        FILTER d.type == "vulnerability" 
            AND d._is_latest == TRUE 
        COLLECT group = d.x_opencti_epss_score != NULL ? FLOOR(d.x_opencti_epss_score * 10) / 10 : NULL WITH COUNT INTO cve_count
        RETURN [
                group,
                cve_count
        ]
        """
        groups = {}
        for group, cve_count in self.execute_query(
            query,
        ):
            if group == None:
                name = "undefined"
            else:
                name = f"{group:.1f} - {group + 0.1: .1f}"
            groups[name] = cve_count
        return groups


@extend_schema_view(
    list=extend_schema(
        description=textwrap.dedent(
            """
            Use this endpoint to get high level summary of the data held in Vulmatch.

            When you make a request to the endpoint, and new summart is generated unless the `revision` or `date` (EST time) has changed.
            
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
