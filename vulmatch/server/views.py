import re
from django.shortcuts import render
from rest_framework import viewsets, filters, status, decorators

from vulmatch.server.arango_helpers import CVE_SORT_FIELDS, ArangoDBHelper, ATTACK_TYPES, CWE_TYPES, SOFTWARE_TYPES, CAPEC_TYPES
from vulmatch.server.utils import Pagination, Response, Ordering, split_mitre_version
from vulmatch.worker.tasks import new_task
from . import models
from vulmatch.server import serializers
from django_filters.rest_framework import FilterSet, Filter, DjangoFilterBackend, ChoiceFilter, BaseCSVFilter, CharFilter, BooleanFilter, MultipleChoiceFilter, NumberFilter, NumericRangeFilter, DateTimeFilter
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiParameter
from drf_spectacular.types import OpenApiTypes
from textwrap import dedent
# Create your views here.

import textwrap

class VulnerabilityStatus(models.models.TextChoices):
    RECEIVED = "Received"
    REJECTED = "Rejected"
    ANALYZED = "Analyzed"
    AWAITING_ANALYSIS = "Awaiting Analysis"
    MODIFIED = "Modified"

@extend_schema_view(
    create=extend_schema(
        responses={201: serializers.JobSerializer
        },
        request=serializers.NVDTaskSerializer,
        summary="Download data for CVEs",
        description=textwrap.dedent(
            """
            Use this data to update the CVE records.\n\n
            The earliest CVE record has a `modified` value of `2007-07-13T04:00:00.000Z`. That said, as a rough guide, we recommend downloading CVEs from `last_modified_earliest` = `2020-01-01` because anything older than this is _generally_ stale.\n\n
            The easiest way to identify the last update time used (to keep CVE records current) is to use the jobs endpoint which will show the `last_modified_earliest` and `last_modified_latest` dates used.\n\n
            The following key/values are accepted in the body of the request:\n\n
            * `last_modified_earliest` (required - `YYYY-MM-DD`): earliest modified time for vulnerability
            * `last_modified_latest` (required - `YYYY-MM-DD`): latest modified time for vulnerability \n\n
            The data for updates is requested from `https://downloads.ctibutler.com` (managed by the [DOGESEC](https://www.dogesec.com/) team).
            """
        ),
    ),
    list_objects=extend_schema(
        responses={200: serializers.StixObjectsSerializer(many=True)}, filters=True,
        summary="Get Vulnerability Objects for CVEs",
        description=textwrap.dedent(
            """
            Search and filter CVE records. This endpoint only returns the vulnerability objects for matching CVEs.\n\n
            Once you have the CVE ID you want, you can get all associated data linked to it (e.g. Indicator Objects) using the bundle endpoint.\n\n
            If you already know the CVE ID, use the Get a Vulnerability by ID endpoint
            """
        ),
    ),
    retrieve_objects=extend_schema(
        summary='Get a Vulnerability by CVE ID',
        description=textwrap.dedent(
            """
            Return data for a CVE by ID. This endpoint only returns the `vulnerability` object for CVE.\n\n
            If you want all the Objects related to this vulnerability you should use the bundle endpoint for the CVE.
            """
        ),
        responses={200: ArangoDBHelper.get_paginated_response_schema('vulnerabilities', 'vulnerability')},
        parameters=ArangoDBHelper.get_schema_operation_parameters()+[
            OpenApiParameter("cve_version", type=OpenApiTypes.DATETIME, description="Return only vulnerability object where `modified` value matches query")
        ],
    ),
    bundle=extend_schema(
        summary='Get all objects for a Vulnerability by CVE ID',
        description=textwrap.dedent(
            """
            This endpoint will return all objects related to the Vulnerability. This can include the following:\n\n
            * `vulnerability`: Represents the CVE
            * `indicator`: Contains a pattern identifying products affected by the CVE
            * `relationship` (`indicator`->`vulnerability`)
            * `note`: Represents EPSS scores
            * `sighting`: Represents CISA KEVs
            * `software`: Represents the products listed in the pattern
            * `relationship` (`indicator`->`software`)
            * `weakness` (CWE): represents CWEs linked to the Vulneability (requires `cve-cwe` mode to be run)
            * `relationship` (`vulnerability` (CVE) ->`weakness` (CWE))
            * `attack-pattern` (CAPEC): represents CAPECs in CWEs (linked to Vulnerability) (requires `cve-cwe` and `cwe-capec` mode to be run)
            * `relationship` (`weakness` (CWE) ->`attack-pattern` (CAPEC))
            * `attack-pattern` (ATT&CK Enterprise/ICS/Mobile): represents ATT&CKs in CAPECs in CWEs (linked to Vulnerability) (requires `cve-cwe`, `cwe-capec` and `capec-attack` mode to be run)
            * `relationship` (`attack-pattern` (CAPEC) ->`attack-pattern` (ATT&CK))
            """
        ),
        responses={200: ArangoDBHelper.get_paginated_response_schema('objects', 'vulnerability')},
        parameters=ArangoDBHelper.get_schema_operation_parameters(),
    ),
    versions=extend_schema(
        responses=serializers.StixVersionsSerializer,
        summary="Get all updates for a Vulnerability by CVE ID",
        description=textwrap.dedent(
            """
            This endpoint will return all the times a Vulnerability has been modified over time as new information becomes available.\n\n
            By default the latest version of objects will be returned by all endpoints. This endpoint is generally most useful to researchers interested in the evolution of what is known about a vulnerability. The version returned can be used to get an older versions of a Vulnerability.
            """
        ),

    )
)   
class CveView(viewsets.ViewSet):
    openapi_tags = ["CVE"]
    pagination_class = Pagination("vulnerabilities")
    filter_backends = [DjangoFilterBackend]
    serializer_class = serializers.StixObjectsSerializer(many=True)
    lookup_url_kwarg = 'cve_id'
    openapi_path_params = [
        OpenApiParameter('stix_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The STIX ID, e.g `vulnerability--4d2cad44-0a5a-5890-925c-29d535c3f49e`.'),
        OpenApiParameter('cve_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The CVE ID, e.g `CVE-2024-3125`'),

    ]

    
    class filterset_class(FilterSet):
        stix_id = MultipleChoiceFilter(help_text='Filter the results using the STIX ID of a `vulnerability` object. e.g. `vulnerability--4d2cad44-0a5a-5890-925c-29d535c3f49e`.')
        cve_id = CharFilter(help_text='Filter the results using a CVE ID. e.g. `CVE-2023-22518`')
        description = CharFilter(help_text='Filter the results by the description of the Vulnerability. Search is a wildcard, so `exploit` will return all descriptions that contain the string `exploit`.')
        has_kev = BooleanFilter(label=dedent('''
        Filter the results to only include those reported by CISA KEV (Known Exploited Vulnerability).
        '''))
        cpes_vulnerable = BaseCSVFilter(label=dedent('''
        Filter Vulnerabilities that are vulnerable to a full or partial CPE Match String. Search is a wildcard to support partial match strings (e.g. `cpe:2.3:o:microsoft:windows` will match `cpe:2.3:o:microsoft:windows_10_1607:-:*:*:*:*:*:x86:*`, `cpe:2.3:o:microsoft:windows_10_1607:-:*:*:*:*:*:x64:*`, etc.\n\n
        `cve-cpe` mode must have been triggered on the Arango CTI Processor endpoint for this to work.
        '''))
        cpes_in_pattern = BaseCSVFilter(label=dedent('''
        Filter Vulnerabilities that contain a full or partial CPE Match String. Note, this will return Vulnerabilities that are vulnerable and not vulnerable (e.g. an operating system might not be vulnerable, but it might be required for software running on it to be vulnerable). Search is a wildcard to support partial match strings (e.g. `cpe:2.3:o:microsoft:windows` will match `cpe:2.3:o:microsoft:windows_10_1607:-:*:*:*:*:*:x86:*`, `cpe:2.3:o:microsoft:windows_10_1607:-:*:*:*:*:*:x64:*`, etc.\n\n
        `cve-cpe` mode must have been triggered on the Arango CTI Processor endpoint for this to work.
        '''))
        weakness_id = BaseCSVFilter(label=dedent("""
            Filter results by weakness (CWE ID). e.g. `CWE-122`.\n\n
            filters using the `external_references` property of `vulnerability` object
            """))
        cvss_base_score_min = NumberFilter(help_text="The minumum CVSS score you want. `0` is lowest, `10` is highest.")
        epss_score_min = NumberFilter(help_text="The minimum EPSS score you want. Between `0` (lowest) and `1` highest to 2 decimal places (e.g. `9.34`).\n\n`cve-epss` mode must have been triggered on the Arango CTI Processor endpoint for this to work.")
        epss_percentile_min = NumberFilter(help_text="The minimum EPSS percentile you want. Between `0` (lowest) and `1` highest to 2 decimal places (e.g. `9.34`).\n\n`cve-epss` mode must have been triggered on the Arango CTI Processor endpoint for this to work.")
        created_min = DateTimeFilter(help_text="Is the minumum `created` value (`YYYY-MM-DDThh:mm:ss.sssZ`)")
        created_max = DateTimeFilter(help_text="Is the maximum `created` value (`YYYY-MM-DDThh:mm:ss.sssZ`)")
        
        modified_min = DateTimeFilter(help_text="Is the minumum `modified` value (`YYYY-MM-DDThh:mm:ss.sssZ`)")
        modified_max = DateTimeFilter(help_text="Is the maximum `modified` value (`YYYY-MM-DDThh:mm:ss.sssZ`)")
        sort = ChoiceFilter(choices=[(v, v) for v in CVE_SORT_FIELDS], help_text="Sort results by")
        vuln_status = ChoiceFilter(choices=VulnerabilityStatus.choices, help_text="filter by vulnerability status")


    def create(self, request, *args, **kwargs):
        serializer = serializers.NVDTaskSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        job = new_task(serializer.data, models.JobType.CVE_UPDATE)
        job_s = serializers.JobSerializer(instance=job)
        return Response(job_s.data, status=status.HTTP_201_CREATED)
    
    @decorators.action(methods=['GET'], url_path="objects", detail=False)
    def list_objects(self, request, *args, **kwargs):
        return ArangoDBHelper('', request, 'vulnerabilities').get_vulnerabilities()
    
    @decorators.action(methods=['GET'], detail=False, url_path="objects/<str:cve_id>/bundle")
    def bundle(self, request, *args, cve_id=None, **kwargs):
        return ArangoDBHelper('', request).get_cve_bundle(cve_id)
    
    @decorators.action(methods=['GET'], url_path="objects/<str:cve_id>", detail=False)
    def retrieve_objects(self, request, *args, cve_id=None, **kwargs):
        return ArangoDBHelper('nvd_cve_vertex_collection', request).get_cxe_object(cve_id)
    
    @decorators.action(detail=False, url_path="objects/<str:cve_id>/versions", methods=["GET"], pagination_class=Pagination('versions'))
    def versions(self, request, *args, cve_id=None, **kwargs):
        return ArangoDBHelper('nvd_cve_vertex_collection', request).get_cve_versions(cve_id)
    

@extend_schema_view(
    create=extend_schema(
        responses={201: serializers.JobSerializer
        },
        request=serializers.NVDTaskSerializer,
        summary="Download CPE data",
        description=textwrap.dedent(
            """
            Use this data to update the CPE records.\n\n
            The earliest CPE was `2007-09-01`. That said, as a rough guide, we recommend downloading CPEs from `last_modified_earliest` = `2015-01-01` because anything older than this is _generally_ stale.\n\n
            Note, Software objects representing CPEs do not have a `modified` time in the way Vulnerability objects do. As such, you will want to store a local index of last_modified_earliest` and `last_modified_latest` used in previous request. Requesting the same dates won't cause an issue (existing records will be skipped) but it will be more inefficient.\n\n
            The following key/values are accepted in the body of the request:\n\n
            * `last_modified_earliest` (required - `YYYY-MM-DD`): earliest modified time for CPE
            * `last_modified_latest` (required - `YYYY-MM-DD`): latest modified time for CPE\n\n
            The data for updates is requested from `https://downloads.ctibutler.com` (managed by the [DOGESEC](https://www.dogesec.com/) team).
            """
        ),
    ),
    list_objects=extend_schema(
        summary='Get Software Objects for CPEs',
        description="Search and filter CPE records.\n\nThis endpoint only returns the `software` objects for matching CPEs.\n\nThis endpoint is useful to find CPEs that can be used to filter CVEs.",
        filters=True,
    ),
    retrieve_objects=extend_schema(
        summary='Get a CPE object by STIX ID',
        description="Retrieve a single STIX `software` object for a CPE using its STIX ID. You can identify a STIX ID using the GET CPEs endpoint.",
        filters=False,
    ),
) 
class CpeView(viewsets.ViewSet):
    openapi_tags = ["CPE"]
    pagination_class = Pagination("objects")
    filter_backends = [DjangoFilterBackend]
    serializer_class = serializers.StixObjectsSerializer(many=True)
    lookup_url_kwarg = 'stix_id'
    openapi_path_params = [
        OpenApiParameter('stix_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The full STIX `id` of the object. e.g. `vulnerability--4d2cad44-0a5a-5890-925c-29d535c3f49e`'),
        OpenApiParameter('cpe_name', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The full CPE name. e.g. `cpe:2.3:a:slicewp:affiliate_program_suite:1.0.13:*:*:*:*:wordpress:*:*`'),
    ]

    
    class filterset_class(FilterSet):
        id = BaseCSVFilter(help_text='Filter the results by the STIX ID of the `software` object. e.g. `software--93ff5b30-0322-50e8-90c1-1c3f151c8adc`')
        cpe_match_string = CharFilter(help_text='Filter CPEs that contain a full or partial CPE Match String. Search is a wildcard to support partial match strings (e.g. `cpe:2.3:o:microsoft:windows` will match `cpe:2.3:o:microsoft:windows_10_1607:-:*:*:*:*:*:x86:*`, `cpe:2.3:o:microsoft:windows_10_1607:-:*:*:*:*:*:x64:*`, etc.')
        vendor = CharFilter(help_text='Filters CPEs returned by vendor name. Is wildcard search so `goog` will match `google`, `googe`, etc.')
        product = CharFilter(help_text='Filters CPEs returned by product name. Is wildcard search so `chrom` will match `chrome`, `chromium`, etc.')

        product_type = ChoiceFilter(choices=[('operating-system', 'Operating System'), ('application', 'Application'), ('hardware', 'Hardware')],
                        help_text='Filters CPEs returned by product type.'
        )
        cve_vulnerable = BaseCSVFilter(help_text='Filters CPEs returned to those vulnerable to CVE ID specified. e.g. `CVE-2023-22518`.')
        in_cve_pattern = BaseCSVFilter(help_text='Filters CPEs returned to those referenced CVE ID specified (if you want to only filter by vulnerable CPEs, use the `cve_vulnerable` parameter. e.g. `CVE-2023-22518`.')

    def create(self, request, *args, **kwargs):
        serializer = serializers.NVDTaskSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        job = new_task(serializer.data, models.JobType.CPE_UPDATE)
        job_s = serializers.JobSerializer(instance=job)
        return Response(job_s.data, status=status.HTTP_201_CREATED)
    
    @decorators.action(methods=['GET'], url_path="objects", detail=False)
    def list_objects(self, request, *args, **kwargs):
        return ArangoDBHelper('', request).get_softwares()

    @decorators.action(methods=['GET'], url_path="objects/<str:cpe_name>", detail=False)
    def retrieve_objects(self, request, *args, cpe_name=None, **kwargs):
        return ArangoDBHelper(f'nvd_cpe_vertex_collection', request).get_cxe_object(cpe_name, type='software', var='cpe')
      
@extend_schema_view(
    create=extend_schema(
        responses={201: serializers.JobSerializer
        },
        summary="Trigger arango_cti_processor `mode` to generate relationships.",
        description=textwrap.dedent(
            """
            This endpoint will link together knowledgebases based on the `mode` selected. For more information about how this works see [arango_cti_processor](https://github.com/muchdogesec/arango_cti_processor/), specifically the `--relationship` setting.\n\n
            The following key/values are accepted in the body of the request:\n\n
            * `ignore_embedded_relationships` (optional - default: `true`): arango_cti_processor generates SROs to link knowledge-bases. These SROs have embedded relationships inside them. Setting this to `true` (recommended) will generat SROs for these embedded relationships so they can be searched. `false` will ignore them\n\n
            * `modified_min` (optional - default: all time - format: `YYYY-MM-DDTHH:MM:SS.sssZ`): by default arango_cti_processor will run over all objects in the latest version of a framework (e.g. ATT&CK). This is not always effecient, espeically when updating CVE records. As such, you can ask the script to only consider objects with a `modified` time greater than that specified for this field.\n\n
            * `created_min` (optional - default: all time- format: `YYYY-MM-DDTHH:MM:SS.sssZ`): same as `modified_min`, but this time considers `created` time of the object (not `modified` time).
            """
        ),
    ),
)
class ACPView(viewsets.ViewSet):
    openapi_tags = ["Arango CTI Processor"]
    serializer_class = serializers.ACPSerializer
    openapi_path_params = [
            OpenApiParameter(name='mode', enum=list(serializers.ACP_MODES), location=OpenApiParameter.PATH, description='The  [`arango_cti_processor`](https://github.com/muchdogesec/arango_cti_processor/) `--relationship` mode.')
    ]

    def create(self, request, *args, **kwargs):
        serializer = serializers.ACPSerializerWithMode(data={**request.data, **kwargs})
        serializer.is_valid(raise_exception=True)
        data = serializer.data.copy()
        job = new_task(data, models.JobType.CTI_PROCESSOR)
        job_s = serializers.JobSerializer(instance=job)
        return Response(job_s.data, status=status.HTTP_201_CREATED)

@extend_schema_view(
    list=extend_schema(
        description="Search and filter Jobs. Jobs are triggered for each time a data download request is executed (e.g. GET ATT&CK). The response of these requests will contain a Job ID. Note, Jobs also include Arango CTI Processor runs to join the data together.\n\nNote, for job types `cpe-update` and `cve-update` you might see a lot of urls marked as `errors`. This is expected. This simply means there is no data for the day requested and the script is not smart enough to handle it gracefully.",
        summary="Get Jobs",
        responses={200: serializers.JobSerializer}
    ),
    retrieve=extend_schema(
        description="Get information about a specific Job. To retrieve a Job ID, use the GET Jobs endpoint.\n\nNote, for job types `cpe-update` and `cve-update` you might see a lot of urls marked as `errors`. This is expected. This simply means there is no data for the day requested and the script is not smart enough to handle it gracefully.",
        summary="Get a Job by ID",
    ),
)
class JobView(viewsets.ModelViewSet):
    http_method_names = ["get"]
    serializer_class = serializers.JobSerializer
    filter_backends = [DjangoFilterBackend, Ordering]
    ordering_fields = ["run_datetime", "state", "type", "id"]
    ordering = "run_datetime_descending"
    pagination_class = Pagination("jobs")
    openapi_tags = ["Jobs"]
    lookup_url_kwarg = 'job_id'
    openapi_path_params = [
        OpenApiParameter(lookup_url_kwarg, type=OpenApiTypes.UUID, location=OpenApiParameter.PATH, description='The Job `id`. You can find Jobs and their `id`s using the Get Jobs endpoint.')
    ]

    def get_queryset(self):
        return models.Job.objects.all()
    class filterset_class(FilterSet):
        @staticmethod
        def get_type_choices():
            choices = list(models.JobType.choices)
            for mode, summary in serializers.ACP_MODES.items():
                type = models.JobType.CTI_PROCESSOR
                choices.append((f"{type}--{mode}", summary))

            choices.sort(key=lambda x: x[0])
            return choices
        
        type = ChoiceFilter(
            help_text='Filter the results by the type of Job',
            choices=get_type_choices(), method='filter_type'
        )
        state = Filter(help_text='Filter the results by the state of the Job')

        def filter_type(self, qs, field_name, value: str):
            query = {field_name: value}
            if '--' in value:
                type, mode = value.split('--')
                query.update({field_name: type, "parameters__mode":mode})
            return qs.filter(**query)
        
    def create(self, request, *args, **kwargs):
        return super().create(request, *args, **kwargs)
