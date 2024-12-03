import re
from django.shortcuts import render
from rest_framework import viewsets, filters, status, decorators

from vulmatch.server.arango_helpers import ATLAS_TYPES, CPE_REL_SORT_FIELDS, CPE_RELATIONSHIP_TYPES, CVE_BUNDLE_TYPES, CVE_SORT_FIELDS, LOCATION_TYPES, TLP_TYPES, ArangoDBHelper, ATTACK_TYPES, CWE_TYPES, SOFTWARE_TYPES, CAPEC_TYPES
from vulmatch.server.autoschema import DEFAULT_400_ERROR
from vulmatch.server.utils import Pagination, Response, Ordering, split_mitre_version
from vulmatch.worker.tasks import new_task
from . import models
from vulmatch.server import serializers
from django_filters.rest_framework import FilterSet, Filter, DjangoFilterBackend, ChoiceFilter, BaseCSVFilter, CharFilter, BooleanFilter, MultipleChoiceFilter, NumberFilter, NumericRangeFilter, DateTimeFilter
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiParameter, OpenApiExample, OpenApiResponse
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
            Use this data to update the CVE records.

            The earliest CVE record has a `modified` value of `2007-07-13T04:00:00.000Z`. That said, as a rough guide, we recommend downloading CVEs from `last_modified_earliest` = `2020-01-01` because anything older than this is _generally_ stale.

            The easiest way to identify the last update time used (to keep CVE records current) is to use the jobs endpoint which will show the `last_modified_earliest` and `last_modified_latest` dates used.

            The following key/values are accepted in the body of the request:

            * `last_modified_earliest` (required - `YYYY-MM-DD`): earliest modified time for vulnerability
            * `last_modified_latest` (required - `YYYY-MM-DD`): latest modified time for vulnerability
            * `ignore_embedded_relationships` (optional - default: `false`): Most objects contains embedded relationships inside them (e.g. `created_by_ref`). Setting this to `false` (recommended) will get stix2arango to generate SROs for these embedded relationships so they can be searched. `true` will ignore them.

            The data for updates is requested from `https://downloads.ctibutler.com` (managed by the [DOGESEC](https://www.dogesec.com/) team).
            """
        ),
    ),
    list_objects=extend_schema(
        responses={200: serializers.StixObjectsSerializer(many=True)}, filters=True,
        summary="Get Vulnerability Objects for CVEs",
        description=textwrap.dedent(
            """
            Search and filter CVE records. This endpoint only returns the vulnerability objects for matching CVEs.
            Once you have the CVE ID you want, you can get all associated data linked to it (e.g. Indicator Objects) using the bundle endpoint.

            If you already know the CVE ID, use the Get a Vulnerability by ID endpoint
            """
        ),
    ),
    retrieve_objects=extend_schema(
        summary='Get a Vulnerability by CVE ID',
        description=textwrap.dedent(
            """
            Return data for a CVE by ID. This endpoint only returns the `vulnerability` object for CVE.

            If you want all the Objects related to this vulnerability you should use the bundle endpoint for the CVE.
            """
        ),
        responses={200: ArangoDBHelper.get_paginated_response_schema('objects', 'vulnerability')},
        parameters=ArangoDBHelper.get_schema_operation_parameters(),
    ),
    retrieve_object_relationships=extend_schema(
        summary='Get Relationships for Vulnerability by CVE ID',
        description=textwrap.dedent(
            """
            Return data for a CVE by ID. This endpoint only returns the `vulnerability` object for CVE.

            If you want all the Objects related to this vulnerability you should use the bundle endpoint for the CVE.
            """
        ),
        responses={200: ArangoDBHelper.get_paginated_response_schema('relationships', 'relationship')},
        parameters=ArangoDBHelper.get_schema_operation_parameters(),
    ),
    bundle=extend_schema(
        summary='Get all objects for a Vulnerability by CVE ID',
        description=textwrap.dedent(
            """
            This endpoint will return all objects related to the Vulnerability. This can include the following:

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
        parameters=ArangoDBHelper.get_schema_operation_parameters() + [
            OpenApiParameter('object_type', description="The type of STIX object to be returned", enum=CVE_BUNDLE_TYPES, many=True, explode=False),
            OpenApiParameter('include_cpe', description="will show all `software` objects related to this vulnerability (and the SROS linking cve-cpe)", type=OpenApiTypes.BOOL),
            OpenApiParameter('include_cpe_vulnerable', description="will show `software` objects vulnerable to this vulnerability (and the SROS), if exist. Note `include_cpe` should be set to `false` if you only want to see vulnerable cpes (and the SROS linking cve-cpe)", type=OpenApiTypes.BOOL),
            OpenApiParameter('include_cwe', description="will show `weakness` objects related to this vulnerability, if exist (and the SROS linking cve-cwe)", type=OpenApiTypes.BOOL),
            OpenApiParameter('include_epss', description="will show `note` objects related to this vulnerability, if exist", type=OpenApiTypes.BOOL),
            OpenApiParameter('include_kev', description="will show `sighthing` objects related to this vulnerability, if exist (and the SROS linking cve-sighting)", type=OpenApiTypes.BOOL),
            OpenApiParameter('include_capec', description="will show CAPEC `attack-pattern` objects related to this vulnerability, if exist  (and the SROS linking cwe-capec)\n * note this mode will also show `include_cwe` outputs, due to the way CAPEC is linked to CVE", type=OpenApiTypes.BOOL),
            OpenApiParameter('include_attack', description="will show ATT&CK `attack-pattern` objects (for Techniques/Sub-techniques) related to this vulnerability, if exist (and the SROS linking capec-attack)\n * note this mode will also show `include_capec` and `include_cwe` outputs, due to the way ATT&CK is linked to CVE", type=OpenApiTypes.BOOL),
        ],
    ),
    versions=extend_schema(
        responses=serializers.StixVersionsSerializer,
        summary="Get all updates for a Vulnerability by CVE ID",
        description=textwrap.dedent(
            """
            This endpoint will return all the times a Vulnerability has been modified over time as new information becomes available.

            By default the latest version of objects will be returned by all endpoints. This endpoint is generally most useful to researchers interested in the evolution of what is known about a vulnerability. The version returned can be used to get an older versions of a Vulnerability.
            """
        ),

    ),

)   
class CveView(viewsets.ViewSet):
    openapi_tags = ["CVE"]
    pagination_class = Pagination("objects")
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
        
        modified_min = DateTimeFilter(label="Is the minumum `modified` value (`YYYY-MM-DDThh:mm:ss.sssZ`)")
        modified_max = DateTimeFilter(label="Is the maximum `modified` value (`YYYY-MM-DDThh:mm:ss.sssZ`)")
        sort = ChoiceFilter(choices=[(v, v) for v in CVE_SORT_FIELDS], label="Sort results by")

        vuln_status = ChoiceFilter(choices=VulnerabilityStatus.choices, help_text="filter by vulnerability status")


    def create(self, request, *args, **kwargs):
        serializer = serializers.NVDTaskSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        job = new_task(serializer.data, models.JobType.CVE_UPDATE)
        job_s = serializers.JobSerializer(instance=job)
        return Response(job_s.data, status=status.HTTP_201_CREATED)
    
    @decorators.action(methods=['GET'], url_path="objects", detail=False)
    def list_objects(self, request, *args, **kwargs):
        return ArangoDBHelper('', request).get_vulnerabilities()
    
    @decorators.action(methods=['GET'], detail=False, url_path="objects/<str:cve_id>/bundle")
    def bundle(self, request, *args, cve_id=None, **kwargs):
        return ArangoDBHelper('', request).get_cve_bundle(cve_id)
    
    @extend_schema(
            parameters=[
                OpenApiParameter("cve_version", type=OpenApiTypes.DATETIME, description="Return only vulnerability object where `modified` value matches query")
            ]
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:cve_id>", detail=False)
    def retrieve_objects(self, request, *args, cve_id=None, **kwargs):
        return ArangoDBHelper('nvd_cve_vertex_collection', request).get_cxe_object(cve_id)
    
    @extend_schema(
            parameters=[
                OpenApiParameter("cve_version", type=OpenApiTypes.DATETIME, description="Return only vulnerability object where `modified` value matches query")
            ]
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:cve_id>/relationships", detail=False)
    def retrieve_object_relationships(self, request, *args, cve_id=None, **kwargs):
        return ArangoDBHelper('nvd_cve_vertex_collection', request).get_cxe_object(cve_id, relationship_mode=True)
    
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
            Use this data to update the CPE records.

            The earliest CPE was `2007-09-01`. That said, as a rough guide, we recommend downloading CPEs from `last_modified_earliest` = `2015-01-01` because anything older than this is _generally_ stale.

            Note, Software objects representing CPEs do not have a `modified` time in the way Vulnerability objects do. As such, you will want to store a local index of last_modified_earliest` and `last_modified_latest` used in previous request. Requesting the same dates won't cause an issue (existing records will be skipped) but it will be more inefficient.

            The following key/values are accepted in the body of the request:

            * `last_modified_earliest` (required - `YYYY-MM-DD`): earliest modified time for CPE
            * `last_modified_latest` (required - `YYYY-MM-DD`): latest modified time for CPE
            * `ignore_embedded_relationships` (optional - default: `false`): Most objects contains embedded relationships inside them (e.g. `created_by_ref`). Setting this to `false` (recommended) will get stix2arango to generate SROs for these embedded relationships so they can be searched. `true` will ignore them.

            The data for updates is requested from `https://downloads.ctibutler.com` (managed by the [DOGESEC](https://www.dogesec.com/) team).
            """
        ),
    ),
    list_objects=extend_schema(
        summary='Get Software Objects for CPEs',
        description=textwrap.dedent(
            """
            Search and filter CPE records.\n\nThis endpoint only returns the `software` objects for matching CPEs.\n\nThis endpoint is useful to find CPEs that can be used to filter CVEs.
            """
        ),
        filters=True,
    ),
    retrieve_objects=extend_schema(
        summary='Get a CPE object by STIX ID',
        description=textwrap.dedent(
            """
            Retrieve a single STIX `software` object for a CPE using its STIX ID. You can identify a STIX ID using the GET CPEs endpoint.
            """
        ),
        filters=False,
    ),
    retrieve_object_relationships=extend_schema(
        summary='Get Relationships for Object',
        description=textwrap.dedent(
            """
            Return relationships.
            """
        ),
        responses={200: ArangoDBHelper.get_paginated_response_schema('relationships', 'relationship')},
        parameters=ArangoDBHelper.get_schema_operation_parameters(),
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
    
    @extend_schema(
            parameters=[
                OpenApiParameter('relationship_type', enum=CPE_RELATIONSHIP_TYPES, allow_blank=False, description="either `vulnerable-to` or `in-pattern` (default is both)."),
                OpenApiParameter('sort', enum=CPE_REL_SORT_FIELDS, description="Sort results by"),
            ]
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:cpe_name>/relationships", detail=False)
    def retrieve_object_relationships(self, request, *args, cpe_name=None, **kwargs):
        return ArangoDBHelper(f'nvd_cpe_vertex_collection', request).get_cxe_object(cpe_name, type='software', var='cpe', relationship_mode=True)


@extend_schema_view(
    create=extend_schema(
        responses={201: serializers.JobSerializer
        },
        summary="Trigger arango_cti_processor `mode` to generate relationships.",
        description=textwrap.dedent(
            """
            This endpoint will link together knowledgebases based on the `mode` selected. For more information about how this works see [arango_cti_processor](https://github.com/muchdogesec/arango_cti_processor/), specifically the `--relationship` setting.

            The following key/values are accepted in the body of the request:

            * `ignore_embedded_relationships` (optional - default: `true`): arango_cti_processor generates SROs to link knowledge-bases. These SROs have embedded relationships inside them. Setting this to `true` (recommended) will generat SROs for these embedded relationships so they can be searched. `false` will ignore them
            * `modified_min` (optional - default: all time - format: `YYYY-MM-DDTHH:MM:SS.sssZ`): by default arango_cti_processor will run over all objects in the latest version of a framework (e.g. ATT&CK). This is not always effecient, espeically when updating CVE records. As such, you can ask the script to only consider objects with a `modified` time greater than that specified for this field.
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
        description=textwrap.dedent(
            """
            Search and filter Jobs. Jobs are triggered for each time a data download request is executed (e.g. GET ATT&CK). The response of these requests will contain a Job ID. Note, Jobs also include Arango CTI Processor runs to join the data together.

            Note, for job types `cpe-update` and `cve-update` you might see a lot of urls marked as `errors`. This is expected. This simply means there is no data for the day requested and the script is not smart enough to handle it gracefully.
            """
        ),
        summary="Get Jobs",
        responses={200: serializers.JobSerializer}
    ),
    retrieve=extend_schema(
        description=textwrap.dedent(
            """
            Get information about a specific Job. To retrieve a Job ID, use the GET Jobs endpoint.

            Note, for job types `cpe-update` and `cve-update` you might see a lot of urls marked as `errors`. This is expected. This simply means there is no data for the day requested and the script is not smart enough to handle it gracefully.
            """
        ),
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


class AttackView(viewsets.ViewSet):
    openapi_tags = ["ATT&CK"]
    serializer_class = serializers.MitreVersionsSerializer
    
    MATRIX_TYPES = ["mobile", "ics", "enterprise"]
    @property
    def matrix(self):
        m: re.Match = re.search(r"/attack-(\w+)/", self.request.path)
        return m.group(1)

    def create(self, request, *args, **kwargs):
        serializer = serializers.MitreTaskSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.data.copy()
        data['matrix'] = self.matrix
        job = new_task(data, models.JobType.ATTACK_UPDATE)
        job_s = serializers.JobSerializer(instance=job)
        return Response(job_s.data, status=status.HTTP_201_CREATED)
    
    @decorators.action(detail=False, methods=["GET"])
    def versions(self, request, *args, **kwargs):
        return ArangoDBHelper(f'mitre_attack_{self.matrix}_vertex_collection', request).get_mitre_versions()

    @classmethod
    def attack_view(cls, matrix_name: str):
        matrix_name_human = matrix_name.title()
        if matrix_name == 'ics':
            matrix_name_human = "ICS"

        
        @extend_schema_view(
            create=extend_schema(
                responses={
                    201: OpenApiResponse(
                        serializers.JobSerializer,
                        examples=[
                            OpenApiExample(
                                "",
                                value={
                                    "id": "fbc43f28-6929-4b55-9559-326191701e48",
                                    "type": "attack-update",
                                    "state": "pending",
                                    "errors": [],
                                    "run_datetime": "2024-10-25T14:21:02.850924Z",
                                    "completion_time": "2024-10-25T14:22:09.966635Z",
                                    "parameters": {
                                        "matrix": matrix_name,
                                        "version": "1_0",
                                        "ignore_embedded_relationships": True,
                                    },
                                },
                            )
                        ],
                    ),
                    400: DEFAULT_400_ERROR
                },
                request=serializers.MitreTaskSerializer,
                summary=f"Download MITRE ATT&CK {matrix_name_human} Objects",
                description=textwrap.dedent(
                    """
                    Use this endpoint to update MITRE ATT&CK records. [More information about MITRE ATT&CK here](https://attack.mitre.org/).

                    The following key/values are accepted in the body of the request:

                    * `version` (required): the version of ATT&CK you want to download in the format `N_N`, e.g. `15_1` for `15.1`. You can see all [Enterprise versions here](https://github.com/muchdogesec/stix2arango/blob/main/utilities/arango_cti_processor/insert_archive_attack_enterprise.py#L7), [Mobile versions here](https://github.com/muchdogesec/stix2arango/blob/main/utilities/arango_cti_processor/insert_archive_attack_mobile.py#L7), or [ICS versions here](https://github.com/muchdogesec/stix2arango/blob/main/utilities/arango_cti_processor/insert_archive_attack_ics.py#L7).
                    * `ignore_embedded_relationships` (optional - default: `false`): Most objects contains embedded relationships inside them (e.g. `created_by_ref`). Setting this to `false` (recommended) will get stix2arango to generate SROs for these embedded relationships so they can be searched. `true` will ignore them.

                    The data for updates is requested from `https://downloads.ctibutler.com` (managed by the [DOGESEC](https://www.dogesec.com/) team).

                    Successful request will return a job `id` that can be used with the GET Jobs endpoint to track the status of the import.
                    """
                ),
            ),
            versions=extend_schema(
                summary=f"Get a list of MITRE ATT&CK {matrix_name_human} versions stored in the database",
                description=textwrap.dedent(
                    """
                    It is possible to import multiple versions of ATT&CK using the POST MITRE ATT&CK {matrix_name_human} endpoint. By default, all endpoints will only return the latest version of ATT&CK objects (which generally suits most use-cases).

                    This endpoint allows you to see all imported versions of MITRE ATT&CK {matrix_name_human} available to use, and which version is the latest (the default version for the objects returned).
                    """
                ),
            ),
        )  
        class TempAttackView(cls):
            matrix = matrix_name
            openapi_tags = [f"ATT&CK {matrix_name_human}"]
        TempAttackView.__name__ = f'{matrix_name.title()}AttackView'
        return TempAttackView


@extend_schema_view(
    create=extend_schema(
        responses={
            201: OpenApiResponse(
                serializers.JobSerializer,
                examples=[
                    OpenApiExample(
                        "",
                        value={
                            "id": "85e78220-6387-4be1-81ea-b8373c89aa92",
                            "type": "cwe-update",
                            "state": "pending",
                            "errors": [],
                            "run_datetime": "2024-10-25T10:39:25.925090Z",
                            "completion_time": "2024-10-25T10:39:41.551515Z",
                            "parameters": {"version": "4_15"},
                        },
                    )
                ],
            ),
            400: DEFAULT_400_ERROR,
        },
        request=serializers.MitreTaskSerializer,
        summary="Download MITRE CWE objects",
        description=textwrap.dedent(
            """
            Use this data to update CWE records. [More information about MITRE CWE here](https://cwe.mitre.org/).

            The following key/values are accepted in the body of the request:

            * `version` (required): the version of CWE you want to download in the format `N_N`, e.g. `4_14` for `4.14`. [Currently available versions can be viewed here](https://github.com/muchdogesec/stix2arango/blob/main/utilities/arango_cti_processor/insert_archive_cwe.py#L7).
            * `ignore_embedded_relationships` (optional - default: `false`): Most objects contains embedded relationships inside them (e.g. `created_by_ref`). Setting this to `false` (recommended) will get stix2arango to generate SROs for these embedded relationships so they can be searched. `true` will ignore them.

            The data for updates is requested from `https://downloads.ctibutler.com` (managed by the [DOGESEC](https://www.dogesec.com/) team).

            Successful request will return a job `id` that can be used with the GET Jobs endpoint to track the status of the import.
            """
        ),
    ),
    versions=extend_schema(
        summary="See available CWE versions",
        description=textwrap.dedent(
            """
            It is possible to import multiple versions of CWE using the POST MITRE CWE endpoint. By default, all endpoints will only return the latest version of CWE objects (which generally suits most use-cases).

            This endpoint allows you to see all imported versions of MITRE CWE available to use, and which version is the latest (the default version for the objects returned).
            """
        ),
    ),
)
class CweView(viewsets.ViewSet):
    openapi_tags = ["CWE"]
    serializer_class = serializers.MitreVersionsSerializer


    def create(self, request, *args, **kwargs):
        serializer = serializers.MitreTaskSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.data.copy()
        job = new_task(data, models.JobType.CWE_UPDATE)
        job_s = serializers.JobSerializer(instance=job)
        return Response(job_s.data, status=status.HTTP_201_CREATED)


    @decorators.action(detail=False, methods=["GET"])
    def versions(self, request, *args, **kwargs):
        return ArangoDBHelper(f'mitre_cwe_vertex_collection', request).get_mitre_versions()


@extend_schema_view(
    create=extend_schema(
        responses={
            201: OpenApiResponse(
                serializers.JobSerializer,
                examples=[
                    OpenApiExample(
                        "",
                        value={
                            "id": "d18c2179-3b05-4d24-bd34-d4935ad30e23",
                            "type": "capec-update",
                            "state": "pending",
                            "errors": [],
                            "run_datetime": "2024-10-25T10:38:25.850756Z",
                            "completion_time": "2024-10-25T10:38:39.369972Z",
                            "parameters": {"version": "3_9"},
                        },
                    )
                ],
            ),
            400: DEFAULT_400_ERROR,
        },
        request=serializers.MitreTaskSerializer,
        summary="Download MITRE CAPEC objects",
        description=textwrap.dedent(
            """
            Use this data to update MITRE CAPEC records. [More information about MITRE CAPEC here](https://capec.mitre.org/).

            The following key/values are accepted in the body of the request:

            * `version` (required): the version of CAPEC you want to download in the format `N_N`, e.g. `3_9` for `3.9`. [Currently available versions can be viewed here](https://github.com/muchdogesec/stix2arango/blob/main/utilities/arango_cti_processor/insert_archive_capec.py#L7).
            * `ignore_embedded_relationships` (optional - default: `false`): Most objects contains embedded relationships inside them (e.g. `created_by_ref`). Setting this to `false` (recommended) will get stix2arango to generate SROs for these embedded relationships so they can be searched. `true` will ignore them.

            The data for updates is requested from `https://downloads.ctibutler.com` (managed by the [DOGESEC](https://www.dogesec.com/) team).

            Successful request will return a job `id` that can be used with the GET Jobs endpoint to track the status of the import.
            """
        ),
    ),
    versions=extend_schema(
        summary="Get a list of CAPEC versions stored in the database",
        description=textwrap.dedent(
            """
            It is possible to import multiple versions of CAPEC using the POST MITRE CAPEC endpoint. By default, all endpoints will only return the latest version of CAPEC objects (which generally suits most use-cases).

            This endpoint allows you to see all imported versions of MITRE CAPEC available to use, and which version is the latest (the default version for the objects returned).
            """
        ),
    ),
)
class CapecView(viewsets.ViewSet):
    openapi_tags = ["CAPEC"]
    serializer_class = serializers.MitreVersionsSerializer
    
    def create(self, request, *args, **kwargs):
        serializer = serializers.MitreTaskSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.data.copy()
        job = new_task(data, models.JobType.CAPEC_UPDATE)
        job_s = serializers.JobSerializer(instance=job)
        return Response(job_s.data, status=status.HTTP_201_CREATED)
    

    @decorators.action(detail=False, methods=["GET"])
    def versions(self, request, *args, **kwargs):
        return ArangoDBHelper(f'mitre_capec_vertex_collection', request).get_mitre_versions()
