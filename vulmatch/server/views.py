import os
from urllib.parse import urljoin
import requests
from rest_framework import viewsets, status, decorators

from vulmatch.server.arango_helpers import CPE_REL_SORT_FIELDS, CPE_RELATIONSHIP_TYPES, CVE_BUNDLE_TYPES, CVE_SORT_FIELDS, EPSS_SORT_FIELDS, KEV_SORT_FIELDS, VulmatchDBHelper
from dogesec_commons.utils import Pagination, Ordering
from vulmatch.worker.tasks import new_task
from . import models
from vulmatch.server import serializers
from django_filters.rest_framework import FilterSet, Filter, DjangoFilterBackend, ChoiceFilter, BaseCSVFilter, CharFilter, BooleanFilter, MultipleChoiceFilter, NumberFilter, DateTimeFilter
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiParameter
from drf_spectacular.types import OpenApiTypes


import textwrap
from drf_spectacular.views import SpectacularAPIView
from rest_framework.response import Response

class SchemaViewCached(SpectacularAPIView):
    _schema = None
    
    def _get_schema_response(self, request):
        version = self.api_version or request.version or self._get_version_parameter(request)
        if not self.__class__._schema:
            generator = self.generator_class(urlconf=self.urlconf, api_version=version, patterns=self.patterns)
            self.__class__._schema = generator.get_schema(request=request, public=self.serve_public)
        return Response(
            data=self.__class__._schema,
            headers={"Content-Disposition": f'inline; filename="{self._get_filename(request, version)}"'}
        )


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
            * `ignore_embedded_relationships` (optional - default: `true`): Most objects contains embedded relationships inside them (e.g. `created_by_ref`). Setting this to `false` is not recommended as it will get stix2arango to generate SROs for these embedded relationships so they can be searched (this will create millions of additional relationships). `true` will ignore them. This is a stix2arango setting.
            * `ignore_embedded_relationships_sro` (optional): boolean, if `true` passed (recommended), will stop any embedded relationships from being generated from SRO objects (`type` = `relationship`). Default is `true`. This is a stix2arango setting.
            * `ignore_embedded_relationships_smo` (optional): boolean, if `true` passed (recommended), will stop any embedded relationships from being generated from SMO objects (`type` = `marking-definition`, `extension-definition`, `language-content`). Default is `true`. This is a stix2arango setting.

            The data for updates is requested from `https://cve2stix.vulmatch.com` (managed by the [DOGESEC](https://www.dogesec.com/) team).
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
        responses={200: VulmatchDBHelper.get_paginated_response_schema('objects', 'vulnerability')},
        parameters=VulmatchDBHelper.get_schema_operation_parameters(),
    ),
    retrieve_object_relationships=extend_schema(
        summary='Get Relationships for Vulnerability by CVE ID',
        description=textwrap.dedent(
            """
            This endpoint will return all SROs where the Vulnerability selected is either a `source_ref` or a `target_ref`. This allows you to quickly find out what objects the CVE is related to.
            """
        ),
        responses={200: VulmatchDBHelper.get_paginated_response_schema('relationships', 'relationship')},
        parameters=VulmatchDBHelper.get_schema_operation_parameters(),
    ),
    bundle=extend_schema(
        summary='Get all objects for a Vulnerability by CVE ID',
        description=textwrap.dedent(
            """
            This endpoint will return the vulnerability itself and all objects related to the Vulnerability. Use this endpoint to get the complete intelligence graph for this Vulnerability.

            The results can include the following:

            * `vulnerability`: Represents the CVE (source: cve2stix)
            * `indicator`: Contains a pattern identifying products affected by the CVE (source: cve2stix)
            * `relationship` (`indicator`->`vulnerability`) (source: cve2stix)
            * `report`: Represents EPSS scores for the Vulnerability (source: cve2stix)
            * `report`: Represents CISA KEVs for the Vulnerability (source: cve2stix)
            * `software`: Represents the products listed in the pattern (source: cve2stix)
            * `relationship` (`indicator`->`software`) (source: cve2stix)
            * `weakness` (CWE): represents CWEs linked to the Vulnerability (source: arango_cve_processor, requires `cve-cwe` mode to be run)
            * `relationship` (`vulnerability` (CVE) -> `weakness` (CWE)) (source: arango_cve_processor, requires `cve-cwe` mode to be run)
            * `attack-pattern` (CAPEC): represents CAPECs linked to the Vulnerability (source: arango_cve_processor, requires `cve-capec` mode to be run)
            * `relationship` (`vulnerability` (CVE) -> `attack-pattern` (CAPEC)) (source: arango_cve_processor, requires `cve-capec` mode to be run)
            * `attack-pattern` (ATT&CK Enterprise): represents ATT&CKs linked to the Vulnerability (source: arango_cve_processor, requires `cve-attack` mode to be run)
            * `relationship` (`vulnerability` (CVE) ->  `attack-pattern` (ATT&CK)) (source: arango_cve_processor, requires `cve-attack` mode to be run)
            """
        ),
        responses={200: VulmatchDBHelper.get_paginated_response_schema('objects', 'vulnerability')},
        parameters=VulmatchDBHelper.get_schema_operation_parameters() + [
            OpenApiParameter('object_type', description="The type of STIX object to be returned", enum=CVE_BUNDLE_TYPES, many=True, explode=False),
            OpenApiParameter('include_cpe', description="will show all `software` objects related to this vulnerability (and the SROS linking cve-cpe)", type=OpenApiTypes.BOOL),
            OpenApiParameter('include_cpe_vulnerable', description="will show `software` objects vulnerable to this vulnerability (and the SROS), if exist. Note `include_cpe` should be set to `false` if you only want to see vulnerable cpes (and the SROS linking cve-cpe)", type=OpenApiTypes.BOOL),
            OpenApiParameter('include_cwe', description="will show `weakness` objects related to this vulnerability, if exist (and the SROS linking cve-cwe)", type=OpenApiTypes.BOOL),
            OpenApiParameter('include_epss', description="will show `note` objects related to this vulnerability, if exist", type=OpenApiTypes.BOOL),
            OpenApiParameter('include_kev', description="will show `sighting` objects related to this vulnerability, if exist (and the SROS linking cve-sighting)", type=OpenApiTypes.BOOL),
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
        OpenApiParameter('cve_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The CVE ID, e.g `CVE-2023-22518`'),

    ]

    class filterset_class(FilterSet):
        stix_id = MultipleChoiceFilter(help_text=textwrap.dedent(
            """
            Filter the results using the STIX ID of a `vulnerability` object. e.g. `vulnerability--4d2cad44-0a5a-5890-925c-29d535c3f49e`.
            """
        ))
        cve_id = CharFilter(help_text=textwrap.dedent(
            """
            Filter the results using a CVE ID. e.g. `CVE-2023-22518`
            """
        ))
        description = CharFilter(help_text=textwrap.dedent(
            """
            Filter the results by the description of the Vulnerability. Search is a wildcard, so `exploit` will return all descriptions that contain the string `exploit`.'
            """
        ))
        has_kev = BooleanFilter(help_text=textwrap.dedent(
            """
            Optionally filter the results to only include those reported by CISA KEV (Known Exploited Vulnerability).
            """
        ))
        cpes_vulnerable = BaseCSVFilter(help_text=textwrap.dedent(
            """
            Filter Vulnerabilities that are vulnerable to a full CPE Match String (e.g. `cpe:2.3:o:microsoft:windows_10_1607:-:*:*:*:*:*:x86:*`, `cpe:2.3:o:microsoft:windows_10_1607:-:*:*:*:*:*:x64:*`, etc.)
            """
        ))
        cpes_in_pattern = BaseCSVFilter(help_text=textwrap.dedent(
            """
            Filter Vulnerabilities that contain a full CPE Match String. Note, this will return Vulnerabilities that are vulnerable and not vulnerable (e.g. an operating system might not be vulnerable, but it might be required for software running on it to be vulnerable). (e.g. `cpe:2.3:o:microsoft:windows_10_1607:-:*:*:*:*:*:x86:*`, `cpe:2.3:o:microsoft:windows_10_1607:-:*:*:*:*:*:x64:*`, etc.)
            """
        ))
        weakness_id = BaseCSVFilter(help_text=textwrap.dedent(
            """
            Filter results by weakness (CWE ID). e.g. `CWE-122`. `cve-cwe` mode must be run in Arango CVE Processor first for this to work.
            """
        ))
        cvss_base_score_min = NumberFilter(help_text=textwrap.dedent(
            """
            The minimum CVSS score you want. `0` is lowest, `10` is highest. Note, some CVEs have multiple CVSS scores. This filter will use the base score from the highest version of CVSS reported (e.g. v4.0 over v3.1) and always use the primary source reporting the CVSS if it exist.
            """
        ))
        epss_score_min = NumberFilter(help_text=textwrap.dedent(
            """
            The minimum EPSS score you want. Between `0` (lowest) and `1` highest to 2 decimal places (e.g. `9.34`).
            """
        ))
        epss_percentile_min = NumberFilter(help_text=textwrap.dedent(
            """
            The minimum EPSS percentile you want. Between `0` (lowest) and `1` highest to 2 decimal places (e.g. `9.34`).
            """
        ))
        created_min = DateTimeFilter(help_text=textwrap.dedent(
            """
            Is the minimum `created` value (`YYYY-MM-DDThh:mm:ss.sssZ`)
            """
        ))
        created_max = DateTimeFilter(help_text=textwrap.dedent(
            """
            Is the maximum `created` value (`YYYY-MM-DDThh:mm:ss.sssZ`)
            """
        ))
        modified_min = DateTimeFilter(help_text=textwrap.dedent(
            """
            Is the minimum `modified` value (`YYYY-MM-DDThh:mm:ss.sssZ`)
            """
        ))
        modified_max = DateTimeFilter(help_text=textwrap.dedent(
            """
            Is the maximum `modified` value (`YYYY-MM-DDThh:mm:ss.sssZ`)
            """
        ))
        sort = ChoiceFilter(choices=[(v, v) for v in CVE_SORT_FIELDS], help_text=textwrap.dedent(
            """
            Sort results by
            """
        ))
        vuln_status = ChoiceFilter(choices=VulnerabilityStatus.choices, help_text=textwrap.dedent(
            """
            Filter by the Vulnerability status.
            """
        ))

        attack_id = BaseCSVFilter(help_text=textwrap.dedent(
            """
            Filter results by weakness (ATT&CK ID). e.g. `T1223`.\n\n
            filters using the `description` property of `cve-attack` relationship object
            """
        ))
        capec_id = BaseCSVFilter(help_text=textwrap.dedent(
            """
            Filter results by weakness (CAPEC ID). e.g. `CAPEC-665`.\n\n
            filters using the `description` property of `cve-capec` relationship object
            """
        ))


    def create(self, request, *args, **kwargs):
        serializer = serializers.NVDTaskSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        job = new_task(serializer.data, models.JobType.CVE_UPDATE)
        job_s = serializers.JobSerializer(instance=job)
        return Response(job_s.data, status=status.HTTP_201_CREATED)
    
    @decorators.action(methods=['GET'], url_path="objects", detail=False)
    def list_objects(self, request, *args, **kwargs):
        return VulmatchDBHelper('', request).get_vulnerabilities()
    
    @decorators.action(methods=['GET'], detail=False, url_path="objects/<str:cve_id>/bundle")
    def bundle(self, request, *args, cve_id=None, **kwargs):
        return VulmatchDBHelper('', request).get_cve_bundle(cve_id)
    
    @extend_schema(
            parameters=[
                OpenApiParameter("cve_version", type=OpenApiTypes.DATETIME, description="Return only vulnerability object where `modified` value matches query")
            ]
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:cve_id>", detail=False)
    def retrieve_objects(self, request, *args, cve_id=None, **kwargs):
        return VulmatchDBHelper('nvd_cve_vertex_collection', request).get_cxe_object(cve_id)
    
    @extend_schema(
            parameters=[
                OpenApiParameter("cve_version", type=OpenApiTypes.DATETIME, description="Return only vulnerability object where `modified` value matches query")
            ]
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:cve_id>/relationships", detail=False)
    def retrieve_object_relationships(self, request, *args, cve_id=None, **kwargs):
        return VulmatchDBHelper('nvd_cve_vertex_collection', request).get_cxe_object(cve_id, relationship_mode=True)
    
    @decorators.action(detail=False, url_path="objects/<str:cve_id>/versions", methods=["GET"], pagination_class=Pagination('versions'))
    def versions(self, request, *args, cve_id=None, **kwargs):
        return VulmatchDBHelper('nvd_cve_vertex_collection', request).get_cve_versions(cve_id)

@extend_schema_view(
    list_objects=extend_schema(
        responses={200: serializers.StixObjectsSerializer(many=True)}, filters=True,
        summary="Get KEV Objects for CVEs",
        description=textwrap.dedent(
            """
            Search and filter [CISA KEV records](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).

            This endpoint returns `report` objects with the `labels` = `kev` for CVEs.

            **IMPORTANT:** You need to run Arango CVE Processor in `cve-kev` mode to generate these reports.
            """
        ),
    ),
    retrieve_objects=extend_schema(
        summary='Get a KEV Report by CVE ID',
        description=textwrap.dedent(
            """
            Use this endpoint to get a KEV `report` object using the CVE ID.

            If there is no KEV reported for the CVE, the response will be empty.
            """
        ),
        responses={200: VulmatchDBHelper.get_paginated_response_schema('objects', 'report')},
        parameters=VulmatchDBHelper.get_schema_operation_parameters(),
    ),
)  
class KevView(viewsets.ViewSet):

    openapi_tags = ["KEV"]
    pagination_class = Pagination("objects")
    filter_backends = [DjangoFilterBackend]
    serializer_class = serializers.StixObjectsSerializer(many=True)
    lookup_url_kwarg = 'cve_id'
    label = "kev"

    openapi_path_params = [
        OpenApiParameter('cve_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The CVE ID, e.g `CVE-2023-22518`'),

    ]
    class filterset_class(FilterSet):
        cve_id = CharFilter(help_text=textwrap.dedent(
            """
            Filter the results using a CVE ID. e.g. `CVE-2024-23897`
            """
        ))
        
    @extend_schema(
            parameters=[
                OpenApiParameter('sort', enum=KEV_SORT_FIELDS, description="Sort results by"),
            ]
    )
    @decorators.action(methods=['GET'], url_path="objects", detail=False)
    def list_objects(self, request, *args, **kwargs):
        return VulmatchDBHelper('', request).list_kev_or_epss_objects(self.label)
    

    @decorators.action(methods=['GET'], url_path="objects/<str:cve_id>", detail=False)
    def retrieve_objects(self, request, *args, cve_id=None, **kwargs):
        return VulmatchDBHelper('nvd_cve_vertex_collection', request).retrieve_kev_or_epss_object(cve_id, self.label)

@extend_schema_view(
    list_objects=extend_schema(
        summary="Get EPSS Objects for CVEs",
        description=textwrap.dedent(
            """
            Search and filter EPSS `report` objects for CVEs.

            This endpoint returns `report` objects with the `labels` = `epss`.

            **IMPORTANT:** You need to run Arango CVE Processor in `cve-epss` mode to generate these reports.
            """
        ),
        parameters=[
            OpenApiParameter('sort', enum=EPSS_SORT_FIELDS, description="Sort results by"),
            OpenApiParameter('epss_min_score', type=OpenApiTypes.FLOAT, description="minimum epss score"),
        ],
    ),
    retrieve_objects=extend_schema(
        summary='Get a EPSS Report by CVE ID',
        description=textwrap.dedent(
            """
            Use this endpoint to get an EPSS `report` object using the CVE ID.

            Every CVE has an EPSS score that can change over time. EPSS report objects can be used to track the change in EPSS score over time.
            """
        ),
    ),
)     
class EPSSView(KevView):
    openapi_tags = ["EPSS"]
    label = "epss"


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
            Search and filter CPE records.

            This endpoint only returns the `software` objects for matching CPEs.

            This endpoint is useful to find CPEs that can be used to filter CVEs.
            """
        ),
        filters=True,
    ),
    retrieve_objects=extend_schema(
        summary='Get a CPE object by STIX ID',
        description=textwrap.dedent(
            """
            Retrieve a single STIX `software` object for a CPE using its STIX ID. You can identify a CPE ID using the GET CPEs endpoint.
            """
        ),
        filters=False,
    ),
    retrieve_object_relationships=extend_schema(
        summary='Get Relationships for Object',
        description=textwrap.dedent(
            """
            This endpoint will return all SROs where the Software (CPE) selected is either a `source_ref` or a `target_ref`. This allows you to quickly find out what CVEs the CPE is found in.
            """
        ),
        responses={200: VulmatchDBHelper.get_paginated_response_schema('relationships', 'relationship')},
        parameters=VulmatchDBHelper.get_schema_operation_parameters(),
    ),
) 
class CpeView(viewsets.ViewSet):
    openapi_tags = ["CPE"]
    pagination_class = Pagination("objects")
    filter_backends = [DjangoFilterBackend]
    serializer_class = serializers.StixObjectsSerializer(many=True)
    lookup_url_kwarg = 'stix_id'
    openapi_path_params = [
        OpenApiParameter('stix_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The full STIX `id` of the object. e.g. `software--93ff5b30-0322-50e8-90c1-1c3f151c8adc`'),
        OpenApiParameter('cpe_name', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The full CPE name. e.g. `cpe:2.3:a:slicewp:affiliate_program_suite:1.0.13:*:*:*:*:wordpress:*:*`'),
    ]

    
    class filterset_class(FilterSet):
        id = BaseCSVFilter(help_text=textwrap.dedent(
            """
            Filter the results by the STIX ID of the `software` object. e.g. `software--93ff5b30-0322-50e8-90c1-1c3f151c8adc`
            """
        ))
        cpe_match_string = CharFilter(help_text=textwrap.dedent(
            """
            Filter CPEs that contain a full or partial CPE Match String. Search is a wildcard to support partial match strings (e.g. `cpe:2.3:o:microsoft:windows` will match `cpe:2.3:o:microsoft:windows_10_1607:-:*:*:*:*:*:x86:*`, `cpe:2.3:o:microsoft:windows_10_1607:-:*:*:*:*:*:x64:*`, etc.
            """
        ))
        vendor = CharFilter(help_text=textwrap.dedent(
            """
            Filters CPEs returned by vendor name. Is wildcard search so `goog` will match `google`, `googe`, etc. (this is the 3ed value in the CPE URI).
            """
        ))
        product = CharFilter(help_text=textwrap.dedent(
            """
            Filters CPEs returned by product name. Is wildcard search so `chrom` will match `chrome`, `chromium`, etc. (this is the 4th value in the CPE URI).
            """
        ))
        product_type = ChoiceFilter(choices=[('operating-system', 'Operating System'), ('application', 'Application'), ('hardware', 'Hardware')],
                        help_text=textwrap.dedent(
            """
            Filters CPEs returned by product type (this is the 2nd value in the CPE URI).
            """
        ))
        cve_vulnerable = BaseCSVFilter(help_text=textwrap.dedent(
            """
            Filters CPEs returned to those vulnerable to CVE ID specified. e.g. `CVE-2023-22518`.
            """
        ))
        in_cve_pattern = BaseCSVFilter(help_text=textwrap.dedent(
            """
            Filters CPEs returned to those referenced CVE ID specified (if you want to only filter by vulnerable CPEs, use the `cve_vulnerable` parameter. e.g. `CVE-2023-22518`.
            """
        ))

        ### more filters
        version = CharFilter(help_text='Vendor-specific alphanumeric strings characterising the particular release version of the product (this is the 5th value in the CPE URI).')
        update = CharFilter(help_text='Vendor-specific alphanumeric strings characterising the particular update, service pack, or point release of the product (this is the 6th value in the CPE URI).')
        edition = CharFilter(help_text='Assigned the logical value ANY (*) except where required for backward compatibility with version 2.2 of the CPE specification (this is the 7th value in the CPE URI).')
        language = CharFilter(help_text='Valid language tags as defined by RFC5646 (this is the 8th value in the CPE URI).')
        sw_edition = CharFilter(help_text='Characterises how the product is tailored to a particular market or class of end users (this is the 9th value in the CPE URI).')
        target_sw = CharFilter(help_text='Characterises the software computing environment within which the product operates (this is the 10th value in the CPE URI).')
        target_hw = CharFilter(help_text='Characterises the instruction set architecture (e.g., x86) on which the product being described or identified operates (this is the 11th value in the CPE URI).')
        other = CharFilter(help_text='Capture any other general descriptive or identifying information which is vendor- or product-specific and which does not logically fit in any other attribute value (this is the 12th value in the CPE URI).')
    
    @decorators.action(methods=['GET'], url_path="objects", detail=False)
    def list_objects(self, request, *args, **kwargs):
        return VulmatchDBHelper('', request).get_softwares()

    @decorators.action(methods=['GET'], url_path="objects/<str:cpe_name>", detail=False)
    def retrieve_objects(self, request, *args, cpe_name=None, **kwargs):
        return VulmatchDBHelper(f'nvd_cve_vertex_collection', request).get_cxe_object(cpe_name, type='software', var='cpe')
    
    @extend_schema(
            parameters=[
                OpenApiParameter('relationship_type', enum=CPE_RELATIONSHIP_TYPES, allow_blank=False, description="either `vulnerable-to` or `in-pattern` (default is both)."),
                OpenApiParameter('sort', enum=CPE_REL_SORT_FIELDS, description="Sort results by"),
            ]
    )
    @decorators.action(methods=['GET'], url_path="objects/<str:cpe_name>/relationships", detail=False)
    def retrieve_object_relationships(self, request, *args, cpe_name=None, **kwargs):
        return VulmatchDBHelper(f'nvd_cve_vertex_collection', request).get_cxe_object(cpe_name, type='software', var='cpe', relationship_mode=True)


@extend_schema_view(
    create=extend_schema(
        responses={201: serializers.JobSerializer
        },
        summary="Trigger arango_cve_processor `mode` to generate relationships.",
        description=textwrap.dedent(
            """
            This endpoint will link together knowledgebases based on the `mode` selected. For more information about how this works see [arango_cve_processor](https://github.com/muchdogesec/arango_cve_processor/), specifically the `--relationship` setting.

            The following key/values are accepted in the body of the request:

            * `ignore_embedded_relationships` (optional - default: `false`): arango_cve_processor generates SROs to link knowledge-bases. These SROs have embedded relationships inside them. Setting this to `false` is generally recommended, but ALWAYS when running `cve-epss` and `cve-kev` to ensure the Report objects created are correctly joined to the CVE.
            * `ignore_embedded_relationships_sro` (optional): boolean, if `true` passed (recommended), will stop any embedded relationships from being generated from SRO objects (`type` = `relationship`). Default is `true`. This is a stix2arango setting.
            * `ignore_embedded_relationships_smo` (optional): boolean, if `true` passed (recommended), will stop any embedded relationships from being generated from SMO objects (`type` = `marking-definition`, `extension-definition`, `language-content`). Default is `true`. This is a stix2arango setting.
            * `modified_min` (optional - default: all time - format: `YYYY-MM-DDTHH:MM:SS.sssZ`): by default arango_cve_processor will run over all objects in the latest version of a framework (e.g. ATT&CK). This is not always efficient, especially when updating CVE records. As such, you can ask the script to only consider objects with a `modified` time greater than that specified for this field.
            * `created_min` (optional - default: all time- format: `YYYY-MM-DDTHH:MM:SS.sssZ`): same as `modified_min`, but this time considers `created` time of the object (not `modified` time).
            """
        ),
    ),
)
class ACPView(viewsets.ViewSet):
    openapi_tags = ["Arango CVE Processor"]
    serializer_class = serializers.ACPSerializer
    openapi_path_params = [
            OpenApiParameter(name='mode', enum=list(serializers.ACP_MODES), location=OpenApiParameter.PATH, description='The  [`arango_cve_processor`](https://github.com/muchdogesec/arango_cve_processor/) `--relationship` mode.')
    ]

    def create(self, request, *args, **kwargs):
        serializers.ACPSerializer(data=request.data).is_valid(raise_exception=True)
        serializer = serializers.ACPSerializerWithMode(data={**request.data, **kwargs})
        serializer.is_valid(raise_exception=True)
        data = serializer.data.copy()
        job = new_task(data, models.JobType.CVE_PROCESSOR)
        job_s = serializers.JobSerializer(instance=job)
        return Response(job_s.data, status=status.HTTP_201_CREATED)

@extend_schema_view(
    list=extend_schema(
        description=textwrap.dedent(
            """
            Search and filter Jobs. Jobs are triggered for each time a data download request is executed (e.g. GET ATT&CK). The response of these requests will contain a Job ID. Note, Jobs also include Arango CVE Processor runs to join the data together.
            """
        ),
        summary="Get Jobs",
        responses={200: serializers.JobSerializer}
    ),
    retrieve=extend_schema(
        description=textwrap.dedent(
            """
            Get information about a specific Job. To retrieve a Job ID, use the GET Jobs endpoint.
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
                type = models.JobType.CVE_PROCESSOR
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


@extend_schema_view(
    list=extend_schema(
        responses={204: {}},
        summary="Check if the service is running",
        description=textwrap.dedent(
            """
        If this endpoint returns a 204, the service is running as expected.
        """
        ),
    ),
    service=extend_schema(
        responses={200: serializers.HealthCheckSerializer},
        summary="Check the status of all external dependencies",
        description="Check the status of all external dependencies",
    ),
)
class HealthCheck(viewsets.ViewSet):
    openapi_tags = ["Server Status"]

    def list(self, request, *args, **kwargs):
        return Response(status=status.HTTP_204_NO_CONTENT)

    @decorators.action(detail=False)
    def service(self, request, *args, **kwargs):
        return Response(status=200, data=dict(ctibutler=self.check_ctibutler()))

    @staticmethod
    def check_ctibutler():
        base_url = os.getenv("CTIBUTLER_BASE_URL")
        if not base_url:
            return "not-configured"
        try:
            resp = requests.get(
                urljoin(base_url, "v1/location/versions/available/"),
                headers={"API-KEY": os.getenv("CTIBUTLER_API_KEY")},
            )
            match resp.status_code:
                case 401 | 403:
                    return "unauthorized"
                case 200:
                    return "authorized"
                case _:
                    return "unknown"
        except:
            return "offline"
