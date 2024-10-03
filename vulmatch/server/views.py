import re
from django.shortcuts import render
from rest_framework import viewsets, filters, status, decorators

from vulmatch.server.arango_helpers import ArangoDBHelper, ATTACK_TYPES, CWE_TYPES, SOFTWARE_TYPES, CAPEC_TYPES
from vulmatch.server.utils import Pagination, Response, Ordering, split_mitre_version
from vulmatch.worker.tasks import new_task
from . import models
from vulmatch.server import serializers
from django_filters.rest_framework import FilterSet, Filter, DjangoFilterBackend, ChoiceFilter, BaseCSVFilter, CharFilter, BooleanFilter, MultipleChoiceFilter
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiParameter
from drf_spectacular.types import OpenApiTypes
from arango_cti_processor.config import MODE_COLLECTION_MAP
from textwrap import dedent
# Create your views here.

@extend_schema_view(
    create=extend_schema(
        responses={201: serializers.JobSerializer
        },
        request=serializers.NVDTaskSerializer,
        summary="Download data for CVEs",
        description="Use this data to update the CVE records.\n\nThe earliest CVE record has a `modified` value of `2007-07-13T04:00:00.000Z`. That said, as a rough guide, we recommend downloading CVEs from `last_modified_earliest` = `2020-01-01` because anything older than this is _generally_ stale.\n\nThe easiest way to identify the last update time used (to keep CVE records current) is to use the jobs endpoint which will show the `last_modified_earliest` and `last_modified_latest` dates used.\n\n`last_modified_earliest` and `last_modified_latest` dates should be in the format `YYYY-MM-DD`.\n\nThe data for updates is requested from `https://downloads.ctibutler.com` (managed by the [DOGESEC](https://www.dogesec.com/) team).",
    ),
    list=extend_schema(
        responses={200: serializers.StixObjectsSerializer}, filters=True,
        summary="Get Vulnerability Objects for CVEs",
        description="Search and filter CVE records.\n\nThis endpoint only returns the vulnerability objects for matching CVEs. Once you have the CVE ID you want, you can get all associated data linked to it (e.g. Indicator Objects) using the bundle endpoint.",
    ),
    retrieve=extend_schema(
        summary='Get a Vulnerability by STIX ID',
        description='This endpoint only returns the vulnerability object for CVE. Typically you want to use the endpoint Get all objects for a Vulnerability by STIX ID. You can identify the STIX ID of a CVE using the GET CVE endpoint if needed.',
        responses={200: ArangoDBHelper.get_paginated_response_schema('vulnerabilities', 'vulnerability')}
    ),
    bundle=extend_schema(
        summary='Get all objects for a Vulnerability by STIX ID',
        description='This endpoint will return Vulnerability, Indicator, and Software STIX objects for the CVE ID. It will also include any STIX SROs defining the relationships between them.',
        responses={200: ArangoDBHelper.get_paginated_response_schema('vulnerabilities', 'vulnerability')},
        parameters=ArangoDBHelper.get_schema_operation_parameters(),
    ),
)   
class CveView(viewsets.ViewSet):
    openapi_tags = ["CVE"]
    pagination_class = Pagination("vulnerabilities")
    filter_backends = [DjangoFilterBackend]
    serializer_class = serializers.JobSerializer
    lookup_url_kwarg = 'stix_id'
    openapi_path_params = [
        OpenApiParameter('stix_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The STIX ID'),
        OpenApiParameter('cve_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The CVE ID'),

    ]

    
    class filterset_class(FilterSet):
        id = MultipleChoiceFilter(label='Filter the results using the STIX ID of a `vulnerability` object. e.g. `vulnerability--4d2cad44-0a5a-5890-925c-29d535c3f49e`.')
        cve_id = CharFilter(label='Filter the results using a CVE ID. e.g. `CVE-2023-22518`')
        description = CharFilter(label='Filter the results by the description of the Vulnerability. Search is a wildcard, so `exploit` will return all descriptions that contain the string `exploit`.')
        has_kev = BooleanFilter(label=dedent('''
        Filter the results to only include those reported by CISA KEV (Known Exploited Vulnerability).
        '''))
        cpes_vulnerable = BaseCSVFilter(label=dedent('''
        Filter Vulnerabilities that are vulnerable to a full or partial CPE Match String. Search is a wildcard to support partial match strings (e.g. `cpe:2.3:o:microsoft:windows` will match `cpe:2.3:o:microsoft:windows_10_1607:-:*:*:*:*:*:x86:*`, `cpe:2.3:o:microsoft:windows_10_1607:-:*:*:*:*:*:x64:*`, etc.
        '''))
        cpes_in_pattern = BaseCSVFilter(label=dedent('''
        Filter Vulnerabilities that contain a full or partial CPE Match String. Note, this will return Vulnerabilities that are vulnerable and not vulnerable (e.g. an operating system might not be vulnerable, but it might be required for software running on it to be vulnerable). Search is a wildcard to support partial match strings (e.g. `cpe:2.3:o:microsoft:windows` will match `cpe:2.3:o:microsoft:windows_10_1607:-:*:*:*:*:*:x86:*`, `cpe:2.3:o:microsoft:windows_10_1607:-:*:*:*:*:*:x64:*`, etc.
        '''))
        weakness_id = BaseCSVFilter(label=dedent("""Filter results by weakness (CWE ID). e.g. `CWE-122`."""))
        attack_id = BaseCSVFilter(label=dedent("""Filter results by an ATT&CK technique or sub-technique ID linked to CVE. e.g `T1587`, `T1587.001`.\n\nNote, CVEs are not directly linked to ATT&CK techniques. To do this, we follow the path `cve->cwe->capec->attack` to link ATT&CK objects to CVEs."""))

    def create(self, request, *args, **kwargs):
        serializer = serializers.NVDTaskSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        job = new_task(serializer.data, models.JobType.CVE_UPDATE)
        job_s = serializers.JobSerializer(instance=job)
        return Response(job_s.data, status=status.HTTP_201_CREATED)
    
    def list(self, request, *args, **kwargs):
        return ArangoDBHelper('', request, 'vulnerabilities').get_vulnerabilities()
    
    @decorators.action(methods=['GET'], detail=True)
    def bundle(self, request, *args, stix_id=None, **kwargs):
        return ArangoDBHelper('', request).get_cve_bundle(stix_id)
    
    def retrieve(self, request, *args, stix_id=None, **kwargs):
        return ArangoDBHelper('nvd_cve_vertex_collection', request).get_object(stix_id)
    
    @decorators.action(detail=True, methods=["GET"])
    def versions(self, request, *args, stix_id=None, **kwargs):
        return ArangoDBHelper('nvd_cve_vertex_collection', request).get_object_versions(stix_id)
    

@extend_schema_view(
    create=extend_schema(
        responses={201: serializers.JobSerializer
        },
        request=serializers.NVDTaskSerializer,
        summary="Download CPE data",
        description="Use this data to update the CPE records.\n\nThe earliest CPE was `2007-09-01`. That said, as a rough guide, we recommend downloading CPEs from `last_modified_earliest` = `2015-01-01` because anything older than this is _generally_ stale.\n\nNote, Software objects representing CPEs do not have a `modified` time in the way Vulnerability objects do. As such, you will want to store a local index of last_modified_earliest` and `last_modified_latest` used in previous request. Requesting the same dates won't cause an issue (existing records will be skipped) but it will be more inefficient.\n\n`last_modified_earliest` and `last_modified_latest` dates should be in the format `YYYY-MM-DD`.\n\nThe data for updates is requested from `https://downloads.ctibutler.com` (managed by the [DOGESEC](https://www.dogesec.com/) team).",
    ),
    list=extend_schema(
        summary='Get Software Objects for CPEs',
        description="Search and filter CPE records.\n\nThis endpoint only returns the software objects for matching CPEs. ",
    ),
    retrieve=extend_schema(
        summary='Get a CPE object by STIX ID',
        description="Retrieve a single STIX `software` object for a CPE using its STIX ID. You can identify a STIX ID using the GET CPE endpoint.",
    ),
) 
class CpeView(viewsets.ViewSet):
    openapi_tags = ["CPE"]
    pagination_class = Pagination("objects")
    filter_backends = [DjangoFilterBackend]
    serializer_class = serializers.StixObjectsSerializer
    lookup_url_kwarg = 'stix_id'
    openapi_path_params = [
        OpenApiParameter('stix_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The full STIX `id` of the object. e.g. `vulnerability--4d2cad44-0a5a-5890-925c-29d535c3f49e`')
    ]

    #def get_queryset(self):
    #    return models.Job.objects.all()
    
    class filterset_class(FilterSet):
        id = BaseCSVFilter(label='Filter the results by the STIX ID of the `software` object. e.g. `software--93ff5b30-0322-50e8-90c1-1c3f151c8adc`')
        cpe_match_string = CharFilter(label='Filter CPEs that contain a full or partial CPE Match String. Search is a wildcard to support partial match strings (e.g. `cpe:2.3:o:microsoft:windows` will match `cpe:2.3:o:microsoft:windows_10_1607:-:*:*:*:*:*:x86:*`, `cpe:2.3:o:microsoft:windows_10_1607:-:*:*:*:*:*:x64:*`, etc.')
        vendor = CharFilter(label='Filters CPEs returned by vendor name. Is wildcard search so `goog` will match `google`, `googe`, etc.')
        product = CharFilter(label='Filters CPEs returned by product name. Is wildcard search so `chrom` will match `chrome`, `chromium`, etc.')

        product_type = ChoiceFilter(choices=[('operating-system', 'Operating System'), ('application', 'Application'), ('hardware', 'Hardware')],
                        label='Filters CPEs returned by product type.'
        )
        cve_vulnerable = BaseCSVFilter(label='Filters CPEs returned to those vulnerable to CVE ID specified. e.g. `CVE-2023-22518`.')
        in_cve_pattern = BaseCSVFilter(label='Filters CPEs returned to those referenced CVE ID specified (if you want to only filter by vulnerable CPEs, use the `cve_vulnerable` parameter. e.g. `CVE-2023-22518`.')

    def create(self, request, *args, **kwargs):
        serializer = serializers.NVDTaskSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        job = new_task(serializer.data, models.JobType.CPE_UPDATE)
        job_s = serializers.JobSerializer(instance=job)
        return Response(job_s.data, status=status.HTTP_201_CREATED)
    
    def list(self, request, *args, **kwargs):
        return ArangoDBHelper('', request).get_softwares()

    def retrieve(self, request, *args, stix_id=None, **kwargs):
        return ArangoDBHelper(f'nvd_cpe_vertex_collection', request).get_object(stix_id)
    

    
@extend_schema_view(
    create=extend_schema(
        responses={201: serializers.JobSerializer
        },
        request=serializers.MitreTaskSerializer,
        summary="Download ATT&CK Objects",
        description="Use this data to update ATT&CK records.\n\nYou can specify the version of ATT&CK you want to download in the format `N_N`. e.g. `15_0, `15_1`.\n\nThe data for updates is requested from `https://downloads.ctibutler.com` (managed by the [DOGESEC](https://www.dogesec.com/) team)."
    ),
    list=extend_schema(
        summary='Get ATT&CK objects',
        description="Search and filter ATT&CK results.",
    ),
    retrieve=extend_schema(
        summary='Get an ATT&CK object',
        description="Get an ATT&CK object by its STIX ID. To search and filter objects to get an ID use the GET Objects endpoint.",
    ),
)  
class AttackView(viewsets.ViewSet):
    openapi_tags = ["ATT&CK"]
    lookup_url_kwarg = 'stix_id'
    openapi_path_params = [
        OpenApiParameter('stix_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The STIX ID')
    ]

    filter_backends = [DjangoFilterBackend]
    MATRIX_TYPES = ["mobile", "ics", "enterprise"]
    @property
    def matrix(self):
        m: re.Match = re.search(r"/attack-(\w+)/", self.request.path)
        return m.group(1)
    serializer_class = serializers.StixObjectsSerializer
    pagination_class = Pagination("objects")

    class filterset_class(FilterSet):
        id = BaseCSVFilter(label='Filter the results using the STIX ID of an object. e.g. `attack-pattern--0042a9f5-f053-4769-b3ef-9ad018dfa298`, `malware--04227b24-7817-4de1-9050-b7b1b57f5866`.')
        attack_id = BaseCSVFilter(label='The ATT&CK IDs of the object wanted. e.g. `T1659`, `TA0043`, `S0066`.')
        description = CharFilter(label='Filter the results by the `description` property of the object. Search is a wildcard, so `exploit` will return all descriptions that contain the string `exploit`.')
        name = CharFilter(label='Filter the results by the `name` property of the object. Search is a wildcard, so `exploit` will return all names that contain the string `exploit`.')
        type = ChoiceFilter(choices=[(f,f) for f in ATTACK_TYPES], label='Filter the results by STIX Object type.')
        attack_version = CharFilter(label="Filter the results by the version of ATT&CK")

    
    def create(self, request, *args, **kwargs):
        serializer = serializers.MitreTaskSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.data.copy()
        data['matrix'] = self.matrix
        job = new_task(data, models.JobType.ATTACK_UPDATE)
        job_s = serializers.JobSerializer(instance=job)
        return Response(job_s.data, status=status.HTTP_201_CREATED)

    
    def list(self, request, *args, **kwargs):
        return ArangoDBHelper('', request).get_attack_objects(self.matrix)
    
    def retrieve(self, request, *args, stix_id=None, **kwargs):
        return ArangoDBHelper(f'mitre_attack_{self.matrix}_vertex_collection', request).get_object(stix_id)
        
    @extend_schema(summary="See available versions", description="See all imported versions available to use, and which version is the default (latest)")
    @decorators.action(detail=False, methods=["GET"])
    def versions(self, request, *args, **kwargs):
        versions = sorted([
            v[14:].replace('_', ".")
            for v in ArangoDBHelper(f'mitre_attack_{self.matrix}_vertex_collection', request).get_mitre_versions()
        ], key=split_mitre_version, reverse=True)
        versions = [f"v{v}" for v in versions]
        return Response(dict(latest=versions[0], versions=versions))
    
@extend_schema_view(
    create=extend_schema(
        responses={201: serializers.JobSerializer
        },
        request=serializers.MitreTaskSerializer,
        summary="Download CWE objects",
        description='Use this data to update CWE records.\n\nYou can specify the version of CWE you want to download in the format `N_N`. e.g. `4_15`.\n\nThe data for updates is requested from `https://downloads.ctibutler.com` (managed by the [DOGESEC](https://www.dogesec.com/) team).',
    ),
    list=extend_schema(
        summary='Get CWE objects',
        description='Search and filter CWE results.',
    ),
    retrieve=extend_schema(
        summary='Get a CWE object',
        description='Get an CWE object by its STIX ID. To search and filter objects to get an ID use the GET Objects endpoint.',
    ),
)  
class CweView(viewsets.ViewSet):
    openapi_tags = ["CWE"]
    lookup_url_kwarg = 'stix_id'
    openapi_path_params = [
        OpenApiParameter('stix_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The STIX ID')
    ]

    filter_backends = [DjangoFilterBackend]

    serializer_class = serializers.StixObjectsSerializer
    pagination_class = Pagination("objects")

    class filterset_class(FilterSet):
        id = BaseCSVFilter(label='Filter the results using the STIX ID of an object. e.g. `weakness--f3496f30-5625-5b6d-8297-ddc074fb26c2`.')
        cwe_id = BaseCSVFilter(label='Filter the results by the CWE ID of the object. e.g. `CWE-242`.')
        description = CharFilter(label='Filter the results by the `description` property of the object. Search is a wildcard, so `exploit` will return all descriptions that contain the string `exploit`.')
        name = CharFilter(label='Filter the results by the `name` property of the object. Search is a wildcard, so `exploit` will return all names that contain the string `exploit`.')
        type = ChoiceFilter(choices=[(f,f) for f in CWE_TYPES], label='Filter the results by STIX Object type.')
        cwe_version = CharFilter(label="Filter the results by the version of CWE")

    def create(self, request, *args, **kwargs):
        serializer = serializers.MitreTaskSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.data.copy()
        job = new_task(data, models.JobType.CWE_UPDATE)
        job_s = serializers.JobSerializer(instance=job)
        return Response(job_s.data, status=status.HTTP_201_CREATED)

    
    def list(self, request, *args, **kwargs):
        return ArangoDBHelper('mitre_cwe_vertex_collection', request).get_weakness_or_capec_objects()
    
    def retrieve(self, request, *args, stix_id=None, **kwargs):
        return ArangoDBHelper('mitre_cwe_vertex_collection', request).get_object(stix_id)
        
    @extend_schema(summary="See available versions", description="See all imported versions available to use, and which version is the default (latest)")
    @decorators.action(detail=False, methods=["GET"])
    def versions(self, request, *args, **kwargs):
        versions = sorted([
            v[14:].replace('_', ".")
            for v in ArangoDBHelper('mitre_cwe_vertex_collection', request).get_mitre_versions()
        ], key=split_mitre_version, reverse=True)
        versions = [f"v{v}" for v in versions]
        return Response(dict(latest=versions[0], versions=versions))
    
   
@extend_schema_view(
    create=extend_schema(
        responses={201: serializers.JobSerializer
        },
        request=serializers.MitreTaskSerializer,
        summary="Download CAPEC objects",
        description='Use this data to update CAPEC records.\n\nYou can specify the version of CAPEC you want to download in the format `N_N`. e.g. `3_5`.\n\nThe data for updates is requested from `https://downloads.ctibutler.com` (managed by the [DOGESEC](https://www.dogesec.com/) team).',
    ),
    list=extend_schema(
        summary='Get CAPEC objects',
        description="Search and filter CAPEC results.",
    ),
    retrieve=extend_schema(
        summary='Get a CAPEC object',
        description='Get an CAPEC object by its STIX ID. To search and filter objects to get an ID use the GET Objects endpoint.',
    ),
)
class CapecView(viewsets.ViewSet):
    openapi_tags = ["CAPEC"]
    lookup_url_kwarg = 'stix_id'
    openapi_path_params = [
        OpenApiParameter('stix_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The STIX ID')
    ]

    filter_backends = [DjangoFilterBackend]

    serializer_class = serializers.StixObjectsSerializer
    pagination_class = Pagination("objects")

    class filterset_class(FilterSet):
        id = BaseCSVFilter(label='Filter the results using the STIX ID of an object. e.g. `attack-pattern--00268a75-3243-477d-9166-8c78fddf6df6`, `course-of-action--0002fa37-9334-41e2-971a-cc8cab6c00c4`.')
        capec_id = BaseCSVFilter(label='Filter the results by the CAPEC ID of the object. e.g. `CAPEC-112`.')
        description = CharFilter(label='Filter the results by the `description` property of the object. Search is a wildcard, so `exploit` will return all descriptions that contain the string `exploit`.')
        name = CharFilter(label='Filter the results by the `name` property of the object. Search is a wildcard, so `exploit` will return all names that contain the string `exploit`.')
        type = ChoiceFilter(choices=[(f,f) for f in CAPEC_TYPES], label='Filter the results by STIX Object type.')
        capec_version = CharFilter(label="Filter the results by the version of CAPEC")

    
    def create(self, request, *args, **kwargs):
        serializer = serializers.MitreTaskSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.data.copy()
        job = new_task(data, models.JobType.CAPEC_UPDATE)
        job_s = serializers.JobSerializer(instance=job)
        return Response(job_s.data, status=status.HTTP_201_CREATED)

    
    def list(self, request, *args, **kwargs):
        return ArangoDBHelper('mitre_capec_vertex_collection', request).get_weakness_or_capec_objects(types=CAPEC_TYPES)
    
    def retrieve(self, request, *args, stix_id=None, **kwargs):
        return ArangoDBHelper('mitre_capec_vertex_collection', request).get_object(stix_id)
    
    @extend_schema(summary="See available versions", description="See all imported versions available to use, and which version is the default (latest)")
    @decorators.action(detail=False, methods=["GET"])
    def versions(self, request, *args, **kwargs):
        versions = sorted([
            v[14:].replace('_', ".")
            for v in ArangoDBHelper('mitre_capec_vertex_collection', request).get_mitre_versions()
        ], key=split_mitre_version, reverse=True)
        versions = [f"v{v}" for v in versions]
        return Response(dict(latest=versions[0], versions=versions))
    
   
@extend_schema_view(
    create=extend_schema(
        responses={201: serializers.JobSerializer
        },
        description="These endpoints will trigger the relevant arango_cti_processor mode to generate relationships.",
        summary="Trigger arango_cti_processor `mode` to generate relationships."
    ),
)
class ACPView(viewsets.ViewSet):
    openapi_tags = ["Arango CTI Processor"]
    serializer_class = serializers.ACPSerializer
    openapi_path_params = [
            OpenApiParameter(name='mode', enum=list(MODE_COLLECTION_MAP), location=OpenApiParameter.PATH, description='mode (`--relationship`) to run [`arango_cti_processor`](https://github.com/muchdogesec/arango_cti_processor/tree/embedded-relationship-tests?tab=readme-ov-file#run) in')
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
        description="Search and filter Jobs. Jobs are triggered for each time a data download request is executed (e.g. GET ATT&CK). The response of these requests will contain a Job ID. Note, Jobs also include Arango CTI Processor runs to join the data together.",
        summary="Get Jobs",
        responses={200: serializers.JobSerializer}
    ),
    retrieve=extend_schema(
        description="Get information about a specific Job. To retrieve a Job ID, use the GET Jobs endpoint.",
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
            cti_modes = list(MODE_COLLECTION_MAP)
            for mode in cti_modes:
                type = models.JobType.CTI_PROCESSOR
                choices.append((f"{type}--{mode}", f"The `{mode}` mode of {type}"))

            for mode in AttackView.MATRIX_TYPES:
                type = models.JobType.ATTACK_UPDATE
                choices.append((f"{type}--{mode}", f"The `{mode}` mode of {type}"))
            choices.sort(key=lambda x: x[0])
            return choices
        
        type = ChoiceFilter(
            label='Filter the results by the type of Job',
            choices=get_type_choices(), method='filter_type'
        )
        state = Filter(label='Filter the results by the state of the Job')

        def filter_type(self, qs, field_name, value: str):
            query = {field_name: value}
            if '--' in value:
                type, mode = value.split('--')
                query.update({field_name: type, "parameters__mode":mode})
            return qs.filter(**query)
        
    def create(self, request, *args, **kwargs):
        return super().create(request, *args, **kwargs)
