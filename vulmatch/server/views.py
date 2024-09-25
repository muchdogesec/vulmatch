import re
from django.shortcuts import render
from rest_framework import viewsets, filters, status, decorators

from vulmatch.server.arango_helpers import ArangoDBHelper, ATTACK_TYPES, CWE_TYPES, SOFTWARE_TYPES, CAPEC_TYPES
from vulmatch.server.utils import Pagination, Response
from vulmatch.worker.tasks import new_task
from . import models
from vulmatch.server import serializers
from django_filters.rest_framework import FilterSet, Filter, DjangoFilterBackend, ChoiceFilter, BaseCSVFilter, CharFilter, BooleanFilter, MultipleChoiceFilter
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiParameter
from arango_cti_processor.config import MODE_COLLECTION_MAP
from textwrap import dedent
# Create your views here.

@extend_schema_view(
    create=extend_schema(
        responses={201: serializers.JobSerializer
        },
        request=serializers.NVDTaskSerializer,
        summary="Download Vulnerability data for CVEs",
        description="Use this data to update the CVE records stored in Vulmatch.\n\nThe earliest CVE record has a `modified` value of `2007-07-13T04:00:00.000Z`. That said, as a rough guide, we recommend downloading CVEs from `last_modified_earliest` = `2020-01-01` because anything older than this is _generally_ stale.\n\nThe easiest way to identify the last update time used (to keep CVE records current) is to use the jobs endpoint which will show the `last_modified_earliest` and `last_modified_latest` dates used.\n\n`last_modified_earliest` and `last_modified_latest` dates should be in the format `YYYY-MM-DD`.\n\nThe data for updates is requested from `https://downloads.ctibutler.com` (managed by the DOGESEC team).",
    ),
    list=extend_schema(
        responses={200: ArangoDBHelper.get_paginated_response_schema('vulnerabilities')}, filters=True,
        summary="Get Vulnerability Objects for CVEs",
        description="This endpoint only returns the vulnerability object for matching CVEs. Once you have the CVE ID you want, you can get all associated data linked to it using the bundle endpoint.",
    )
)   
class CveView(viewsets.ViewSet):
    openapi_tags = ["CVE"]
    pagination_class = Pagination("vulnerabilities")
    filter_backends = [DjangoFilterBackend]
    serializer_class = serializers.JobSerializer
    lookup_url_kwarg = 'stix_id'

    
    class filterset_class(FilterSet):
        id = MultipleChoiceFilter(label='Filter the results using a STIX ID. e.g. `vulnerability--4d2cad44-0a5a-5890-925c-29d535c3f49e`.')
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
    

@extend_schema_view(
    create=extend_schema(
        responses={201: serializers.JobSerializer
        },
        request=serializers.NVDTaskSerializer,
        summary="Will download CPEs using cloudflare",
    ),
    list=extend_schema(
        summary='Get Software Objects for CPEs',
        description="This endpoint only returns the Software Objects for matching CPEs.",
    ),
    retrieve=extend_schema(
        summary='Get CPE object',
    ),
) 
class CpeView(viewsets.ViewSet):
    openapi_tags = ["CPE"]
    pagination_class = Pagination("objects")
    filter_backends = [DjangoFilterBackend]
    serializer_class = serializers.JobSerializer
    lookup_url_kwarg = 'cpe_match_string'

    #def get_queryset(self):
    #    return models.Job.objects.all()
    
    class filterset_class(FilterSet):
        id = BaseCSVFilter(label='(stix id): The STIX ID(s) of the object wanted (e.g. `software--1234`)')
        type = ChoiceFilter(choices=[(f,f) for f in SOFTWARE_TYPES], label="(stix type): The STIX object `type`(s) of the object wanted (e.g. `software`).")
        cpe_match_string = CharFilter(label='(optional): ID of CVE (e.g. `cpe:2.3:o:microsoft:windows_10`). Can use wildcards or can omit end of string (rest will be treated as wildcard values)')
        vendor = CharFilter(label='(optional, uses cpe match string 3rd part)')
        product = CharFilter(label='(optional, uses cpe match string 4th part)')

        product_type = ChoiceFilter(choices=[('operating-system', 'Operating System'), ('application', 'Application'), ('hardware', 'Hardware')],
                        label='(optional, uses cpe match string 2nd part)'
        )
        cve_vulnerable = BaseCSVFilter(label='(optional, list of CVE ids): only returns CPEs vulnerable to CVE')
        in_cve_pattern = BaseCSVFilter(label='(optional, list of CVE ids): only returns CPEs in a CVEs Pattern')

    def create(self, request, *args, **kwargs):
        serializer = serializers.NVDTaskSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        job = new_task(serializer.data, models.JobType.CPE_UPDATE)
        job_s = serializers.JobSerializer(instance=job)
        return Response(job_s.data, status=status.HTTP_201_CREATED)
    
    def list(self, request, *args, **kwargs):
        return ArangoDBHelper('', request).get_softwares()

    def retrieve(self, request, *args, cpe_match_string=None, **kwargs):
        return ArangoDBHelper(f'nvd_cpe_vertex_collection', request).get_software_by_name(cpe_match_string)
    

    
@extend_schema_view(
    create=extend_schema(
        responses={201: serializers.JobSerializer
        },
        request=serializers.MitreTaskSerializer,
        summary="Will download ATT&CK bundle using cloudflare",
    ),
    list=extend_schema(
        summary='Search ATT&CK objects',
    ),
    retrieve=extend_schema(
        summary='Get ATT&CK object',
    ),
)  
class AttackView(viewsets.ViewSet):
    openapi_tags = ["ATT&CK"]
    lookup_url_kwarg = 'stix_id'

    filter_backends = [DjangoFilterBackend]
    MATRIX_TYPES = ["mobile", "ics", "enterprise"]
    @property
    def matrix(self):
        m: re.Match = re.search(r"/attack-(\w+)/", self.request.path)
        return m.group(1)
    serializer_class = serializers.JobSerializer

    class filterset_class(FilterSet):
        id = BaseCSVFilter(label='(stix id): The STIX ID(s) of the object wanted (e.g. `attack-pattern--1234`)')
        attack_id = BaseCSVFilter(label='(attack ID): The ATTACK ids of the object wanted (e.g. `T1659`)')
        description = CharFilter(label='(stix description): The description if the object. Is wildcard')
        name = CharFilter(label='(stix name): The name if the object. Is wildcard')
        type = ChoiceFilter(choices=[(f,f) for f in ATTACK_TYPES], label='(stix type): The STIX object `type`(s) of the object wanted (e.g. `attack-pattern`).')

    
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
    
    
@extend_schema_view(
    create=extend_schema(
        responses={201: serializers.JobSerializer
        },
        request=serializers.MitreTaskSerializer,
        summary="Will download CWEs using cloudflare",
    ),
    list=extend_schema(
        summary='Search CWE objects',
    ),
    retrieve=extend_schema(
        summary='Get CWE object',
    ),
)  
class CweView(viewsets.ViewSet):
    openapi_tags = ["CWE"]
    lookup_url_kwarg = 'stix_id'

    filter_backends = [DjangoFilterBackend]

    serializer_class = serializers.JobSerializer

    class filterset_class(FilterSet):
        id = BaseCSVFilter(label='(stix id): The STIX ID(s) of the object wanted (e.g. `weakness--1234`)')
        cwe_id = BaseCSVFilter(label='(cwe ID): The CWE ids of the object wanted (e.g. `CWE-242`)')
        description = CharFilter(label='(stix description): The description if the object. Is wildcard')
        name = CharFilter(label='(stix name): The name if the object. Is wildcard')
        type = ChoiceFilter(choices=[(f,f) for f in CWE_TYPES], label='(stix type): The STIX object `type`(s) of the object wanted (e.g. `weakness`).')

    
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
    
   
@extend_schema_view(
    create=extend_schema(
        responses={201: serializers.JobSerializer
        },
        request=serializers.MitreTaskSerializer,
        summary="Will download CAPECs using cloudflare",
    ),
    list=extend_schema(
        summary='Search CAPEC objects',
    ),
    retrieve=extend_schema(
        summary='Get CAPEC object',
    ),
)
class CapecView(viewsets.ViewSet):
    openapi_tags = ["CAPEC"]
    lookup_url_kwarg = 'stix_id'

    filter_backends = [DjangoFilterBackend]

    serializer_class = serializers.JobSerializer

    class filterset_class(FilterSet):
        id = BaseCSVFilter(label='(stix id): The STIX ID(s) of the object wanted (e.g. `attack-pattern--1234`)')
        capec_id = BaseCSVFilter(label='(capec ID): The CAPEC ids of the object wanted (e.g. `CAPEC-112`)')
        
        description = CharFilter(label='(stix description): The description if the object. Is wildcard')
        name = CharFilter(label='(stix name): The name if the object. Is wildcard')
        type = ChoiceFilter(choices=[(f,f) for f in CAPEC_TYPES], label='(stix type): The STIX object `type`(s) of the object wanted (e.g. `attack-pattern`).')

    
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
    
   
@extend_schema_view(
    create=extend_schema(
        responses={201: serializers.JobSerializer
        },
        #request=serializers.ACPSerializer
        parameters=[
            OpenApiParameter(name='mode', enum=list(MODE_COLLECTION_MAP), location=OpenApiParameter.PATH)
        ],
        description="These endpoints will trigger the relevant arango_cti_processor mode to generate relationships.",
        summary="Trigger arango_cti_processor `mode` to generate relationships."
    ),
)
class ACPView(viewsets.ViewSet):
    openapi_tags = ["Arango CTI Processor"]
    serializer_class = serializers.ACPSerializer

    def create(self, request, *args, **kwargs):
        serializer = serializers.ACPSerializerWithMode(data={**request.data, **kwargs})
        serializer.is_valid(raise_exception=True)
        data = serializer.data.copy()
        job = new_task(data, models.JobType.CTI_PROCESSOR)
        job_s = serializers.JobSerializer(instance=job)
        return Response(job_s.data, status=status.HTTP_201_CREATED)

@extend_schema_view(
    list=extend_schema(
        description="search jobs",
        summary="search jobs",
        responses={200: serializers.JobSerializer}
    ),
    retrieve=extend_schema(
        description="get job by ID",
        summary="get job by ID",
    ),
)
class JobView(viewsets.ModelViewSet):
    http_method_names = ["get"]
    serializer_class = serializers.JobSerializer
    filter_backends = [DjangoFilterBackend]
    pagination_class = Pagination("jobs")
    openapi_tags = ["Jobs"]
    lookup_url_kwarg = 'job_id'

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
        
        type = ChoiceFilter(choices=get_type_choices(), method='filter_type')
        state = Filter()

        def filter_type(self, qs, field_name, value: str):
            query = {field_name: value}
            if '--' in value:
                type, mode = value.split('--')
                query.update({field_name: type, "parameters__mode":mode})
            return qs.filter(**query)
        
    def create(self, request, *args, **kwargs):
        return super().create(request, *args, **kwargs)
