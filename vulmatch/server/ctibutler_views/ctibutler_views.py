import re
import textwrap
from rest_framework import viewsets, status, decorators

from vulmatch.server.arango_helpers import ArangoDBHelper, ATTACK_TYPES, CAPEC_TYPES
from vulmatch.server.autoschema import DEFAULT_400_ERROR
from vulmatch.server.utils import Pagination, Response
from vulmatch.server import serializers
from django_filters.rest_framework import FilterSet, DjangoFilterBackend, ChoiceFilter, BaseCSVFilter, CharFilter, BooleanFilter
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiParameter
from drf_spectacular.types import OpenApiTypes
from .arango_helpers import ATLAS_FORMS, ATLAS_TYPES, DISARM_FORMS, DISARM_TYPES, LOCATION_TYPES, ArangoDBHelper, ATTACK_TYPES, ATTACK_FORMS, CAPEC_TYPES, LOCATION_SUBTYPES

REVOKED_AND_DEPRECATED_PARAMS = [
    OpenApiParameter('include_revoked', type=OpenApiTypes.BOOL, description="By default all objects with `revoked` are ignored. Set this to `true` to include them."),
    OpenApiParameter('include_deprecated', type=OpenApiTypes.BOOL, description="By default all objects with `x_mitre_deprecated` are ignored. Set this to `true` to include them."),
]

@extend_schema_view(
    list_objects=extend_schema(
        responses={200: serializers.StixObjectsSerializer(many=True), 400: DEFAULT_400_ERROR},
        filters=True
    ),
    retrieve_objects=extend_schema(
        responses={200: serializers.StixObjectsSerializer(many=True), 400: DEFAULT_400_ERROR},
        parameters=REVOKED_AND_DEPRECATED_PARAMS,
    ),
    retrieve_object_relationships=extend_schema(
        responses={200: ArangoDBHelper.get_paginated_response_schema('relationships', 'relationship'), 400: DEFAULT_400_ERROR},
        parameters=ArangoDBHelper.get_relationship_schema_operation_parameters() + REVOKED_AND_DEPRECATED_PARAMS,
    ),
)  
class AttackView(viewsets.ViewSet):
    openapi_tags = ["ATT&CK"]
    lookup_url_kwarg = 'stix_id'
    openapi_path_params = [
        OpenApiParameter('stix_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The STIX ID (e.g. `attack-pattern--0042a9f5-f053-4769-b3ef-9ad018dfa298`, `malware--04227b24-7817-4de1-9050-b7b1b57f5866`)'),
        OpenApiParameter('attack_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The ATT&CK ID, e.g `T1659`, `TA0043`, `S0066`'),
    ]

    filter_backends = [DjangoFilterBackend]
    MATRIX_TYPES = ["mobile", "ics", "enterprise"]
    @property
    def matrix(self):
        m: re.Match = re.search(r"/attack-(\w+)/", self.request.path)
        return ""
    serializer_class = serializers.StixObjectsSerializer(many=True)
    pagination_class = Pagination("objects")

    class filterset_class(FilterSet):
        id = BaseCSVFilter(help_text='Filter the results using the STIX ID of an object. e.g. `attack-pattern--0042a9f5-f053-4769-b3ef-9ad018dfa298`, `malware--04227b24-7817-4de1-9050-b7b1b57f5866`.')
        attack_id = BaseCSVFilter(help_text='The ATT&CK IDs of the object wanted. e.g. `T1659`, `TA0043`, `S0066`.')
        description = CharFilter(help_text='Filter the results by the `description` property of the object. Search is a wildcard, so `exploit` will return all descriptions that contain the string `exploit`.')
        name = CharFilter(help_text='Filter the results by the `name` property of the object. Search is a wildcard, so `exploit` will return all names that contain the string `exploit`.')
        type = ChoiceFilter(choices=[(f,f) for f in ATTACK_TYPES], help_text='Filter the results by STIX Object type.')
        alias = CharFilter(help_text='Filter the results by the `x_mitre_aliases` property of the object. Search is a wildcard, so `sun` will return all objects with x_mitre_aliases that contains the string `sun`, e.g `SUNBURST`.')
        attack_type = ChoiceFilter(choices=[(f,f) for f in ATTACK_FORMS], help_text='Filter the results by Attack Object type.')

    @decorators.action(methods=['GET'], url_path="objects", detail=False)
    def list_objects(self, request, *args, **kwargs):
        return ArangoDBHelper('', request).get_attack_objects(self.matrix)

    @decorators.action(methods=['GET'], url_path="objects/<str:attack_id>", detail=False)
    def retrieve_objects(self, request, *args, attack_id=None, **kwargs):
        return ArangoDBHelper(f'nvd_cve_vertex_collection', request).get_object_by_external_id(attack_id, revokable=True)

    @decorators.action(methods=['GET'], url_path="objects/<str:attack_id>/relationships", detail=False)
    def retrieve_object_relationships(self, request, *args, attack_id=None, **kwargs):
        return ArangoDBHelper(f'nvd_cve_vertex_collection', request).get_object_by_external_id(attack_id, relationship_mode=True, revokable=True)

    # @classmethod
    # def attack_view(cls, matrix_name: str):
    #     matrix_name_human = matrix_name.title()
    #     if matrix_name == 'ics':
    #         matrix_name_human = "ICS"

    #     @extend_schema_view(
    #         list_objects=extend_schema(
    #             summary=f"Search and filter MITRE ATT&CK {matrix_name_human} objects",
    #             description=textwrap.dedent(
    #                 """
    #                 Search and filter MITRE ATT&CK objects.
    #                 """
    #             ),
    #             filters=True,
    #         ),
    #         retrieve_objects=extend_schema(
    #             summary=f"Get a specific MITRE ATT&CK {matrix_name_human} object by its ID",
    #             description=textwrap.dedent(
    #                 """
    #                 Get a MITRE ATT&CK object by its MITRE ATT&CK ID (e.g. `T1659`, `TA0043`, `S0066`).

    #                 If you do not know the ID of the object you can use the GET MITRE ATT&CK Objects endpoint to find it.
    #                 """
    #             ),
    #             filters=False,
    #         ),
    #         retrieve_object_relationships=extend_schema(
    #             summary=f"Get the Relationships linked to the MITRE ATT&CK {matrix_name_human} Object",
    #             description=textwrap.dedent(
    #                 """
    #                 This endpoint will return all the STIX `relationship` objects where the ATT&CK object is found as a `source_ref` or a `target_ref`.

    #                 If you want to see an overview of how MITRE ATT&CK objects are linked, [see this diagram](https://miro.com/app/board/uXjVKBgHZ2I=/).

    #                 MITRE ATT&CK objects can also be `target_ref` from CAPECs objects. Requires POST arango-cti-processor request using `capec-attack` mode for this data to show.
    #                 """
    #             ),
    #         ),
    #     )
    #     class TempAttackView(cls):
    #         matrix = matrix_name
    #         openapi_tags = [f"ATT&CK {matrix_name_human}"]
    #         truncate_collections = [f"mitre_attack_{matrix}"]
    #     TempAttackView.__name__ = f'{matrix_name.title()}AttackView'
    #     return TempAttackView

@extend_schema_view(
    list_objects=extend_schema(
        summary='Search and filter MITRE CWE objects',
        description=textwrap.dedent(
            """
            Search and filter MITRE CWE objects.
            """
        ),
        filters=True,
        responses={200: serializers.StixObjectsSerializer(many=True), 400: DEFAULT_400_ERROR},
    ),
    retrieve_objects=extend_schema(
        summary='Get a CWE object',
        description=textwrap.dedent(
            """
            Get an CWE object by its ID (e.g. `CWE-242` `CWE-250`).

            If you do not know the ID of the object you can use the GET MITRE CWE Objects endpoint to find it.
            """
        ),
        filters=False,
        responses={200: serializers.StixObjectsSerializer(many=True), 400: DEFAULT_400_ERROR},
    ),
    retrieve_object_relationships=extend_schema(
        summary='Get the Relationships linked to MITRE CWE Object',
        description=textwrap.dedent(
            """
            This endpoint will return all the STIX relationship objects where the CWE object is found as a `source_ref` or a `target_ref`.

            If you want to see an overview of how MITRE CWE objects are linked, [see this diagram](https://miro.com/app/board/uXjVKpOg6bM=/).

            MITRE CWE objects can also be `source_ref` to CAPEC objects. Requires POST arango-cti-processor request using `cwe-capec` mode for this data to show.
            """
        ),
        responses={200: ArangoDBHelper.get_paginated_response_schema('relationships', 'relationship'), 400: DEFAULT_400_ERROR},
        parameters=ArangoDBHelper.get_relationship_schema_operation_parameters(),
    ),
)  
class CweView(viewsets.ViewSet):
    openapi_tags = ["CWE"]
    truncate_collections = ['nvd_cve']
    lookup_url_kwarg = 'cwe_id'
    openapi_path_params = [
        OpenApiParameter('stix_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The STIX ID (e.g. `weakness--f3496f30-5625-5b6d-8297-ddc074fb26c2`, `grouping--000ee024-ad9c-5557-8d49-2573a8e788d2`)'),
        OpenApiParameter('cwe_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The CWE ID, e.g `CWE-242`, `CWE-250`'),
    ]

    filter_backends = [DjangoFilterBackend]

    serializer_class = serializers.StixObjectsSerializer(many=True)
    pagination_class = Pagination("objects")

    class filterset_class(FilterSet):
        id = BaseCSVFilter(help_text='Filter the results using the STIX ID of an object. e.g. `weakness--f3496f30-5625-5b6d-8297-ddc074fb26c2`, `grouping--000ee024-ad9c-5557-8d49-2573a8e788d2`.')
        cwe_id = BaseCSVFilter(help_text='Filter the results by the CWE ID of the object. e.g. `CWE-242` `CWE-250`.')
        description = CharFilter(help_text='Filter the results by the `description` property of the object. Search is a wildcard, so `exploit` will return all descriptions that contain the string `exploit`.')
        name = CharFilter(help_text='Filter the results by the `name` property of the object. Search is a wildcard, so `exploit` will return all names that contain the string `exploit`.')
        # type = ChoiceFilter(choices=[(f,f) for f in CWE_TYPES], help_text='Filter the results by STIX Object type.')


    
    @decorators.action(methods=['GET'], url_path="objects", detail=False)
    def list_objects(self, request, *args, **kwargs):
        return ArangoDBHelper('nvd_cve_vertex_collection', request).get_weakness_or_capec_objects('cve-cwe')
    
    @decorators.action(methods=['GET'], url_path="objects/<str:cwe_id>", detail=False)
    def retrieve_objects(self, request, *args, cwe_id=None, **kwargs):
        return ArangoDBHelper('nvd_cve_vertex_collection', request).get_object_by_external_id(cwe_id, 'cve-cwe')
        

    @decorators.action(methods=['GET'], url_path="objects/<str:cwe_id>/relationships", detail=False)
    def retrieve_object_relationships(self, request, *args, cwe_id=None, **kwargs):
        return ArangoDBHelper('nvd_cve_vertex_collection', request).get_object_by_external_id(cwe_id, 'cve-cwe', relationship_mode=True)        

@extend_schema_view(
    list_objects=extend_schema(
        summary='Search and filter MITRE CAPEC objects',
        description=textwrap.dedent(
            """
            Search and filter MITRE CAPEC objects.      
            """
        ),
        filters=True,
        responses={200: serializers.StixObjectsSerializer(many=True), 400: DEFAULT_400_ERROR},
    ),
    retrieve_objects=extend_schema(
        summary='Get a CAPEC object',
        description=textwrap.dedent(
            """
            Get a CAPEC object by its ID (e.g. `CAPEC-112`, `CAPEC-699`).

            If you do not know the ID of the object you can use the GET MITRE CAPEC Objects endpoint to find it.
            """
        ),
        filters=False,
        responses={200: serializers.StixObjectsSerializer(many=True), 400: DEFAULT_400_ERROR},
    ),
    retrieve_object_relationships=extend_schema(
        summary='Get the Relationships linked to MITRE CAPEC Object',
        description=textwrap.dedent(
            """
            This endpoint will return all the STIX relationship objects where the CAPEC object is found as a `source_ref` or a `target_ref`.

            MITRE CAPEC objects can also be `source_ref` from ATT&CK Enterprise objects. Requires POST arango-cti-processor request using `capec-attack` mode for this data to show.

            MITRE CAPEC objects can also be `target_ref` to CWE objects. Requires POST arango-cti-processor request using `cwe-capec` mode for this data to show.
            """
        ),
        responses={200: ArangoDBHelper.get_paginated_response_schema('relationships', 'relationship'), 400: DEFAULT_400_ERROR},
        parameters=ArangoDBHelper.get_relationship_schema_operation_parameters(),
    ),
)
class CapecView(viewsets.ViewSet):
    openapi_tags = ["CAPEC"]
    truncate_collections = ['nvd_cve']
    lookup_url_kwarg = 'capec_id'
    openapi_path_params = [
        OpenApiParameter('stix_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The STIX ID (e.g. `attack-pattern--00268a75-3243-477d-9166-8c78fddf6df6`, `course-of-action--0002fa37-9334-41e2-971a-cc8cab6c00c4`)'),
        OpenApiParameter('capec_id', type=OpenApiTypes.STR, location=OpenApiParameter.PATH, description='The CAPEC ID, e.g `CAPEC-112`, `CAPEC-699`'),
    ]

    filter_backends = [DjangoFilterBackend]

    serializer_class = serializers.StixObjectsSerializer(many=True)
    pagination_class = Pagination("objects")

    class filterset_class(FilterSet):
        id = BaseCSVFilter(help_text='Filter the results using the STIX ID of an object. e.g. `attack-pattern--00268a75-3243-477d-9166-8c78fddf6df6`, `course-of-action--0002fa37-9334-41e2-971a-cc8cab6c00c4`.')
        capec_id = BaseCSVFilter(help_text='Filter the results by the CAPEC ID of the object. e.g. `CAPEC-112`, `CAPEC-699`.')
        description = CharFilter(help_text='Filter the results by the `description` property of the object. Search is a wildcard, so `exploit` will return all descriptions that contain the string `exploit`.')
        name = CharFilter(help_text='Filter the results by the `name` property of the object. Search is a wildcard, so `exploit` will return all names that contain the string `exploit`.')
        type = ChoiceFilter(choices=[(f,f) for f in CAPEC_TYPES], help_text='Filter the results by STIX Object type.')

    
    @decorators.action(methods=['GET'], url_path="objects", detail=False)
    def list_objects(self, request, *args, **kwargs):
        return ArangoDBHelper('nvd_cve_vertex_collection', request).get_weakness_or_capec_objects('cve-capec', types=CAPEC_TYPES, lookup_kwarg=self.lookup_url_kwarg)
    

    @decorators.action(methods=['GET'], url_path="objects/<str:capec_id>", detail=False)
    def retrieve_objects(self, request, *args, capec_id=None, **kwargs):
        return ArangoDBHelper('nvd_cve_vertex_collection', request).get_object_by_external_id(capec_id, 'cve-capec')
    

    @decorators.action(methods=['GET'], url_path="objects/<str:capec_id>/relationships", detail=False)
    def retrieve_object_relationships(self, request, *args, capec_id=None, **kwargs):
        return ArangoDBHelper('nvd_cve_vertex_collection', request).get_object_by_external_id(capec_id, 'cve-capec', relationship_mode=True)
       