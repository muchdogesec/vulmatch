import contextlib
import itertools
import re
import typing

from django.conf import settings
from drf_spectacular.utils import OpenApiParameter
from drf_spectacular.types import OpenApiTypes
from dogesec_commons.objects.helpers import ArangoDBHelper as DCHelper
from rest_framework.response import Response

from vulmatch.server.arango_helpers import CVE_BUNDLE_TYPES

if typing.TYPE_CHECKING:
    from .. import settings


import textwrap

ATTACK_TYPES = set(
    [
        "attack-pattern",
        "campaign",
        "course-of-action",
        "identity",
        "intrusion-set",
        "malware",
        "marking-definition",
        "tool",
        "x-mitre-data-component",
        "x-mitre-data-source",
        "x-mitre-matrix",
        "x-mitre-tactic",
    ]
)

ATTACK_FORMS = {
    "Technique": [
        dict(type="attack-pattern", x_mitre_is_subtechnique=False),
        dict(type="attack-pattern", x_mitre_is_subtechnique=None),
    ],
    "Sub-technique": [dict(type="attack-pattern", x_mitre_is_subtechnique=True)],
}


CWE_TYPES = set(
    [
        "weakness",
        # "grouping",
        # "identity",
        # "marking-definition",
        # "extension-definition"
    ]
)

CAPEC_TYPES = set(
    ["attack-pattern", "course-of-action", "identity", "marking-definition"]
)

SORT_PROPERTIES = [
    "created_descending",
    "created_ascending",
    "name_descending",
    "name_ascending",
    "modified_descending",
    "modified_ascending",
]


class AttachedDBHelper(DCHelper):

    @classmethod
    def get_paginated_response(
        cls, container, data, page_number, page_size=None, full_count=0
    ):
        return Response(
            {
                "page_size": page_size or cls.page_size,
                "page_number": page_number,
                "page_results_count": len(data),
                "total_results_count": full_count,
                container: data,
            }
        )

    @classmethod
    def get_paginated_response_schema(cls, container="objects", stix_type="identity"):
        if stix_type == "string":
            container_schema = {"type": "string"}
        else:
            container_schema = {
                "type": "object",
                "properties": {
                    "type": {
                        "example": stix_type,
                    },
                    "id": {
                        "example": f"{stix_type}--a86627d4-285b-5358-b332-4e33f3ec1075",
                    },
                },
                "additionalProperties": True,
            }
        return {
            "type": "object",
            "required": ["page_results_count", container],
            "properties": {
                "page_size": {
                    "type": "integer",
                    "example": cls.max_page_size,
                },
                "page_number": {
                    "type": "integer",
                    "example": 3,
                },
                "page_results_count": {
                    "type": "integer",
                    "example": cls.page_size,
                },
                "total_results_count": {
                    "type": "integer",
                    "example": cls.page_size * cls.max_page_size,
                },
                container: {"type": "array", "items": container_schema},
            },
        }

    @classmethod
    def get_relationship_schema_operation_parameters(cls):
        return cls.get_schema_operation_parameters() + [
            OpenApiParameter(
                "include_embedded_refs",
                description=textwrap.dedent(
                    """
                    If `ignore_embedded_relationships` is set to `false` in the POST request to download data, stix2arango will create SROS for embedded relationships (e.g. from `created_by_refs`). You can choose to show them (`true`) or hide them (`false`) using this parameter. Default value if not passed is `true`.
                    """
                ),
                type=OpenApiTypes.BOOL,
            ),
            OpenApiParameter(
                "relationship_direction",
                enum=["source_ref", "target_ref"],
                description=textwrap.dedent(
                    """
                    Filters the results to only include SROs which have this object in the specified SRO property (e.g. setting `source_ref` will only return SROs where the object is shown in the `source_ref` property). Default is both.
                    """
                ),
            ),
            OpenApiParameter(
                "relationship_type",
                description="filter by the `relationship_type` of the STIX SROs returned.",
            ),
        ]

    @classmethod
    def get_bundle_schema_operation_parameters(cls):
        return cls.get_schema_operation_parameters() + [
            OpenApiParameter("type", enum=CVE_BUNDLE_TYPES, many=True, explode=False)
        ]

    def __init__(self, collection, request, container="objects") -> None:
        super().__init__(collection, request, container)
        self.container = container

    def execute_query(
        self,
        query,
        bind_vars={},
        paginate=True,
        container=None,
    ):
        query = query.replace(
            "#sort_stmt",
            self.get_sort_stmt(
                SORT_PROPERTIES
                + [
                    "cwe_id_descending",
                    "cwe_id_ascending",
                    "capec_id_descending",
                    "capec_id_ascending",
                    "attack_id_descending",
                    "attack_id_ascending",
                ],
                customs={
                    k + "_id": "doc.external_references[0].external_id"
                    for k in ["cwe", "capec", "attack"]
                },
            ),
        )

        if paginate:
            bind_vars["offset"], bind_vars["count"] = self.get_offset_and_count(
                self.count, self.page
            )
        cursor = self.db.aql.execute(
            query, bind_vars=bind_vars, count=True, full_count=True
        )
        if paginate:
            return self.get_paginated_response(
                container or self.container,
                cursor,
                self.page,
                self.count,
                cursor.statistics()["fullCount"],
            )
        return list(cursor)

    def get_attack_objects(self, matrix):
        filters = []
        bind_vars = {
            "@collection": f"nvd_cve_vertex_collection",
            "types": ['attack-pattern'],
        }

        if attack_forms := self.query_as_array("attack_type"):
            form_list = []
            for form in attack_forms:
                form_list.extend(ATTACK_FORMS.get(form, []))

            if form_list:
                filters.append(
                    "FILTER @attack_form_list[? ANY FILTER MATCHES(doc, CURRENT)]"
                )
                bind_vars["attack_form_list"] = form_list

        filters.append("FILTER doc._is_latest")

        if value := self.query_as_array("id"):
            bind_vars["ids"] = value
            filters.append("FILTER doc.id in @ids")

        if value := self.query_as_array("attack_id"):
            bind_vars["attack_ids"] = [v.lower() for v in value]
            filters.append(
                "FILTER LOWER(doc.external_references[0].external_id) in @attack_ids"
            )
        if q := self.query.get("name"):
            bind_vars["name"] = q.lower()
            filters.append("FILTER CONTAINS(LOWER(doc.name), @name)")

        if q := self.query.get("alias"):
            bind_vars["alias"] = q.lower()
            filters.append(
                "FILTER APPEND(doc.aliases, doc.x_mitre_aliases)[? ANY FILTER CONTAINS(LOWER(CURRENT), @alias)]"
            )

        if q := self.query.get("description"):
            bind_vars["description"] = q.lower()
            filters.append("FILTER CONTAINS(LOWER(doc.description), @description)")


        query = """
            FOR doc in @@collection
            FILTER doc.type IN @types AND doc._arango_cve_processor_note == 'cve-attack'
            @filters
            #sort_stmt
            LIMIT @offset, @count
            RETURN KEEP(doc, KEYS(doc, true))
        """.replace(
            "@filters", "\n".join(filters)
        )
        # return HttpResponse(f"""{query}\n// {json.dumps(bind_vars)}""")
        return self.execute_query(query, bind_vars=bind_vars)

    def get_object_by_external_id(
        self, ext_id: str, note, revokable=False, bundle=False
    ):
        bind_vars = {
            "@collection": self.collection,
            "ext_id": ext_id.lower(),
            "note": note,
        }
        filters = [
            "FILTER LOWER(doc.external_references[0].external_id) == @ext_id",
            "FILTER doc._is_latest",
        ]

        if revokable:
            bind_vars["include_deprecated"] = self.query_as_bool(
                "include_deprecated", False
            )
            bind_vars["include_revoked"] = self.query_as_bool("include_revoked", False)
            filters.append(
                "FILTER (@include_revoked OR NOT doc.revoked) AND (@include_deprecated OR NOT doc.x_mitre_deprecated)"
            )

        if "--" in ext_id:
            filters[0] = "FILTER doc.id == @ext_id"

        query = """
            FOR doc in @@collection
            FILTER doc._arango_cve_processor_note == @note AND doc.type > ""
            @filters
            LIMIT @offset, @count
            RETURN KEEP(doc, KEYS(doc, true))
            """.replace(
            "@filters", "\n".join(filters)
        )
        if bundle:
            cursor = self.execute_query(
                query.replace("LIMIT @offset, @count", "").replace(
                    "KEEP(doc, KEYS(doc, true))", "doc._id"
                ),
                bind_vars=bind_vars,
                paginate=False,
            )
            return self.get_bundle(cursor)
        return self.execute_query(query, bind_vars=bind_vars)

    def get_weakness_or_capec_objects(
        self,
        note,
        cwe=True,
        stix_type='weakness',
        lookup_kwarg="cwe_id",
        more_binds={},
        more_filters=[],
        forms={},
    ):
        filters = []
        bind_vars = {
            "@collection": self.collection,
            "types": [stix_type],
            "note": note,
            **more_binds,
        }

        filters.append("FILTER doc._is_latest")

        if value := self.query_as_array("id"):
            bind_vars["ids"] = value
            filters.append("FILTER doc.id in @ids")

        if generic_forms := self.query_as_array(lookup_kwarg.replace("_id", "_type")):
            form_list = []
            for form in generic_forms:
                form_list.extend(forms.get(form, []))

            if form_list:
                filters.append(
                    "FILTER @generic_form_list[? ANY FILTER MATCHES(doc, CURRENT)]"
                )
                bind_vars["generic_form_list"] = form_list

        if value := self.query_as_array(lookup_kwarg):
            bind_vars["ext_ids"] = [v.lower() for v in value]
            filters.append(
                "FILTER LOWER(doc.external_references[0].external_id) in @ext_ids"
            )
        if q := self.query.get("name"):
            bind_vars["name"] = q.lower()
            filters.append("FILTER CONTAINS(LOWER(doc.name), @name)")

        if q := self.query.get("description"):
            bind_vars["description"] = q.lower()
            filters.append("FILTER CONTAINS(LOWER(doc.description), @description)")

        query = """
            FOR doc in @@collection FILTER doc.type IN @types AND doc._arango_cve_processor_note == @note
            @filters
            #sort_stmt
            LIMIT @offset, @count
            RETURN KEEP(doc, KEYS(doc, true))
        """.replace(
            "@filters", "\n".join(filters + more_filters)
        )
        return self.execute_query(query, bind_vars=bind_vars)

    def get_bundle(self, obj_ids):
        binds = {"obj_ids": obj_ids, "@view": settings.VIEW_NAME}
        other_filters = []

        new_query = """
        LET matched_ids = @obj_ids
        FOR d IN @@view
        SEARCH d.type == 'relationship' AND (d._from IN matched_ids OR d._to IN matched_ids)
        @other_filters
        RETURN [d._id, d._from, d._to]
        """.replace(
            "@other_filters", "\n".join(other_filters)
        )

        rels = self.execute_query(new_query, bind_vars=binds, paginate=False)
        rels = tuple(set(itertools.chain(obj_ids, *rels)))
        new_binds = {
            "object_ids": rels,
            "@view": settings.VIEW_NAME,
            "types": None,
        }
        if new_types := self.query_as_array("type"):
            new_binds["types"] = new_types

        return self.execute_query(
            "FOR d IN @@view SEARCH d._id IN @object_ids FILTER NOT @types OR d.type IN @types LIMIT @offset, @count RETURN KEEP(d, KEYS(d, TRUE))",
            bind_vars=new_binds,
        )
