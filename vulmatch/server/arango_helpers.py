import contextlib
import json
import logging
import re
import typing
from django.conf import settings
from django.http import HttpResponse
from rest_framework.validators import ValidationError
from dogesec_commons.objects.helpers import ArangoDBHelper as DCHelper
from rest_framework.response import Response


if typing.TYPE_CHECKING:
    from .. import settings
SDO_TYPES = set(
    [
        "report",
        "note",
        "indicator",
        "attack-pattern",
        "weakness",
        "campaign",
        "course-of-action",
        "infrastructure",
        "intrusion-set",
        "malware",
        "threat-actor",
        "tool",
        "identity",
        "location",
    ]
)
SCO_TYPES = set(
    [
        "ipv4-addr",
        "network-traffic",
        "ipv6-addr",
        "domain-name",
        "url",
        "file",
        "directory",
        "email-addr",
        "mac-addr",
        "windows-registry-key",
        "autonomous-system",
        "user-agent",
        "cryptocurrency-wallet",
        "cryptocurrency-transaction",
        "bank-card",
        "bank-account",
        "phone-number",
    ]
)
TLP_TYPES = set(["marking-definition"])
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
LOCATION_TYPES = set(["location"])
CWE_TYPES = set(
    [
        "weakness",
        # "grouping",
        # "identity",
        # "marking-definition",
        # "extension-definition"
    ]
)

ATLAS_TYPES = set(
    [
        "attack-pattern",
        "course-of-action",
        #   "identity",
        #   "marking-definition",
        "x-mitre-collection",
        "x-mitre-matrix",
        "x-mitre-tactic",
    ]
)

SOFTWARE_TYPES = set(["software", "identity", "marking-definition"])
CAPEC_TYPES = set(
    ["attack-pattern", "course-of-action", "identity", "marking-definition"]
)

CVE_SORT_FIELDS = [
    "modified_descending",
    "modified_ascending",
    "created_ascending",
    "created_descending",
    "name_ascending",
    "name_descending",
    "epss_score_ascending",
    "epss_score_descending",
    "cvss_base_score_ascending",
    "cvss_base_score_descending",
]
EPSS_SORT_FIELDS = [
    "name_descending",
    "name_ascending",
    "created_descending",
    "created_ascending",
    "modified_descending",
    "modified_ascending",
    "epss_score_descending",
    "epss_score_ascending",
]
KEV_SORT_FIELDS = EPSS_SORT_FIELDS[:-2]

OBJECT_TYPES = SDO_TYPES.union(SCO_TYPES).union(["relationship"])

CPE_RELATIONSHIP_TYPES = {"vulnerable-to": "exploits", "in-pattern": "relies-on"}
CPE_REL_SORT_FIELDS = [
    "modified_descending",
    "modified_ascending",
    "created_descending",
    "created_ascending",
]
CPE_SORT_FIELDS = [
    "part_descending",
    "part_ascending",
    "vendor_descending",
    "vendor_ascending",
    "product_ascending",
    "product_descending",
    "version_ascending",
    "version_descending",
]
CVE_BUNDLE_TYPES = set(
    [
        "vulnerability",
        "indicator",
        "relationship",
        "report",
        "software",
        "weakness",
        "attack-pattern",
        # default objects
        "extension-definition",
        "marking-definition",
        "identity",
    ]
)

CVE_BUNDLE_DEFAULT_OBJECTS = [
    "extension-definition--ad995824-2901-5f6e-890b-561130a239d4",
    "extension-definition--82cad0bb-0906-5885-95cc-cafe5ee0a500",
    "extension-definition--2c5c13af-ee92-5246-9ba7-0b958f8cd34a",
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--562918ee-d5da-5579-b6a1-fae50cc6bad3",
    "identity--562918ee-d5da-5579-b6a1-fae50cc6bad3",
]


def as_number(integer_string, min_value=0, max_value=None, default=1, type=int):
    """
    Cast a string to a number.
    """
    with contextlib.suppress(ValueError, TypeError):
        ret = type(integer_string)
        if min_value:
            return max(min_value, ret)
        if max_value:
            return min(ret, max_value)
        return ret
    return default



class VulmatchDBHelper(DCHelper):
    @classmethod
    def like_string(cls, string: str):
        return "%" + cls.get_like_literal(string) + "%"
    
    @classmethod
    def get_paginated_response_schema(cls, result_key="objects", stix_type="identity"):
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
            "required": ["page_results_count", result_key],
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
                result_key: {"items": container_schema, "type": "array"},
            },
        }

    def execute_query(
        self,
        query,
        bind_vars={},
        paginate=True,
        relationship_mode=False,
        result_key=None,
        aql_options=None,
    ):
        aql_options = aql_options or {}
        if relationship_mode:
            return self.get_relationships(query, bind_vars)
        if paginate:
            bind_vars["offset"], bind_vars["count"] = self.get_offset_and_count(
                self.count, self.page
            )
        cursor = self.db.aql.execute(
            query, bind_vars=bind_vars, count=True, full_count=True, **aql_options,
        )
        logging.info("AQL stat: %s", cursor.statistics())
        if paginate:
            return self.get_paginated_response(
                cursor,
                self.page,
                self.count,
                cursor.statistics()["fullCount"],
                result_key=result_key or self.result_key,
            )
        return list(cursor)
    


    def list_kev_or_epss_objects(self, label):
        binds = {"label": label}
        binds["cve_ids"] = [qq.upper() for qq in self.query_as_array("cve_id")] or None
        filters = []
        if min_score := as_number(self.query.get("epss_min_score"), default=None, type=float):
            filters.append("FILTER TO_NUMBER(LAST(doc.x_epss).epss) >= @epss_min_score")
            binds["epss_min_score"] = min_score

        query = """
FOR doc IN nvd_cve_vertex_collection
FILTER doc.type == 'report' AND doc._is_latest == TRUE AND doc.labels[0] == @label
FILTER (not @cve_ids) OR doc.external_references[0].external_id IN @cve_ids
//#filters
@sort_stmt
LIMIT @offset, @count
RETURN KEEP(doc, KEYS(doc, TRUE))
        """.replace(
            "@sort_stmt",
            self.get_sort_stmt(
                EPSS_SORT_FIELDS,
                {
                    "epss_score": "TO_NUMBER(LAST(doc.x_epss).epss)",
                },
            ),
        ).replace(
            "//#filters", "\n".join(filters)
        )
        # return HttpResponse(f"""{query}\n// {json.dumps(binds)}""")
        return self.execute_query(query, bind_vars=binds)

    def retrieve_kev_or_epss_object(self, cve_id, label):
        bind_vars = {"cve_id": cve_id, "label": label}

        query = """
FOR doc IN nvd_cve_vertex_collection
FILTER doc.type == 'report' AND doc._is_latest == TRUE AND doc.labels[0] == @label
FILTER doc.external_references[0].external_id == @cve_id
LIMIT @offset, @count
RETURN KEEP(doc, KEYS(doc, TRUE))
            """

        return self.execute_query(query, bind_vars=bind_vars)

    def get_vulnerabilities(self):
        binds = {}
        filters = []

        if q := self.query.get("vuln_status"):
            binds["vuln_status"] = dict(source_name="vulnStatus", description=q.title())
            filters.append("FILTER @vuln_status IN doc.external_references")

        if q := as_number(self.query.get("cvss_base_score_min"), default=None, type=float):
            binds["cvss_base_score_min"] = q
            filters.append("FILTER doc._cvss_base_score >= @cvss_base_score_min")

        if value := self.query_as_array("stix_id"):
            binds["stix_ids"] = value
            filters.append("FILTER doc.id in @stix_ids")

        created_min, created_max = self.query.get('created_min', ''), self.query.get('created_max', '')
        if created_min or created_max:
            filters.append('FILTER IN_RANGE(doc.created, @created[0], @created[1], true, true)')
            binds['created'] = created_min, created_max

        modified_min, modified_max = self.query.get('modified_min', ''), self.query.get('modified_max', '')
        if modified_min or modified_max:
            filters.append('FILTER IN_RANGE(doc.modified, @modified[0], @modified[1], true, true)')
            binds['modified'] = modified_min, modified_max

        ######################## cpes_in_pattern and cpes_vulnerable filters ##############################
        union = None
        if cpes_in_pattern := self.query_as_array("cpes_in_pattern"):
            binds["cpes_in_pattern"] = cpes_in_pattern
            filters.append(
                """LET cpes_in_pattern = (FOR d IN nvd_cve_edge_collection OPTIONS {indexHint: "cve_edge_inv", forceIndexHint: true} FILTER d.relationship_type == 'relies-on' AND d.external_references[*].external_id IN @cpes_in_pattern RETURN SUBSTITUTE(d.source_ref, "indicator", "vulnerability", 1))"""
            )
        if cpes_vulnerable := self.query_as_array("cpes_vulnerable"):
            binds["cpes_vulnerable"] = cpes_vulnerable
            filters.append(
                """LET cpes_vulnerable = (FOR d IN nvd_cve_edge_collection OPTIONS {indexHint: "cve_edge_inv", forceIndexHint: true} FILTER d.relationship_type == 'exploits' AND d.external_references[*].external_id IN @cpes_vulnerable RETURN SUBSTITUTE(d.source_ref, "indicator", "vulnerability", 1))"""
            )

        if cpes_in_pattern and cpes_vulnerable:
            union = "INTERSECTION(cpes_in_pattern, cpes_vulnerable)"
        elif cpes_in_pattern:
            union = "cpes_in_pattern"
        elif cpes_vulnerable:
            union = "cpes_vulnerable"

        if union:
            filters.append(
                """
            LET indicator_refs = #{union}
            FILTER doc.id IN indicator_refs
            """.replace(
                    "#{union}", union
                )
            )

        ######################## cpes_in_pattern and cpes_vulnerable filters ##############################

        if q := self.query_as_array("cve_id"):
            binds["cve_ids"] = [qq.upper() for qq in q]
            filters.append("FILTER doc.name IN @cve_ids")

        if (hasKev := self.query_as_bool("has_kev", None)) != None:
            if hasKev:
                filters.append("FILTER doc.id IN kevs")
            else:
                filters.append("FILTER doc.id NOT IN kevs")

        if q := self.query_as_array("weakness_id"):
            binds["weakness_ids"] = [qq.upper() for qq in q]
            filters.append(
                """
                FILTER doc.external_references[? ANY FILTER CURRENT.source_name=='cwe' AND CURRENT.external_id IN @weakness_ids]
                """
            )


        if q := self.query_as_array("attack_id"):
            binds["attack_ids"] = [qq.upper() for qq in q]
            filters.append(
                """
                LET attack_matches = (FOR d IN nvd_cve_edge_collection OPTIONS {indexHint: "cve_edge_inv", forceIndexHint: true} FILTER d.relationship_type == 'exploited-using' AND d._arango_cve_processor_note == "cve-attack" AND d.external_references[*].external_id IN @attack_ids RETURN d.source_ref)
                FILTER doc.id IN attack_matches
                """
            )

        if q := self.query_as_array("capec_id"):
            binds["capec_ids"] = [qq.upper() for qq in q]
            filters.append(
                """
                LET capec_matches = (FOR d IN nvd_cve_edge_collection OPTIONS {indexHint: "cve_edge_inv", forceIndexHint: true} FILTER d.relationship_type == 'exploited-using' AND d._arango_cve_processor_note == "cve-capec" AND d.external_references[*].external_id IN @capec_ids RETURN d.source_ref)
                FILTER doc.id IN capec_matches
                """
            )

        ### epss  matches should happen later
        epss_filters = []
        if epss_score_min := as_number(self.query.get("epss_score_min"), default=None, type=float):
            binds["epss_score_min"] = epss_score_min
            epss_filters.append("FILTER TO_NUMBER(last_epss.epss) >= @epss_score_min")

        if epss_percentile_min := as_number(self.query.get("epss_percentile_min"), default=None, type=float):
            binds["epss_percentile_min"] = epss_percentile_min
            epss_filters.append(
                "FILTER TO_NUMBER(last_epss.percentile) >= @epss_percentile_min"
            )

        if epss_filters:
            filters.append("FILTER doc.id IN KEYS(epss)")

        query = (
            """

LET kevs = (
FOR doc IN nvd_cve_vertex_collection
FILTER doc.type == 'report' AND doc._is_latest == TRUE AND doc.labels[0] == "kev"
RETURN doc.object_refs[0]
)
LET epss = MERGE(
FOR doc IN nvd_cve_vertex_collection
LET last_epss = LAST(doc.x_epss)
FILTER doc.type == 'report' AND doc._is_latest == TRUE AND doc.labels[0] == "epss"
#epss_filters
RETURN {[doc.object_refs[0]]: last_epss}
)

FOR doc IN nvd_cve_vertex_collection OPTIONS {indexHint: "cve_search_inv", forceIndexHint: true}
FILTER doc.type == 'vulnerability' AND doc._is_latest == TRUE
@filters
@sort_stmt
LIMIT @offset, @count
RETURN KEEP(doc, KEYS(doc, true))
    """.replace(
                "@filters", "\n".join(filters)
            )
            .replace("#epss_filters", "\n".join(epss_filters))
            .replace(
                "@sort_stmt",
                self.get_sort_stmt(
                    CVE_SORT_FIELDS,
                    {
                        "epss_score": "epss[doc.id].epss",
                        "epss_percentile": "epss[doc.id].percentile",
                        "cvss_base_score": "doc._cvss_base_score",
                    },
                ),
            )
        )
        # return HttpResponse(f"""{query}\n// {json.dumps(binds)}""".replace("@offset, @count", "100"))
        return self.execute_query(query, bind_vars=binds, aql_options=dict(optimizer_rules=['-use-index-for-sort']))

    def get_cve_bundle(self, cve_id: str):
        cve_id = cve_id.upper()
        cve_rels_types = ["detects"]
        binds = dict(
            cve_edge_types=cve_rels_types, default_imports=CVE_BUNDLE_DEFAULT_OBJECTS
        )

        more_queries = {}

        include_attack = self.query_as_bool("include_attack", True)
        include_capec = self.query_as_bool("include_capec", True)  # or include_attack
        include_cwe = self.query_as_bool("include_cwe", True)  # or include_capec

        if include_capec:
            cve_rels_types.append("cve-capec")

        if include_attack:
            cve_rels_types.append("cve-attack")

        if self.query_as_bool("include_cpe", True):
            cve_rels_types.append("relies-on")
        if self.query_as_bool("include_cpe_vulnerable", True):
            cve_rels_types.append("exploits")

        if include_cwe:
            cve_rels_types.append("cve-cwe")

        docnames = [cve_id]
        doctypes = ["indicator", "vulnerability"]
        binds.update(docnames=docnames, doctypes=doctypes)
        if self.query_as_bool("include_epss", True):
            docnames.append(f"EPSS Scores: {cve_id}")
            cve_rels_types.append("object")
            doctypes.append("report")
        if self.query_as_bool("include_kev", True):
            docnames.append(f"CISA KEV: {cve_id}")
            cve_rels_types.append("object")
            doctypes.append("report")

        types = self.query_as_array("object_type") or CVE_BUNDLE_TYPES
        binds["types"] = list(CVE_BUNDLE_TYPES.intersection(types))
        binds["@view"] = settings.VIEW_NAME

        query = """
LET cve_data_ids = (
  FOR doc IN nvd_cve_vertex_collection
  FILTER (doc.name IN @docnames AND doc.type IN @doctypes) AND doc._is_latest == TRUE
  RETURN doc._id
)

LET default_object_ids = (
  FOR doc IN nvd_cve_vertex_collection
  FILTER doc.id IN @default_imports AND doc._is_latest == TRUE
  COLLECT id = doc.id INTO docs
  RETURN docs[0].doc._id
)

LET cve_rels = FLATTEN(
    FOR doc IN nvd_cve_edge_collection
    FILTER (doc._from IN cve_data_ids OR doc._to IN cve_data_ids) AND (doc._arango_cve_processor_note IN @cve_edge_types OR doc.relationship_type IN @cve_edge_types)
    RETURN [doc._id, doc._from, doc._to]
    )
    
LET all_objects_ids = UNION_DISTINCT(default_object_ids, cve_data_ids, cve_rels)
FOR d in @@view
SEARCH d.type IN @types AND d._id IN all_objects_ids
LIMIT @offset, @count
RETURN KEEP(d, KEYS(d, TRUE))
"""
        # query = query \
        #             .replace("@@@vertex_filters", " OR ".join(vertex_filters))

        # return HttpResponse(f"""{query}\n// {json.dumps(binds)}""".replace("@offset, @count", "100"))
        return self.execute_query(query, bind_vars=binds)

    def get_cxe_object(
        self,
        cve_id,
        type="vulnerability",
        var="name",
        version_param="cve_version",
        relationship_mode=False,
    ):
        bind_vars = {
            "@collection": self.collection,
            "obj_name": cve_id,
            "type": type,
            "var": var,
        }
        # return Response(bind_vars)
        filters = ["FILTER doc._is_latest == TRUE"]
        if q := self.query.get(version_param):
            bind_vars["stix_modified"] = q
            filters[0] = "FILTER doc.modified == @stix_modified"

        query = """
            FOR doc in @@collection
            FILTER doc.type == @type AND doc[@var] == @obj_name
            @filters
            LIMIT @offset, @count
            RETURN KEEP(doc, KEYS(doc, true))
            """.replace(
            "@filters", "\n".join(filters)
        )

        if var == "cpe" and relationship_mode:
            return self.get_cpe_relationships(query, bind_vars)
        elif relationship_mode:
            return self.get_relationships(query, bind_vars)

        return self.execute_query(query, bind_vars=bind_vars)

    def get_cve_versions(self, cve_id: str):
        query = """
        FOR doc IN @@collection
        FILTER doc.name == @cve_id
        SORT doc.modified DESC
        RETURN DISTINCT doc.modified
        """
        bind_vars = {"@collection": self.collection, "cve_id": cve_id.upper()}
        self.container = "versions"
        versions = self.execute_query(query, bind_vars=bind_vars, paginate=False)
        return Response(
            dict(latest=versions[0] if versions else None, versions=versions)
        )

    def get_softwares(self):
        filters = []
        bind_vars = {
            "@collection": "nvd_cve_vertex_collection",
        }
        if value := self.query_as_array("id"):
            bind_vars["ids"] = value
            filters.append("FILTER doc.id in @ids")

        if value := self.query.get("cpe_match_string"):
            bind_vars["cpe_match_string"] = self.like_string(value).lower()
            filters.append("FILTER doc.cpe LIKE @cpe_match_string")

        struct_match = {}
        if value := self.query.get("product_type"):
            struct_match["part"] = value[0].lower()
            filters.append("FILTER doc.x_cpe_struct.part == @struct_match.part")

        for k in [
            "product",
            "vendor",
            "version",
            "update",
            "edition",
            "language",
            "sw_edition",
            "target_sw",
            "target_hw",
            "other",
        ]:
            if v := self.query.get(k):
                struct_match[k] = self.like_string(v).lower()
                filters.append(
                    f"FILTER doc.x_cpe_struct.`{k}` LIKE @struct_match.`{k}`"
                )

        if struct_match:
            bind_vars["struct_match"] = struct_match

        ######################## in_cve_pattern and cve_vulnerable filters ##############################
        union = None
        if in_cve_pattern := self.query_as_array("in_cve_pattern"):
            bind_vars["in_cve_pattern"] = in_cve_pattern
            filters.append(
                """LET in_cve_pattern = (FOR d IN nvd_cve_edge_collection OPTIONS {indexHint: "cve_edge_inv", forceIndexHint: true} FILTER d.relationship_type == 'relies-on' AND d.external_references[*].external_id IN @in_cve_pattern RETURN d.target_ref)"""
            )
        if cve_vulnerable := self.query_as_array("cve_vulnerable"):
            bind_vars["cve_vulnerable"] = cve_vulnerable
            filters.append(
                """LET cve_vulnerable = (FOR d IN nvd_cve_edge_collection OPTIONS {indexHint: "cve_edge_inv", forceIndexHint: true} FILTER d.relationship_type == 'exploits' AND d.external_references[*].external_id IN @cve_vulnerable RETURN d.target_ref)"""
            )

        if in_cve_pattern and cve_vulnerable:
            union = "INTERSECTION(in_cve_pattern, cve_vulnerable)"
        elif in_cve_pattern:
            union = "in_cve_pattern"
        elif cve_vulnerable:
            union = "cve_vulnerable"

        if union:
            filters.append(
                """
            FILTER doc.id IN #{union}
            """.replace(
                    "#{union}", union
                )
            )

        ######################## in_cve_pattern and cve_vulnerable filters ##############################

        if q := self.query.get("name"):
            bind_vars["name"] = self.like_string(q).lower()
            filters.append("FILTER doc.name LIKE @name")

        query = """
            FOR doc in @@collection OPTIONS {indexHint: "cpe_search_inv", forceIndexHint: true}
            FILTER doc.type == 'software' 

            @filters
            FILTER doc._is_latest == TRUE //*/
            LIMIT @offset, @count
            RETURN KEEP(doc, KEYS(doc, true))
        """.replace(
            "@filters", "\n".join(filters)
        )

        # return HttpResponse(f"""{query}\n// {json.dumps(bind_vars)}""")
        return self.execute_query(query, bind_vars=bind_vars)

    def get_relationships(self, docs_query, binds):
        regex = r"KEEP\((\w+),\s*\w+\(.*?\)\)"
        binds["@view"] = settings.VIEW_NAME
        new_query = """
        LET matched_ids = (@docs_query)[*]._id
        FOR d IN @@view
        SEARCH d.type == 'relationship' AND (d._from IN matched_ids OR d._to IN matched_ids)
        LIMIT @offset, @count
        RETURN KEEP(d, KEYS(d, TRUE))
        """.replace(
            "@docs_query",
            re.sub(
                regex,
                lambda x: x.group(1),
                docs_query.replace("LIMIT @offset, @count", ""),
            ),
        )
        return self.execute_query(new_query, bind_vars=binds, result_key="relationships")

    def get_cpe_relationships(self, docs_query, binds):
        regex = r"KEEP\((\w+),\s*\w+\(.*?\)\)"
        binds["@view"] = settings.VIEW_NAME
        if reftypes := self.query_as_array("relationship_type"):
            binds["relationship_types"] = []
            for t in reftypes:
                if qt := CPE_RELATIONSHIP_TYPES.get(t):
                    binds["relationship_types"].append(qt)
        else:
            binds["relationship_types"] = tuple(CPE_RELATIONSHIP_TYPES.values())
        new_query = """
        LET matched_ids = (@docs_query)[*]._id
        FOR d3 IN FLATTEN(
            FOR d2 IN @@view
            SEARCH d2.type == 'relationship' AND d2.relationship_type IN @relationship_types AND (d2._from IN matched_ids OR d2._to IN matched_ids)
            RETURN [DOCUMENT(d2._from), d2, DOCUMENT(d2._to)]
        )

        COLLECT rel = d3
        @sort_stmt

        LIMIT @offset, @count
        RETURN KEEP(rel, KEYS(rel, TRUE))
        """.replace(
            "@docs_query",
            re.sub(
                regex,
                lambda x: x.group(1),
                docs_query.replace("LIMIT @offset, @count", "LIMIT 1"),
            ),
        ).replace(
            "@sort_stmt", self.get_sort_stmt(CPE_REL_SORT_FIELDS, doc_name="rel")
        )

        return self.execute_query(new_query, bind_vars=binds, result_key="relationships")
