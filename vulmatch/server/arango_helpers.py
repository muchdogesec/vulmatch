import contextlib
import itertools
import logging
import typing
from django.conf import settings
from rest_framework.exceptions import NotFound, ValidationError
from dogesec_commons.objects.helpers import ArangoDBHelper as DCHelper
from rest_framework.response import Response
from arango_cve_processor.tools.cpe import generate_grouping_id


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
        "exploit",
        "attack-pattern",
        "grouping",
        # default objects
        "extension-definition",
        "marking-definition",
        "identity",
    ]
)

CPEMATCH_BUNDLE_TYPES = {"grouping", "indicator", "relationship", "software"}


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
    NULL_LIST = ["NULL_LIST"]

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
        result_key=None,
        aql_options=None,
    ):
        aql_options = aql_options or {}
        if paginate:
            bind_vars["offset"], bind_vars["count"] = self.get_offset_and_count(
                self.count, self.page
            )
        cursor = self.db.aql.execute(
            query,
            bind_vars=bind_vars,
            count=paginate,
            full_count=paginate,
            **aql_options,
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
        if min_score := as_number(
            self.query.get("epss_min_score"), default=None, type=float
        ):
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

    def list_exploits(self):
        filters = []
        binds = {}
        if cve_ids := self.query_as_array("cve_id"):
            binds["cve_ids"] = [cve_id.upper() for cve_id in cve_ids]
            filters.append("FILTER doc.name IN @cve_ids")
        query = """
FOR doc IN nvd_cve_vertex_collection OPTIONS {indexHint: "cve_search_inv", forceIndexHint: true}
FILTER doc.type == 'exploit' AND doc._is_latest == TRUE
@filters
@sort_stmt
LIMIT @offset, @count
RETURN KEEP(doc, KEYS(doc, true))
    """.replace(
            "@filters", "\n".join(filters)
        ).replace(
            "@sort_stmt",
            self.get_sort_stmt(
                CVE_SORT_FIELDS,
            ),
        )
        return self.execute_query(
            query,
            bind_vars=binds,
            aql_options=dict(optimizer_rules=["-use-index-for-sort"]),
        )

    def list_groupings(self):
        filters = []
        binds = {}
        if criteria_ids := self.query_as_array("criteria_id"):
            binds["criteria_ids"] = [
                generate_grouping_id(criteria_id.upper())
                for criteria_id in criteria_ids
            ]
            filters.append("FILTER doc.id IN @criteria_ids")
        query = """
FOR doc IN nvd_cve_vertex_collection OPTIONS {indexHint: "cve_search_inv", forceIndexHint: true}
FILTER doc.type == 'grouping' AND doc._is_latest == TRUE
@filters
@sort_stmt
LIMIT @offset, @count
RETURN KEEP(doc, KEYS(doc, true))
    """.replace(
            "@filters", "\n".join(filters)
        ).replace(
            "@sort_stmt",
            self.get_sort_stmt(
                CVE_SORT_FIELDS,
            ),
        )
        return self.execute_query(
            query,
            bind_vars=binds,
            aql_options=dict(optimizer_rules=["-use-index-for-sort"]),
        )

    def retrieve_grouping(self, criteria_id: str, hide_sys=True):
        binds = dict(
            grouping_id=generate_grouping_id(criteria_id.upper()), hide_sys=hide_sys
        )
        version_filter = "FILTER doc._is_latest == TRUE"
        if v := self.query.get("version"):
            version_filter = "FILTER doc.modified == @stix_version"
            binds.update(stix_version=v)

        query = """
FOR doc IN nvd_cve_vertex_collection OPTIONS {indexHint: "cve_search_inv", forceIndexHint: true}
FILTER doc.id == @grouping_id
#version_filter
LIMIT 1
RETURN KEEP(doc, KEYS(doc, @hide_sys))
    """.replace(
            "#version_filter", version_filter
        )
        groupings = self.execute_query(query, bind_vars=binds, paginate=False)
        if not groupings:
            raise NotFound({"error": f"No grouping with criteria_id `{criteria_id}`"})
        return groupings

    def get_grouping_bundle(self, criteria_id):
        grouping = self.retrieve_grouping(criteria_id, hide_sys=False)[0]
        types = CPEMATCH_BUNDLE_TYPES
        if t := self.query_as_array("types"):
            types = types.intersection(t)
        pre_query = self.execute_query(
            "FOR d IN nvd_cve_edge_collection FILTER d._to == @grouping_id RETURN [d._id, d._from]",
            bind_vars=dict(grouping_id=grouping["_id"]),
            paginate=False,
        )
        grouping_ids = list(itertools.chain([grouping["_id"]], *pre_query))
        query = """
        FOR d in @@view
        SEARCH d.type IN @types AND (d._id IN @grouping_id OR d.id IN @grouping_refs)
        LIMIT @offset, @count
        RETURN KEEP(d, KEYS(d, TRUE))
        """
        return self.execute_query(
            query,
            bind_vars={
                "@view": settings.VIEW_NAME,
                "grouping_id": grouping_ids,
                "grouping_refs": grouping["object_refs"],
                "types": list(types),
            },
        )

    def get_vulnerabilities(self):
        binds = {}
        filters = []

        if q := self.query.get("vuln_status"):
            binds["vuln_status"] = dict(source_name="vulnStatus", description=q.title())
            filters.append("FILTER @vuln_status IN doc.external_references")

        if q := as_number(
            self.query.get("cvss_base_score_min"), default=None, type=float
        ):
            binds["cvss_base_score_min"] = q
            filters.append("FILTER doc._cvss_base_score >= @cvss_base_score_min")

        if value := self.query_as_array("stix_id"):
            binds["stix_ids"] = value
            filters.append("FILTER doc.id in @stix_ids")

        created_min, created_max = self.query.get("created_min", ""), self.query.get(
            "created_max", "2099"
        )
        if created_min or created_max:
            filters.append(
                "FILTER IN_RANGE(doc.created, @created[0], @created[1], true, true)"
            )
            binds["created"] = created_min, created_max

        modified_min, modified_max = self.query.get("modified_min", ""), self.query.get(
            "modified_max", "2099"
        )
        if modified_min or modified_max:
            filters.append(
                "FILTER IN_RANGE(doc.modified, @modified[0], @modified[1], true, true)"
            )
            binds["modified"] = modified_min, modified_max

        prefetched_matches = []

        ######################## cpes_in_pattern and cpes_vulnerable filters ##############################
        pattern_cpes = self.query_as_array("x_cpes_not_vulnerable")
        vuln_cpes = self.query_as_array("x_cpes_vulnerable")
        if vuln_cpes or pattern_cpes:
            prefetched_matches.append(
                self.cpes_to_vulnerability(pattern_cpes, vuln_cpes)
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

        attack_ids = self.query_as_array("attack_id")
        capec_ids = self.query_as_array("capec_id")
        if attack_ids or capec_ids:
            prefetched_matches.append(
                self.capec_attack_to_vulnerability(
                    capec_ids=capec_ids, attack_ids=attack_ids
                )
            )

        if prefetched_matches:
            binds["id_matches"] = (
                list(set.intersection(*prefetched_matches)) or self.NULL_LIST
            )
            filters.append("FILTER doc.id IN @id_matches")

        ### epss  matches should happen later
        epss_filters = []
        if epss_score_min := as_number(
            self.query.get("epss_score_min"), default=None, type=float
        ):
            binds["epss_score_min"] = epss_score_min
            epss_filters.append("FILTER TO_NUMBER(last_epss.epss) >= @epss_score_min")

        if epss_percentile_min := as_number(
            self.query.get("epss_percentile_min"), default=None, type=float
        ):
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
        return self.execute_query(
            query,
            bind_vars=binds,
            aql_options=dict(optimizer_rules=["-use-index-for-sort"]),
        )

    def cpes_to_vulnerability(self, not_vulnerable_cpes, vulnerable_cpes):
        pattern_group = self.cpes_to_grouping(not_vulnerable_cpes)
        vulnerable_group = self.cpes_to_grouping(vulnerable_cpes)
        query = """
                FOR d IN nvd_cve_edge_collection OPTIONS {indexHint: "cve_edge_inv", forceIndexHint: true}
                FILTER (d.relationship_type == 'x-cpes-vulnerable' AND d._to IN @vulnerable_group) OR (d.relationship_type == 'x-cpes-not-vulnerable' AND d._to IN @pattern_group)
                RETURN [d.relationship_type, d.source_ref]
                """
        vuln_matches = set()
        pattern_matches = set()
        binds2 = dict(
            vulnerable_group=list(vulnerable_group) or self.NULL_LIST,
            pattern_group=list(pattern_group) or self.NULL_LIST,
        )
        for rtype, target in self.execute_query(
            query, binds2, aql_options=dict(cache=True), paginate=False
        ):
            target = target.replace("indicator", "vulnerability")
            if rtype == "x-cpes-vulnerable":
                vuln_matches.add(target)
            if rtype == "x-cpes-not-vulnerable":
                pattern_matches.add(target)
        cpe_matches = vuln_matches or pattern_matches
        if vulnerable_cpes and not_vulnerable_cpes:
            cpe_matches = vuln_matches.intersection(pattern_matches)
        return cpe_matches

    def capec_attack_to_vulnerability(self, capec_ids, attack_ids):
        query = """
        FOR d IN nvd_cve_edge_collection
            OPTIONS {indexHint: "cve_edge_inv", forceIndexHint: true}
        FILTER d.relationship_type == 'exploited-using'
            AND d._arango_cve_processor_note in ["cve-attack", "cve-capec"]
            AND d.external_references[*].external_id IN @ext_ids
        LET ext_id = d.external_references[1].external_id
        RETURN [ext_id, d.source_ref]
        """
        matched_ids = self.execute_query(
            query,
            bind_vars=dict(ext_ids=list(attack_ids + capec_ids)),
            aql_options=dict(cache=True),
            paginate=False,
        )
        capec_matches = set()
        attack_matches = set()
        for ext_id, stix_id in matched_ids:
            if ext_id in capec_ids:
                capec_matches.add(stix_id)
            if ext_id in attack_ids:
                attack_matches.add(stix_id)
        if attack_ids and capec_ids:
            return capec_matches.intersection(attack_matches)
        elif attack_ids:
            return attack_matches
        else:
            return capec_matches

    def cpes_to_grouping(self, cpes):
        if not cpes:
            return {}
        query = """
        LET software_ids = (
            FOR doc IN nvd_cve_vertex_collection
            FILTER doc.cpe IN @cpes
            RETURN doc.id
        )
        FOR d IN nvd_cve_vertex_collection OPTIONS {indexHint: "vulmatch_cpe_grouping", forceIndexHint: true}
        FILTER d.object_refs[*] IN software_ids
        // FILTER d._is_latest == TRUE
        RETURN [d._id, INTERSECTION(d.object_refs, software_ids)]
        """
        grouping = dict(
            self.execute_query(
                query,
                bind_vars=dict(cpes=list(cpes)),
                aql_options=dict(cache=True),
                paginate=False,
            )
        )
        return grouping

    def cves_to_softwares(self, vulnerable_cve_ids, not_vulnerable_cve_ids):
        grouping_query = """
        FOR doc IN nvd_cve_vertex_collection
        FILTER doc.type == 'indicator' AND doc._is_latest == TRUE AND doc.name IN @cpe_names
        RETURN [doc.name, doc.x_cpes.vulnerable[*].matchCriteriaId, doc.x_cpes.not_vulnerable[*].matchCriteriaId]
        """
        cve_xcpes = self.execute_query(
            grouping_query,
            bind_vars=dict(cpe_names=list(vulnerable_cve_ids + not_vulnerable_cve_ids)),
            aql_options=dict(cache=True),
            paginate=False,
        )
        vulnerable_groupings = []
        not_vulnerable_groupings = []
        for cve_id, vulerable_criteria_ids, not_vulerable_criteria_ids in cve_xcpes:
            if cve_id in vulnerable_cve_ids:
                vulnerable_groupings.extend(
                    map(generate_grouping_id, vulerable_criteria_ids)
                )
            if cve_id in not_vulnerable_cve_ids:
                not_vulnerable_groupings.extend(
                    map(generate_grouping_id, not_vulerable_criteria_ids)
                )
        if vulnerable_cve_ids and not_vulnerable_cve_ids:
            grouping_ids = set(vulnerable_groupings).intersection(
                not_vulnerable_groupings
            )
        else:
            grouping_ids = vulnerable_groupings or not_vulnerable_groupings
        software_query = """
        FOR doc IN nvd_cve_vertex_collection
        FILTER doc.id IN @grouping_ids
        RETURN doc.object_refs
        """
        software_ids = self.execute_query(
            software_query,
            bind_vars=dict(grouping_ids=list(grouping_ids)),
            aql_options=dict(cache=True),
            paginate=False,
        )
        return tuple(set(itertools.chain(*software_ids)))

    def get_cve_or_cpe_object(self, cve_id, mode="cve"):
        bind_vars = {
            "@collection": self.collection,
            "obj_name": cve_id,
        }
        version_param = f"{mode}_version"
        match mode:
            case "cve":
                bind_vars.update(
                    var="name",
                    types=["vulnerability", "indicator"],
                )
            case "cpe":
                bind_vars.update(
                    var="cpe",
                    types=["software"],
                )
            case _:
                raise ValueError(f"unsupported mode: {mode}")
        filters = ["FILTER doc._is_latest == TRUE"]
        if version_value := self.query.get(version_param):
            bind_vars["stix_modified"] = version_value
            filters[0] = "FILTER doc.modified == @stix_modified"

        query = """
            FOR doc in @@collection
            FILTER doc.type IN @types AND doc[@var] == @obj_name
            @filters
            RETURN doc
            """.replace(
            "@filters", "\n".join(filters)
        )

        cves = self.execute_query(query, bind_vars=bind_vars, paginate=False)
        if len(cves) < 1:
            msg = f"No object with {mode}_id = {cve_id}"
            if version_value:
                msg += f", version = {version_value}"
            raise NotFound(msg)
        return cves

    def get_groupings_for_indicator(
        self, indicator, include_x_cpes_vulnerable, include_x_cpes_not_vulnerable
    ):
        grouping_ids = set()
        generate_id = lambda c: generate_grouping_id(c["matchCriteriaId"])
        if include_x_cpes_not_vulnerable:
            grouping_ids.update(map(generate_id, indicator["x_cpes"]["not_vulnerable"]))
        if include_x_cpes_vulnerable:
            grouping_ids.update(map(generate_id, indicator["x_cpes"]["vulnerable"]))
        all_ids = self.execute_query(
            """
        FOR doc IN nvd_cve_vertex_collection
        FILTER doc.id IN @grouping_ids
        RETURN doc.object_refs
        """,
            bind_vars=dict(grouping_ids=tuple(grouping_ids)),
            aql_options=dict(cache=True),
            paginate=False,
        )
        return tuple(itertools.chain(grouping_ids, *all_ids))

    def get_cve_bundle(self, cve_id: str):
        primary_objects = self.get_cve_or_cpe_object(cve_id)
        cve_id = cve_id.upper()
        cve_rels_types = ["x-cpe-match"]
        binds = dict(
            cve_edge_types=cve_rels_types,
            default_imports_and_groupings=CVE_BUNDLE_DEFAULT_OBJECTS.copy(),
        )
        indicators = [p for p in primary_objects if p["type"] == "indicator"]
        if include_x_cpes_not_vulnerable := self.query_as_bool(
            "include_x_cpes_not_vulnerable", True
        ):
            cve_rels_types.append("x-cpes-not-vulnerable")
        if include_x_cpes_vulnerable := self.query_as_bool(
            "include_x_cpes_vulnerable", True
        ):
            cve_rels_types.append("x-cpes-vulnerable")
        if indicators:
            grouping_ids = self.get_groupings_for_indicator(
                indicators[0], include_x_cpes_vulnerable, include_x_cpes_not_vulnerable
            )
            binds["default_imports_and_groupings"].extend(grouping_ids)

        include_attack = self.query_as_bool("include_attack", True)
        include_capec = self.query_as_bool("include_capec", True)  # or include_attack
        include_cwe = self.query_as_bool("include_cwe", True)  # or include_capec

        if include_capec:
            cve_rels_types.append("cve-capec")
        if include_attack:
            cve_rels_types.append("cve-attack")

        if include_cwe:
            cve_rels_types.append("cve-cwe")

        docnames = [cve_id]
        doctypes = ["exploit"]
        binds.update(docnames=docnames, doctypes=doctypes)
        if self.query_as_bool("include_epss", True):
            docnames.append(f"EPSS Scores: {cve_id}")
            cve_rels_types.append("object")
            doctypes.append("report")
        if self.query_as_bool("include_kev", True):
            docnames.append(f"CISA KEV: {cve_id}")  # cisa
            docnames.append(f"Vulncheck KEV: {cve_id}")  # vulncheck
            cve_rels_types.append("object")
            doctypes.append("report")

        types = self.query_as_array("object_type") or CVE_BUNDLE_TYPES
        binds["types"] = list(CVE_BUNDLE_TYPES.intersection(types))
        binds["@view"] = settings.VIEW_NAME
        binds.update(primary_keys=[d["_id"] for d in primary_objects])
        query = """
LET cve_data_ids = UNION(@primary_keys, (
  FOR doc IN nvd_cve_vertex_collection
  FILTER (doc.name IN @docnames AND doc.type IN @doctypes) AND doc._is_latest == TRUE
  RETURN doc._id
))

LET default_object_ids = (
  FOR doc IN nvd_cve_vertex_collection
  FILTER doc.id IN @default_imports_and_groupings AND doc._is_latest == TRUE
  COLLECT id = doc.id INTO docs
  RETURN docs[0].doc._id
)

LET cve_rels = FLATTEN(
    FOR doc IN nvd_cve_edge_collection
    FILTER (doc._from IN cve_data_ids OR doc._to IN cve_data_ids) AND (doc._arango_cve_processor_note IN @cve_edge_types OR doc.relationship_type IN @cve_edge_types)
    LET retval = doc._target_type == 'grouping' ? [doc._id, doc._from] : [doc._id, doc._from, doc._to] // don't return direct relation for grouping, already handled with default_imports_and_groupings
    RETURN retval
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

    def get_cpe_bundle(self, cpe_id: str):
        filters = []
        groupings = self.cpes_to_grouping(cpes=[cpe_id])

        indicator_ids = self.execute_query(
            """
            FOR doc IN nvd_cve_edge_collection
            FILTER doc._to IN @matched_ids
            #filters
            FOR d IN [doc.source_ref, doc.target_ref, doc.id]
            RETURN d
            """.replace(
                "#filters", "\n".join(filters)
            ),
            bind_vars={"matched_ids": list(groupings)},
            paginate=False,
        )
        types = {"vulnerability", "software"}
        for indicator_id in indicator_ids[:]:
            type_part, _, uuid_part = indicator_id.partition("--")
            if type_part == "indicator":
                indicator_ids.append("vulnerability--" + uuid_part)
            types.add(type_part)
        if t := self.query_as_array("types"):
            types.intersection_update(t)
        indicator_ids.extend(itertools.chain(*groupings.values()))
        return self.execute_query(
            """
            FOR doc IN @@view
            SEARCH doc.id IN @matched_ids AND doc.type IN @types
            FILTER doc._is_latest == TRUE
            LIMIT @offset, @count
            RETURN KEEP(doc, KEYS(doc, true))
            """,
            bind_vars={
                "matched_ids": sorted(indicator_ids),
                "@view": settings.VIEW_NAME,
                "types": list(types),
            },
        )

    def get_cxe_object(
        self,
        cve_id,
        type="vulnerability",
        var="name",
        version_param="cve_version",
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

        return self.execute_query(query, bind_vars=bind_vars)

    def get_cve_versions(self, cve_id: str):
        query = """
        FOR doc IN @@collection
        FILTER doc.name == @cve_id AND doc.type == 'vulnerability'
        SORT doc.modified DESC
        RETURN DISTINCT doc.modified
        """
        bind_vars = {"@collection": self.collection, "cve_id": cve_id.upper()}
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
                struct_match[k] = str(v).lower()
                filters.append(f"FILTER doc.x_cpe_struct.`{k}` == @struct_match.`{k}`")
        if "product" not in struct_match:
            raise ValidationError("`product` filter is required")

        if "vendor" not in struct_match:
            raise ValidationError("`vendor` filter is required")

        if struct_match:
            bind_vars["struct_match"] = struct_match

        ######################## in_cve_pattern and cve_vulnerable filters ##############################
        in_cve_pattern = self.query_as_array("in_cve_not_vulnerable")
        cve_vulnerable = self.query_as_array("in_cve_vulnerable")
        if in_cve_pattern or cve_vulnerable:
            filters.append("FILTER doc.id IN @cve_matches")
            # because this filter fails with `arango.exceptions.AQLQueryExecuteError: [HTTP 500][ERR 1577] could not use index hint to serve query; {"indexHint":{"forced":true,"lookahead":1,"type":"simple","hint":["cpe_search_inv"]}}`
            # if there are no matches, we'll use NULL_LIST instead to simulate emptiness
            bind_vars["cve_matches"] = (
                self.cves_to_softwares(cve_vulnerable, in_cve_pattern) or self.NULL_LIST
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
