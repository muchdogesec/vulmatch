import contextlib
import json
from pathlib import Path
import re
import typing
from arango import ArangoClient
from django.conf import settings
from .utils import Pagination, Response
from drf_spectacular.utils import OpenApiParameter
from rest_framework.validators import ValidationError

from django.http import HttpResponse

from ..server import utils
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
TLP_TYPES = set([
    "marking-definition"
])
ATTACK_TYPES = set([
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
    "x-mitre-tactic"
]
)
LOCATION_TYPES = set([
    'location'
])
CWE_TYPES = set([
    "weakness",
    # "grouping",
    # "identity",
    # "marking-definition",
    # "extension-definition"
]
)

ATLAS_TYPES = set([
  "attack-pattern",
  "course-of-action",
#   "identity",
#   "marking-definition",
  "x-mitre-collection",
  "x-mitre-matrix",
  "x-mitre-tactic"
])

SOFTWARE_TYPES = set([
    "software",
    "identity",
    "marking-definition"
]
)
CAPEC_TYPES = set([
  "attack-pattern",
  "course-of-action",
  "identity",
  "marking-definition"
]
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
OBJECT_TYPES = SDO_TYPES.union(SCO_TYPES).union(["relationship"])

CPE_RELATIONSHIP_TYPES = {"vulnerable-to": "exploits", "in-pattern": "relies-on"}
CPE_REL_SORT_FIELDS = ["modified_descending", "modified_ascending", "created_descending", "created_ascending"]
CPE_SORT_FIELDS = ['part_descending', 'part_ascending', 'vendor_descending', 'vendor_ascending', 'product_ascending', 'product_descending', 'version_ascending', 'version_descending']
CVE_BUNDLE_TYPES = set([
  "vulnerability",
  "indicator",
  "relationship",
  "report",
  "software",
  "weakness",
  "attack-pattern"
])



def positive_int(integer_string, cutoff=None, default=1):
    """
    Cast a string to a strictly positive integer.
    """
    with contextlib.suppress(ValueError, TypeError):
        ret = int(integer_string)
        if ret <= 0:
            return default
        if cutoff:
            return min(ret, cutoff)
        return ret
    return default


class ArangoDBHelper:
    max_page_size = settings.MAXIMUM_PAGE_SIZE
    page_size = settings.DEFAULT_PAGE_SIZE

    def get_sort_stmt(self, sort_options: list[str], customs={}, doc_name='doc'):
        finder = re.compile(r"(.+)_((a|de)sc)ending")
        sort_field = self.query.get('sort', sort_options[0])
        if sort_field not in sort_options:
            return ""
        if m := finder.match(sort_field):
            field = m.group(1)
            direction = m.group(2).upper()
            if cfield := customs.get(field):
                return f"SORT {cfield} {direction}"
            return f"SORT {doc_name}.{field} {direction}"

    def query_as_array(self, key):
        query = self.query.get(key)
        if not query:
            return []
        return query.split(',')
    def query_as_bool(self, key, default=True):
        query_str = self.query.get(key)
        if not query_str:
            return default
        return query_str.lower() == 'true'
    
    @classmethod
    def like_string(cls, string: str):
        return '%'+string+'%'
    
    @classmethod
    def get_page_params(cls, request):
        kwargs = request.GET.copy()
        page_number = positive_int(kwargs.get('page'))
        page_limit = positive_int(kwargs.get('page_size'), cutoff=ArangoDBHelper.max_page_size, default=ArangoDBHelper.page_size)
        return page_number, page_limit

    @classmethod
    def get_paginated_response(cls, container,  data, page_number, page_size=page_size, full_count=0):
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
    def get_paginated_response_schema(cls, container='objects', stix_type='identity'):
        if stix_type == 'string':
            container_schema = {'type':'string'}
        else:
            container_schema = {
                            "type": "object",
                            "properties": {
                                "type":{
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
                    container: {'items':container_schema, 'type':'array'}
                }
        }
    @classmethod
    def get_schema_operation_parameters(self):
        parameters = [
            OpenApiParameter(
                Pagination.page_query_param,
                type=int,
                description=Pagination.page_query_description,
            ),
            OpenApiParameter(
                Pagination.page_size_query_param,
                type=int,
                description=Pagination.page_size_query_description,
            ),
        ]
        return parameters
    client = ArangoClient(
        hosts=settings.ARANGODB_HOST_URL
    )
    DB_NAME = f"{settings.ARANGODB_DATABASE}_database"
    def __init__(self, collection, request, container='objects') -> None:
        self.collection = collection
        self.db = self.client.db(
            self.DB_NAME,
            username=settings.ARANGODB_USERNAME,
            password=settings.ARANGODB_PASSWORD,
        )
        self.container = container
        self.page, self.count = self.get_page_params(request)
        self.request = request
        self.query = request.query_params.dict()
    def execute_query(self, query, bind_vars={}, paginate=True, relationship_mode=False, container=None):
        if relationship_mode:
            return self.get_relationships(query, bind_vars)
        if paginate:
            bind_vars['offset'], bind_vars['count'] = self.get_offset_and_count(self.count, self.page)
        cursor = self.db.aql.execute(query, bind_vars=bind_vars, count=True, full_count=True)
        if paginate:
            return self.get_paginated_response(container or self.container, cursor, self.page, self.page_size, cursor.statistics()["fullCount"])
        return list(cursor)
    
    def get_offset_and_count(self, count, page) -> tuple[int, int]:
        page = page or 1
        if page >= 2**32:
            raise ValidationError(f"invalid page `{page}`")
        offset = (page-1)*count
        return offset, count
    
    def get_kev_or_epss(self, label):
        binds = {"label": label}
        binds['cve_ids'] = [qq.upper() for  qq in self.query_as_array('cve_id')] or None
        
        query = """
FOR doc IN nvd_cve_vertex_collection
FILTER doc.type == 'report' AND doc._is_latest == TRUE AND doc.labels[0] == @label
FILTER (not @cve_ids) OR doc.external_references[0].external_id IN @cve_ids
LIMIT @offset, @count
RETURN KEEP(doc, KEYS(doc, TRUE))
        """
        return self.execute_query(query, bind_vars=binds)


    def get_kev_or_epss_object(self, cve_id, label):
        bind_vars={'cve_id': cve_id, "label":label}

        query = '''
FOR doc IN nvd_cve_vertex_collection
FILTER doc.type == 'report' AND doc._is_latest == TRUE AND doc.labels[0] == @label
FILTER doc.external_references[0].external_id == @cve_id
LIMIT @offset, @count
RETURN KEEP(doc, KEYS(doc, TRUE))
            '''

        return self.execute_query(query, bind_vars=bind_vars)
    
    def get_vulnerabilities(self):
        binds = {}
        filters = []

        if q := self.query.get('vuln_status'):
            binds['vuln_status'] = dict(source_name='vulnStatus', description=q)
            filters.append("FILTER doc.external_references[? ANY FILTER MATCHES(CURRENT, @vuln_status)]")

        if q := self.query.get('cvss_base_score_min'):
            binds['cvss_base_score_min'] = float(q)
            filters.append("FILTER VALUES(doc.x_cvss)[? FILTER CURRENT.base_score >= @cvss_base_score_min]")

        if value := self.query_as_array('stix_id'):
            binds['stix_ids'] = value
            filters.append(
                "FILTER doc.id in @stix_ids"
            )

        if q := self.query.get('epss_score_min'):
            binds['epss_score_min'] = float(q)
            filters.append("FILTER TO_NUMBER(epss[doc.name].score) >= @epss_score_min")

        if q := self.query.get('epss_percentile_min'):
            binds['epss_percentile_min'] = float(q)
            filters.append("FILTER TO_NUMBER(epss[doc.name].percentile) >= @epss_percentile_min")


        for v in ['created', 'modified']:
            mn, mx = f'{v}_min', f'{v}_max'
            if q := self.query.get(mn):
                binds[mn] = q
                filters.append(f"FILTER doc.{v} >= @{mn}")

            if q := self.query.get(mx):
                binds[mx] = q
                filters.append(f"FILTER doc.{v} <= @{mx}")

        if q := self.query_as_array('cpes_vulnerable'):
            binds['cpes_vulnerable'] = q
            filters.append('''
            LET cpes_vulnerable_ids = (FOR d IN nvd_cve_vertex_collection FILTER d.cpe IN @cpes_vulnerable RETURN d.id)
            LET cpes_vulnerable = (FOR d IN nvd_cve_edge_collection FILTER d.relationship_type == 'exploits' AND d.target_ref IN cpes_vulnerable_ids RETURN d._from)
            FILTER indicator_ref IN cpes_vulnerable
            ''')
        if q := self.query_as_array('cpes_in_pattern'):
            binds['cpes_in_pattern'] = q
            filters.append('''
            LET cpes_in_pattern_ids = (FOR d IN nvd_cve_vertex_collection FILTER d.cpe IN @cpes_in_pattern RETURN d.id)
            LET cpes_in_pattern = (FOR d IN nvd_cve_edge_collection FILTER d.relationship_type == 'relies-on' AND d.target_ref IN cpes_in_pattern_ids RETURN d._from)
            FILTER indicator_ref IN cpes_in_pattern
            ''')

        if q := self.query_as_array('cve_id'):
            binds['cve_ids'] = q
            filters.append('FILTER doc.external_references[0].external_id IN @cve_ids')

        if (q := self.query_as_bool('has_kev', None)) != None:
            binds['has_kev'] = q
            filters.append('''
            LET hasKev = doc.id IN kevs
            FILTER hasKev == @has_kev
            ''')

        if q := self.query_as_array('weakness_id'):
            binds['weakness_ids'] = q
            filters.append('''
                FILTER doc.external_references[? ANY FILTER CURRENT.source_name=='cwe' AND CURRENT.external_id IN @weakness_ids]
                ''')
            
        if q := self.query_as_array('attack_id'):
            binds['attack_ids'] = q
            filters.append('''
                FILTER LENGTH(
                    FOR d IN nvd_cve_edge_collection
                        FILTER doc._id == d._from AND d.relationship_type == 'exploited-using' AND d._arango_cve_processor_note == "cve-attack" AND NOT doc._is_ref AND d.external_references
                        FILTER FIRST(FOR c IN d.external_references FILTER c.source_name == 'mitre-attack' RETURN c.external_id) IN @attack_ids
                        LIMIT 1
                        RETURN TRUE
                    ) > 0
                ''')
            
        if q := self.query_as_array('capec_id'):
            binds['capec_ids'] = q
            filters.append('''
                FILTER LENGTH(
                    FOR d IN nvd_cve_edge_collection
                        FILTER doc._id == d._from AND d.relationship_type == 'exploited-using' AND d._arango_cve_processor_note == "cve-capec" AND NOT doc._is_ref AND d.external_references
                        FILTER FIRST(FOR c IN d.external_references FILTER c.source_name == 'capec' RETURN c.external_id) IN @capec_ids
                        LIMIT 1
                        RETURN TRUE
                    ) > 0
                ''')

        query = """

LET kevs = (
FOR doc IN nvd_cve_vertex_collection
FILTER doc.type == 'report' AND doc._is_latest == TRUE AND doc.labels[0] == "kev"
RETURN doc.object_refs[0]
)
LET epss = MERGE(
FOR doc IN nvd_cve_vertex_collection
FILTER doc.type == 'report' AND doc._is_latest == TRUE AND doc.labels[0] == "epss"
RETURN {[doc.external_references[0].external_id]: LAST(doc.x_epss)}
)

FOR doc IN nvd_cve_vertex_collection
FILTER doc.type == 'vulnerability' AND doc._is_latest == TRUE
LET indicator_ref = FIRST(FOR d IN nvd_cve_edge_collection FILTER doc._id == d._to RETURN d._from)
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
                {
                    "epss_score": "TO_NUMBER(epss[doc.name].score)",
                    "epss_percentile": "TO_NUMBER(epss[doc.name].percentile)",
                    "cvss_base_score": "FIRST(VALUES(doc.x_cvss)).base_score",
                },
            ),
        )
        return self.execute_query(query, bind_vars=binds)
        # return HttpResponse(f"""{query}\n// {json.dumps(binds)}""")

    def get_cve_bundle(self, cve_id: str):
        cve_rels_types = []
        binds = dict(cve_id=cve_id.upper(), cve_edge_types=cve_rels_types)

        more_queries = {}

        include_attack = self.query_as_bool('include_attack', True)
        include_capec = self.query_as_bool('include_capec', True) # or include_attack
        include_cwe = self.query_as_bool('include_cwe', True) # or include_capec
        



        if include_capec:
            cve_rels_types.append('cve-capec')

                
        if include_attack:
            cve_rels_types.append('cve-attack')

            
        if self.query_as_bool('include_cpe', True):
            cve_rels_types.append('relies-on')
        if self.query_as_bool('include_cpe_vulnerable', True):
            cve_rels_types.append('exploits')

        if include_cwe:
            cve_rels_types.append('cve-cwe')

        vertex_filters = ["(doc.type IN ['indicator', 'vulnerability'])"]
        if self.query_as_bool('include_epss', True):
            cve_rels_types.append('object')
            vertex_filters.append("(doc.type == 'report' AND 'epss' IN doc.labels)")
        if self.query_as_bool('include_kev', True):
            cve_rels_types.append('object')
            vertex_filters.append("(doc.type == 'report' AND 'kev' IN doc.labels)")

        types = self.query_as_array('object_type') or CVE_BUNDLE_TYPES
        binds['types'] = list(CVE_BUNDLE_TYPES.intersection(types))
        binds['@view'] = settings.VIEW_NAME

        query = '''
LET cve_data = (
  FOR doc IN nvd_cve_vertex_collection
  FILTER doc._is_latest AND doc.external_references[0].external_id == @cve_id AND ( @@@vertex_filters )
  RETURN doc
)

LET cve_rels = FLATTEN(
    FOR doc IN nvd_cve_edge_collection
    FILTER (doc._from IN cve_data[*]._id OR doc._to IN cve_data[*]._id) AND [doc._arango_cve_processor_note, doc.relationship_type] ANY IN @cve_edge_types

    RETURN [doc._id, doc._from, doc._to]
    )
    
LET all_objects_ids = APPEND(cve_data[*]._id, cve_rels)
FOR d in @@view
SEARCH d.type IN @types AND d._id IN all_objects_ids
LIMIT @offset, @count
RETURN KEEP(d, KEYS(d, TRUE))
'''
        query = query \
                    .replace("@@@vertex_filters", " OR ".join(vertex_filters))
        
        # return HttpResponse(f"""{query}\n// {json.dumps(binds)}""")
        return self.execute_query(query, bind_vars=binds)
  
    def get_cxe_object(self, cve_id, type="vulnerability", var='name', version_param='cve_version', relationship_mode=False):
        bind_vars={'@collection': self.collection, 'obj_name': cve_id, "type":type, 'var':var}
        #return Response(bind_vars)
        filters = ['FILTER doc._is_latest']
        if q := self.query.get(version_param):
            bind_vars['stix_modified'] = q
            filters[0] = 'FILTER doc.modified == @stix_modified'

        query = '''
            FOR doc in @@collection
            FILTER doc.type == @type AND doc[@var] == @obj_name
            @filters
            LIMIT @offset, @count
            RETURN KEEP(doc, KEYS(doc, true))
            '''.replace('@filters', '\n'.join(filters))
        
        if var == 'cpe' and relationship_mode:
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
        bind_vars = {'@collection': self.collection, "cve_id": cve_id.upper()}
        self.container = 'versions'
        versions = self.execute_query(query, bind_vars=bind_vars, paginate=False)
        return Response(dict(latest=versions[0] if versions else None, versions=versions))

    def get_softwares(self):
        filters = []
        bind_vars = {
                "@collection": 'nvd_cve_vertex_collection',
        }
        if value := self.query_as_array('id'):
            bind_vars['ids'] = value
            filters.append(
                "FILTER doc.id in @ids"
            )

        if value := self.query.get('cpe_match_string'):
            bind_vars['cpe_match_string'] = self.like_string(value).lower()
            filters.append(
                "FILTER doc.cpe LIKE @cpe_match_string"
            )

        struct_match = {}
        if value := self.query.get('product_type'):
            struct_match['part'] = value[0].lower()
            filters.append('FILTER doc.x_cpe_struct.part == @struct_match.part')


        for k in ['product', 'vendor', 'version', 'update', 'edition', 'language', 'sw_edition', 'target_sw', 'target_hw', 'other']:
            if v := self.query.get(k):
                struct_match[k] = self.like_string(v).lower()
                filters.append(f'FILTER doc.x_cpe_struct.{k} LIKE @struct_match.{k}')

        if struct_match:
            bind_vars['struct_match'] = struct_match

        if q := self.query_as_array('cve_vulnerable'):
            bind_vars['cve_vulnerable'] = q
            filters.append('''
            FILTER cve_matches[? ANY FILTER CURRENT[0]=='exploits' AND CURRENT[1] IN @cve_vulnerable]
            ''')
        if q := self.query_as_array('in_cve_pattern'):
            bind_vars['in_cve_pattern'] = q
            filters.append('''
            FILTER cve_matches[? ANY FILTER CURRENT[0]=='relies-on' AND CURRENT[1] IN @in_cve_pattern]
            ''')


        if q := self.query.get('name'):
            bind_vars['name'] = q
            filters.append('FILTER CONTAINS(doc.name, @name)')

        query = """
            FOR doc in @@collection OPTIONS {indexHint: "cpe_search_inv", forceIndexHint: true}
            FILTER doc.type == 'software' AND doc._is_latest == TRUE
            LET cve_matches = (FOR d in nvd_cve_edge_collection FILTER d._to == doc._id AND d.relationship_type IN ['exploits', 'relies-on'] RETURN [d.relationship_type, d.external_references[0].external_id])

            @filters
            @sort_stmt
            LIMIT @offset, @count
            RETURN KEEP(doc, KEYS(doc, true))
        """.replace('@filters', '\n'.join(filters))\
            .replace('@sort_stmt', self.get_sort_stmt(CPE_SORT_FIELDS, doc_name='doc.x_cpe_struct'))
        # return HttpResponse(f"""{query}\n// {json.dumps(bind_vars)}""")
        return self.execute_query(query, bind_vars=bind_vars)

    def get_relationships(self, docs_query, binds):
        regex = r"KEEP\((\w+),\s*\w+\(.*?\)\)"
        binds['@view'] = settings.VIEW_NAME
        new_query = """
        LET matched_ids = (@docs_query)[*]._id
        FOR d IN @@view
        SEARCH d.type == 'relationship' AND (d._from IN matched_ids OR d._to IN matched_ids)
        LIMIT @offset, @count
        RETURN KEEP(d, KEYS(d, TRUE))
        """.replace('@docs_query', re.sub(regex, lambda x: x.group(1), docs_query.replace('LIMIT @offset, @count', '')))
        return self.execute_query(new_query, bind_vars=binds, container='relationships')
  
    def get_cpe_relationships(self, docs_query, binds):
        regex = r"KEEP\((\w+),\s*\w+\(.*?\)\)"
        binds['@view'] = settings.VIEW_NAME
        if reftypes := self.query_as_array('relationship_type'):
            binds['relationship_types'] = []
            for t in reftypes:
                if qt := CPE_RELATIONSHIP_TYPES.get(t):
                    binds['relationship_types'].append(qt)
        else:
            binds['relationship_types'] = tuple(CPE_RELATIONSHIP_TYPES.values())
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
        """.replace('@docs_query', re.sub(regex, lambda x: x.group(1), docs_query.replace('LIMIT @offset, @count', 'LIMIT 1'))).replace('@sort_stmt', self.get_sort_stmt(CPE_REL_SORT_FIELDS, doc_name='rel'))

        return self.execute_query(new_query, bind_vars=binds, container='relationships')
  