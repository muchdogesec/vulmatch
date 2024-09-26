import typing
from arango import ArangoClient
from django.conf import settings
from .utils import Pagination, Response
from drf_spectacular.utils import OpenApiParameter
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
CWE_TYPES = set([
    "weakness",
    "grouping",
    "identity",
    "marking-definition",
    "extension-definition"
]
)
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
OBJECT_TYPES = SDO_TYPES.union(SCO_TYPES).union(["relationship"])
class ArangoDBHelper:
    max_page_size = settings.MAXIMUM_PAGE_SIZE
    page_size = settings.DEFAULT_PAGE_SIZE
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
    def get_page_params(cls, request):
        kwargs = request.GET.copy()
        page_number = int(kwargs.get('page', 1))
        page_limit  = min(int(kwargs.get('page_size', ArangoDBHelper.page_size)), ArangoDBHelper.max_page_size)
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
                    container: container_schema
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
    def execute_query(self, query, bind_vars={}, paginate=True):
        if paginate:
            bind_vars['offset'], bind_vars['count'] = self.get_offset_and_count(self.count, self.page)
        cursor = self.db.aql.execute(query, bind_vars=bind_vars, count=True, full_count=True)
        if paginate:
            print(cursor.statistics())
            return self.get_paginated_response(self.container, cursor, self.page, self.page_size, cursor.statistics()["fullCount"])
        return list(cursor)
    def get_offset_and_count(self, count, page) -> tuple[int, int]:
        page = page or 1
        offset = (page-1)*count
        return offset, count

    def get_vulnerabilities(self):
        binds = {}
        filters = []
        if q := self.query_as_array('cpes_vulnerable'):
            binds['cpes_vulnerable'] = q
            filters.append('''
            LET vulnerable_cpes = (FOR d in nvd_cve_edge_collection FILTER d._from == indicator_ref AND d.relationship_type == 'is-vulnerable' AND DOCUMENT(d._to).cpe IN @cpes_vulnerable RETURN TRUE)
            FILTER LENGTH(vulnerable_cpes) > 0
            ''')
        if q := self.query_as_array('cpes_in_pattern'):
            binds['cpes_in_pattern'] = q
            filters.append('''
            LET cpes_in_pattern = (FOR d in nvd_cve_edge_collection FILTER d._from == indicator_ref AND d.relationship_type == 'pattern-contains' AND DOCUMENT(d._to).cpe IN @cpes_in_pattern RETURN TRUE)
            FILTER LENGTH(cpes_in_pattern) > 0
            ''')

        if q := self.query_as_array('cve_id'):
            binds['cve_ids'] = q
            filters.append('FILTER doc.external_references[0].external_id IN @cve_ids')
        
        if (q := self.query_as_bool('has_kev', None)) != None:
            binds['has_kev'] = q
            filters.append('''
            LET hasKev = LENGTH(FOR d IN nvd_cve_edge_collection FILTER doc._id == d._to AND d.relationship_type == 'sighting-of' RETURN d._from) > 0
            FILTER hasKev == @has_kev
            ''')

        if q := self.query_as_array('weakness_id'):
            binds['weakness_ids'] = q
            filters.append('''
                FILTER LENGTH(FOR d IN nvd_cve_edge_collection FILTER doc._id == d._from AND d.relationship_type == 'exploited-using' AND LAST(SPLIT(d.description, ' ')) IN @weakness_ids LIMIT 1 RETURN TRUE) > 0
                ''')

        query = """
FOR doc IN nvd_cve_vertex_collection
FILTER doc.type == 'vulnerability' AND doc._is_latest
LET indicator_ref = FIRST(FOR d IN nvd_cve_edge_collection FILTER doc._id == d._to RETURN d._from)
@filters
LIMIT @offset, @count
RETURN KEEP(doc, KEYS(doc, true))
    """.replace('@filters', '\n'.join(filters))
        #return Response(query)
        return self.execute_query(query, bind_vars=binds)
    
    def get_cve_bundle(self, cve_id):
        query = '''
LET bundle = FIRST(FOR doc IN nvd_cve_vertex_collection
FILTER doc._is_latest AND doc.id == @id
LIMIT 1
RETURN UNIQUE(FLATTEN(
FOR v, e, p IN 0..5
  OUTBOUND doc._id
  GRAPH "cti_graph"
  
  PRUNE v.type IN ['identity', 'marking-definition'] OR STARTS_WITH(e.relationship_type, 'x-capec') OR (e AND NOT IS_SAME_COLLECTION('nvd_cve_edge_collection', e._id))
  OPTIONS { uniqueVertices: "path"}
RETURN APPEND(p.vertices, p.edges)
))) OR []

FOR doc IN bundle
LIMIT @offset, @count
RETURN KEEP(doc, KEYS(doc, true))
'''
        return self.execute_query(query, bind_vars=dict(id=cve_id))
    
    def get_attack_objects(self, matrix):
        filters = []
        types = ATTACK_TYPES
        if new_types := self.query_as_array('type'):
            types = types.intersection(new_types)
        bind_vars = {
                "@collection": f'mitre_attack_{matrix}_vertex_collection',
                "types": list(types),
        }
        if value := self.query_as_array('id'):
            bind_vars['ids'] = value
            filters.append(
                "FILTER doc.id in @ids"
            )
        
        if value := self.query_as_array('attack_id'):
            bind_vars['attack_ids'] = value
            filters.append(
                "FILTER doc.external_references[0].external_id in @attack_ids"
            )
        if q := self.query.get('name'):
            bind_vars['name'] = q
            filters.append('FILTER CONTAINS(doc.name, @name)')
        
        if q := self.query.get('description'):
            bind_vars['description'] = q
            filters.append('FILTER CONTAINS(doc.description, @description)')
        query = """
            FOR doc in @@collection
            FILTER CONTAINS(@types, doc.type) AND doc._is_latest
            @filters
            LIMIT @offset, @count
            RETURN KEEP(doc, KEYS(doc, true))
        """.replace('@filters', '\n'.join(filters))
        return self.execute_query(query, bind_vars=bind_vars)
    
    def get_object(self, stix_id):
        return self.execute_query('''
        FOR doc in @@collection
        FILTER doc.id == @stix_id AND doc._is_latest
        LIMIT @offset, @count
        RETURN KEEP(doc, KEYS(doc, true))
        ''', bind_vars={'@collection': self.collection, 'stix_id': stix_id})
    
    
    def get_weakness_or_capec_objects(self, cwe=True, types=CWE_TYPES):
        filters = []
        if new_types := self.query_as_array('type'):
            types = types.intersection(new_types)

        bind_vars = {
                "@collection": self.collection,
                "types": list(types),
        }
        if value := self.query_as_array('id'):
            bind_vars['ids'] = value
            filters.append(
                "FILTER doc.id in @ids"
            )
        
        if value := self.query_as_array('cwe_id'):
            bind_vars['cwe_ids'] = value
            filters.append(
                "FILTER doc.external_references[0].external_id in @cwe_ids"
            )
        if value := self.query_as_array('capec_id'):
            bind_vars['capec_ids'] = value
            filters.append(
                "FILTER doc.external_references[0].external_id in @capec_ids"
            )
        if q := self.query.get('name'):
            bind_vars['name'] = q
            filters.append('FILTER CONTAINS(doc.name, @name)')
        
        if q := self.query.get('description'):
            bind_vars['description'] = q
            filters.append('FILTER CONTAINS(doc.description, @description)')
        query = """
            FOR doc in @@collection
            FILTER CONTAINS(@types, doc.type) AND doc._is_latest
            @filters
            LIMIT @offset, @count
            RETURN KEEP(doc, KEYS(doc, true))
        """.replace('@filters', '\n'.join(filters))
        return self.execute_query(query, bind_vars=bind_vars)
    

    def get_softwares(self):
        filters = []
        bind_vars = {
                "@collection": 'nvd_cpe_vertex_collection',
                "types": ['software'],
        }
        if value := self.query_as_array('id'):
            bind_vars['ids'] = value
            filters.append(
                "FILTER doc.id in @ids"
            )
        
        if value := self.query_as_array('cpe_match_string'):
            bind_vars['cpe_match_string'] = value
            filters.append(
                "FILTER @cpe_match_string[? ANY FILTER CONTAINS(doc.cpe, CURRENT)]"
            )
        if value := self.query.get('product_type'):
            bind_vars['product_type'] = value[0]
            filters.append(
                "FILTER @product_type == SPLIT(doc.cpe, ':')[2]"
            )
            
        if value := self.query.get('product'):
            bind_vars['product'] = value
            filters.append(
                "FILTER @product == SPLIT(doc.cpe, ':')[4]"
            )
        if value := self.query.get('vendor'):
            bind_vars['vendor'] = value
            filters.append(
                "FILTER @vendor == SPLIT(doc.cpe, ':')[3]"
            )

        
        if q := self.query_as_array('cve_vulnerable'):
            bind_vars['cve_vulnerable'] = q
            filters.append('''
            FILTER cve_matches[? ANY FILTER CURRENT[0]=='is-vulnerable' AND CURRENT[1] IN @cve_vulnerable]
            ''')
        if q := self.query_as_array('in_cve_pattern'):
            bind_vars['in_cve_pattern'] = q
            filters.append('''
            FILTER cve_matches[? ANY FILTER CURRENT[0]=='pattern-contains' AND CURRENT[1] IN @in_cve_pattern]
            ''')
            
        if q := self.query.get('name'):
            bind_vars['name'] = q
            filters.append('FILTER CONTAINS(doc.name, @name)')
        
        query = """
            FOR doc in @@collection
            FILTER CONTAINS(@types, doc.type) AND doc._is_latest
            LET cve_matches = (FOR d in nvd_cve_edge_collection FILTER d._to == doc._id AND d.relationship_type IN ['is-vulnerable', 'pattern-contains'] RETURN [d.relationship_type, FIRST(SPLIT(d.description, ' '))])

            @filters
            LIMIT @offset, @count
            RETURN KEEP(doc, KEYS(doc, true))
        """.replace('@filters', '\n'.join(filters))
        return self.execute_query(query, bind_vars=bind_vars)


    def get_software_by_name(self, cpe_name):
        return self.execute_query('''
        FOR doc in @@collection
        FILTER doc.cpe == @cpe_name AND doc._is_latest
        LIMIT @offset, @count
        RETURN KEEP(doc, KEYS(doc, true))
        ''', bind_vars={'@collection': self.collection, 'cpe_name': cpe_name})



    def get_reports(self, id=None):
        bind_vars = {
                "@collection": self.collection,
                "type": 'report',
        }
        query = """
            FOR doc in @@collection
            FILTER doc.type == @type AND doc._is_latest
            LIMIT @offset, @count
            RETURN KEEP(doc, KEYS(doc, true))
        """
        print(query)
        return self.execute_query(query, bind_vars=bind_vars)
    def get_report_by_id(self, id):
        bind_vars = {
                "@collection": self.collection,
                "id": id,
                'type': 'report',
        }
        query = """
            FOR doc in @@collection
            FILTER doc.id == @id AND doc._is_latest AND doc.type == @type
            LIMIT 1
            RETURN KEEP(doc, KEYS(doc, true))
        """
        return self.execute_query(query, bind_vars=bind_vars, paginate=False)
    def remove_report(self, id):
        bind_vars = {
                "@collection": self.collection,
                'report_id': id,
        }
        query = """
            FOR doc in @@collection
            FILTER doc._stixify_report_id == @report_id AND doc._is_latest
            RETURN doc._id
        """
        collections = {}
        out = self.execute_query(query, bind_vars=bind_vars, paginate=False)
        for key in out:
            collection, key = key.split('/', 2)
            collections[collection] = collections.get(collection, [])
            collections[collection].append(key)
        deletion_query = """
            FOR _key in @objects
            REMOVE {_key} IN @@collection
            RETURN _key
        """
        for collection, objects in collections.items():
            bind_vars = {
                "@collection": collection,
                "objects": objects,
            }
            self.execute_query(deletion_query, bind_vars, paginate=False)
    def get_scos(self, matcher={}):
        types = SCO_TYPES
        other_filters = []
        if new_types := self.query_as_array('types'):
            types = types.intersection(new_types)
        bind_vars = {
                "@collection": self.collection,
                "types": list(types),
        }
        if value := self.query.get('value'):
            bind_vars['search_value'] = value
            other_filters.append(
                """
                (
                    CONTAINS(doc.value, @search_value) OR
                    CONTAINS(doc.name, @search_value) OR
                    CONTAINS(doc.path, @search_value) OR
                    CONTAINS(doc.key, @search_value) OR
                    CONTAINS(doc.number, @search_value) OR
                    CONTAINS(doc.string, @search_value) OR
                    CONTAINS(doc.hash, @search_value) OR
                    CONTAINS(doc.symbol, @search_value) OR
                    CONTAINS(doc.address, @search_value) OR
                    (doc.type == 'file' AND @search_value IN doc.hashes)
                )
                """.strip()
            )
        # if post_id := self.query.get('post_id'):
        #     matcher["_obstracts_post_id"] = post_id
        # if report_id := self.query.get('report_id'):
        #     matcher["_stixify_report_id"] = report_id
        if matcher:
            bind_vars['matcher'] = matcher
            other_filters.insert(0, "MATCHES(doc, @matcher)")
        if other_filters:
            other_filters = "FILTER " + " AND ".join(other_filters)
        query = f"""
            FOR doc in @@collection
            FILTER CONTAINS(@types, doc.type) AND doc._is_latest
            {other_filters or ""}
            LIMIT @offset, @count
            RETURN KEEP(doc, KEYS(doc, true))
        """
        return self.execute_query(query, bind_vars=bind_vars)
    def get_sdos(self):
        types = SDO_TYPES
        if new_types := self.query_as_array('types'):
            types = types.intersection(new_types)
        if not self.query_as_bool('include_txt2stix_notes', False):
            types.remove('note')
        bind_vars = {
            "@collection": self.collection,
            "types": list(types),
        }
        other_filters = []
        if term := self.query.get('labels'):
            bind_vars['labels'] = term
            other_filters.append("COUNT(doc.labels[* CONTAINS(CURRENT, @labels)]) != 0")
        if term := self.query.get('name'):
            bind_vars['name'] = term
            other_filters.append("CONTAINS(doc.name, @name)")
        if other_filters:
            other_filters = "FILTER " + " AND ".join(other_filters)
        query = f"""
            FOR doc in @@collection
            FILTER doc.type IN @types AND doc._is_latest
            {other_filters or ""}
            LIMIT @offset, @count
            RETURN  KEEP(doc, KEYS(doc, true))
        """
        return self.execute_query(query, bind_vars=bind_vars)