from datetime import datetime
import typing
from django.conf import settings
from arango.client import ArangoClient
from arango.database import StandardDatabase
if typing.TYPE_CHECKING:
    from ..import settings


from stix2arango.stix2arango import Stix2Arango
from arango_cve_processor.tools.utils import create_indexes as create_acvep_indexes
from dogesec_commons.objects import db_view_creator


collections_to_create = ['nvd_cve']


def get_db():
    client = ArangoClient(settings.ARANGODB_HOST_URL, request_timeout=600)
    return client.db(settings.ARANGODB_DATABASE+"_database", settings.ARANGODB_USERNAME, settings.ARANGODB_PASSWORD, verify=True)

def find_missing(collections_to_create):
    try:
        db = get_db()
    except Exception as e:
        return collections_to_create
    collections = [c["name"] for c in db.collections()]
    return [
        c for c in collections_to_create
            if not set([f"{c}_vertex_collection", f"{c}_edge_collection"]).issubset(collections)
        ]

def create_indexes(db: StandardDatabase):
    print("creating vulmatch's indexes, this may take several minutes if creating for the first time depending on how much data on the server")
    vertex_collection = db.collection('nvd_cve_vertex_collection')
    edge_collection = db.collection('nvd_cve_edge_collection')
    time = int(datetime.now().timestamp())
    for sorter in "created modified name cpe".split():
        vertex_collection.add_index(dict(type='persistent', fields=["type", "_is_latest", sorter], inBackground=True, name=f"vulmatch_cve_sort_{sorter}_{time}"))
    vertex_collection.add_index(dict(type='persistent', fields=["cpe"], storedValues=["id"], inBackground=True, name=f"vulmatch_cpe", sparse=True))
    vertex_collection.add_index(dict(type='persistent', fields=["type", "cpe"], storedValues=["id"], inBackground=True, name=f"vulmatch_type_cpe"))
    vertex_collection.add_index(dict(type='persistent', fields=["name"], inBackground=True, name=f"vulmatch_name"))
    db.create_analyzer('norm_en', analyzer_type='norm', properties={ "locale": "en", "accent": False, "case": "lower" })
    vertex_collection.add_index(dict(type='inverted', name='cpe_search_inv', fields=[
        dict(name='cpe', analyzer='norm_en'),
        "id",
        "type",
        *[dict(name=f'x_cpe_struct.{name}', analyzer='norm_en') for name in ['product', 'vendor', 'version', 'update', 'edition', 'language', 'sw_edition', 'target_sw', 'target_hw', 'other']],
        "x_cpe_struct.part",
        "_is_latest"
    ], inBackground=True))
    vertex_collection.add_index(dict(type='inverted', name='cve_search_inv', sparse=True, fields=[
        "name",
        "id",
        "modified",
        "created",
        dict(name="description", analyzer='norm_en'),
        "type",
        "_cvss_base_score",
        "_epss_score",
        "_epss_percentile",
        "_is_latest",
    ], inBackground=True, storedValues=["external_references"]))
    edge_collection.add_index(dict(type='inverted', name='cve_edge_inv', fields=[
        "external_references[*].external_id",
        "relationship_type",
        "_arango_cve_processor_note",
    ], storedValues=["_from", "_to"], inBackground=True))
    create_acvep_indexes(db)



def create_collections():
    #create db/collections
    for c in find_missing(collections_to_create):
        print(f"creating collection: {c}")
        s2a = Stix2Arango(settings.ARANGODB_DATABASE, collection=c, file='no-file', username=settings.ARANGODB_USERNAME, password=settings.ARANGODB_PASSWORD, host_url=settings.ARANGODB_HOST_URL)
    create_indexes(get_db())

   
   
if __name__ == '__main__':
    create_collections()
    db_view_creator.startup_func()





