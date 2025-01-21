from datetime import datetime
import typing
from django.conf import settings
from arango.client import ArangoClient
from arango.database import StandardDatabase
if typing.TYPE_CHECKING:
    from ..import settings


from stix2arango.stix2arango import Stix2Arango


collections_to_create = ['nvd_cve']


def get_db():
    client = ArangoClient(settings.ARANGODB_HOST_URL)
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
    vertex_collection = db.collection('nvd_cve_vertex_collection')
    edge_collection = db.collection('nvd_cve_edge_collection')
    time = int(datetime.now().timestamp())
    for sorter in "created modified name cpe".split():
        vertex_collection.add_index(dict(type='persistent', fields=["type", "_is_latest", sorter], inBackground=True, name=f"vulmatch_cve_sort_{sorter}_{time}"))
    vertex_collection.add_index(dict(type='persistent', fields=["cpe"], storedValues=["id"], inBackground=True, name=f"vulmatch_cpe"))
    vertex_collection.add_index(dict(type='persistent', fields=["name"], inBackground=True, name=f"vulmatch_name"))    
            

def create_collections():
    #create db/collections
    for c in find_missing(collections_to_create):
        print(f"creating collection: {c}")
        s2a = Stix2Arango(settings.ARANGODB_DATABASE, collection=c, file='no-file', username=settings.ARANGODB_USERNAME, password=settings.ARANGODB_PASSWORD, host_url=settings.ARANGODB_HOST_URL)
    create_indexes(get_db())

   
   
if __name__ == '__main__':
    create_collections()





