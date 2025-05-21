#### This script adds to vulnerability objects data which are needed later for filtering purposes. 
# It is to be run after uploading cves by any other method than POSTing vulmatch:cpes



from datetime import datetime
import os
import typing
from arango.client import ArangoClient
from arango.database import StandardDatabase



query = """
FOR doc IN nvd_cve_vertex_collection
FILTER doc.type == 'vulnerability' AND doc._is_latest == TRUE
LIMIT @N * @count_per_it, @count_per_it
UPDATE doc WITH {_cvss_base_score: LAST(VALUES(doc.x_cvss)).base_score} IN nvd_cve_vertex_collection OPTIONS {keepNull: False}
"""

def get_db():
    client = ArangoClient(os.environ["ARANGODB_HOST_URL"], request_timeout=600)
    return client.db("vulmatch_database", os.environ["ARANGODB_USERNAME"], os.environ["ARANGODB_PASSWORD"], verify=True)

COUNT_PER_ITERATION = 10_000
modified = 0
db = get_db()
N = 0
while True:
    result = db.aql.execute(query, count=True, full_count=True, bind_vars=dict(count_per_it=COUNT_PER_ITERATION, N=N))
    stats = result.statistics()
    N += 1
    modified += stats['modified']
    fullcount = stats['fullCount']
    print(f"[{datetime.now()}] modified {modified} items, {fullcount=}")
    if stats['modified'] == 0:
        print(f"[{datetime.now()}] nothing more to modify... stopping")
        break
    