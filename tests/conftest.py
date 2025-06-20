from vulmatch.worker.populate_dbs import setup_arangodb

def pytest_sessionstart():
    setup_arangodb()