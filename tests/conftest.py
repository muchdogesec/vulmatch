import pytest
from vulmatch.worker.populate_dbs import setup_arangodb

def pytest_sessionstart():
    setup_arangodb()


@pytest.fixture(scope='session')
def api_schema():
    import schemathesis
    from vulmatch.asgi import application
    yield schemathesis.openapi.from_asgi("/api/schema/?format=json", application)