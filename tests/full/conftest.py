import pytest


@pytest.fixture(autouse=True, scope="package")
def eager_celery():
    from vulmatch.worker.celery import app

    app.conf.task_always_eager = True
    yield
    app.conf.task_always_eager = False


@pytest.fixture(scope="package", autouse=True)
def django_db_setup(django_db_setup, django_db_blocker):
    with django_db_blocker.unblock():
        yield
