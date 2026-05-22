import pytest


@pytest.fixture(autouse=True, scope="package")
def eager_celery():
    from vulmatch.worker.celery import app

    app.conf.task_always_eager = True
    yield
    app.conf.task_always_eager = False

@pytest.fixture
def celery_no_eager():
    from vulmatch.worker.celery import app
    orig = app.conf.task_always_eager
    app.conf.task_always_eager = False
    yield
    app.conf.task_always_eager = orig


# @pytest.fixture(scope="package", autouse=True)
# def django_db_setup(django_db_setup, django_db_blocker):
#     with django_db_blocker.unblock():
#         yield

@pytest.fixture(autouse=True)
def use_db(db):
    yield db