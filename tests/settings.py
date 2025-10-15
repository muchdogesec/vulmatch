from vulmatch.settings import *

assert ARANGODB_DATABASE == 'vulmatch', "test should not run with bad ARANGODB_DATABASE"

ARANGODB_DATABASE = "vulmatch_test"

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
    }
}
