"""
Django settings for vulmatch project.

Generated by 'django-admin startproject' using Django 5.1.1.

For more information on this file, see
https://docs.djangoproject.com/en/5.1/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/5.1/ref/settings/
"""

import os
from pathlib import Path
from textwrap import dedent
from typing import Any
import uuid

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ.get('DJANGO_SECRET', "insecure_django_secret")

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.getenv("DJANGO_DEBUG", False)

ALLOWED_HOSTS = os.getenv('DJANGO_ALLOWED_HOSTS', "localhost 127.0.0.1 [::1]").split()

CORS_ALLOW_ALL_ORIGINS = os.environ.get('DJANGO_CORS_ALLOW_ALL_ORIGINS', True)
CORS_ALLOWED_ORIGINS = [os.environ.get('DJANGO_CORS_ALLOWED_ORIGINS', "http://127.0.0.1:8005")]

MEDIA_ROOT = Path("/var/www/vulmatch_files/media/uploads")

STATIC_ROOT = MEDIA_ROOT.with_name("staticfiles")
MEDIA_URL = str("media/uploads/")

# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'dogesec_commons.objects.app.ArangoObjectsViewApp',
    'drf_spectacular',
    'django.contrib.postgres',
    'vulmatch.server',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'vulmatch.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'vulmatch.wsgi.application'


# Database
# https://docs.djangoproject.com/en/5.1/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.getenv('POSTGRES_DB'),            # Database name
        'USER': os.getenv('POSTGRES_USER'),          # Database user
        'PASSWORD': os.getenv('POSTGRES_PASSWORD'),  # Database password
        'HOST': os.getenv('POSTGRES_HOST'),          # PostgreSQL service name in Docker Compose
        'PORT': os.getenv('POSTGRES_PORT', '5432'),  # PostgreSQL default port
    },
    'sqlite': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}


# Password validation
# https://docs.djangoproject.com/en/5.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/5.1/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.1/howto/static-files/

STATIC_URL = 'static/'

# Default primary key field type
# https://docs.djangoproject.com/en/5.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

REST_FRAMEWORK = {
    "DEFAULT_SCHEMA_CLASS": "vulmatch.server.autoschema.VulmatchAutoSchema",
    'DEFAULT_AUTHENTICATION_CLASSES': [],
    'DEFAULT_PERMISSION_CLASSES': [],
    'EXCEPTION_HANDLER': "dogesec_commons.utils.custom_exception_handler",
}

STIX_NAMESPACE = uuid.UUID('e92c648d-03eb-59a5-a318-9a36e6f8057c')

MAXIMUM_PAGE_SIZE = int(os.getenv("MAX_PAGE_SIZE", 50))
DEFAULT_PAGE_SIZE = int(os.getenv("DEFAULT_PAGE_SIZE", 50))

CELERY_RESULTS_BACKEND = os.getenv('result_backend')

SPECTACULAR_SETTINGS: dict[str, Any] = {
    "COMPONENT_SPLIT_REQUEST": True,
    'ENUM_GENERATE_CHOICE_DESCRIPTION': False,
    "TITLE": "Vulmatch API",
    "DESCRIPTION": dedent(
        """
        Vulmatch is a database of CVEs in STIX 2.1 format with a REST API wrapper to access them.\n\n
        [DOGESEC](https://www.dogesec.com/) offer a fully hosted web version of Vulmatch which includes many additional features over those in this codebase. [You can find out more about the web version here](https://www.vulmatch.com/).
    """
    ),
    "VERSION": "1.0.0",
    "CONTACT": {
        "email": "noreply@dogesec.com",
        "url": "https://github.com/muchdogesec/vulmatch",
    },
    "TAGS": [
        {"name": "CVE", "description": "Download and search the latest CVE objects."},
        {"name": "CPE", "description": "Search and filter CPE objects."},
        {"name": "KEV", "description": "Search and filter KEV objects."},
        {"name": "EPSS", "description": "Search and filter EPSS objects."},
        {"name": "ATT&CK", "description": "Search and filter MITRE ATT&CK objects."},
        {"name": "CAPEC", "description": "Search and filter MITRE CAPEC objects."},
        {"name": "CWE", "description": "Search and filter MITRE CWE objects."},
        {"name": "Objects", "description": "Explore all STIX Objects stored in Vulmatch."},
        {"name": "Arango CVE Processor", "description": "Trigger the generation of relationships between objects."},
        {"name": "Jobs", "description": "Search through Vulmatch Jobs triggered when downloading data and creating relationships."},
    ]
}

VIEW_NAME = "vulmatch_view"
ARANGODB_USERNAME   = os.getenv('ARANGODB_USERNAME')
ARANGODB_PASSWORD   = os.getenv('ARANGODB_PASSWORD')
ARANGODB_HOST_URL   = os.getenv("ARANGODB_HOST_URL")
ARANGODB_DATABASE   = "vulmatch"

CVE2STIX_BUCKET_ROOT_PATH    = os.environ["CVE2STIX_BUCKET_ROOT_PATH"]