# Vulmatch

## Before you begin...

We offer a fully web version of Vulmatch which includes many additional features over those in this codebase. [You can find out more about the web version here](https://www.vulmatch.com/).

## Overview

Vulmatch is a database of CVEs in STIX 2.1 format with a REST API wrapper to access them.

Some common reasons people use Vulmatch include;

* filter CVEs by CVSS and/or EPSS scoring
* get a list of CVEs being exploited (CISA KEV)
* search for CVEs by CPEs (i.e. "what CVEs am I vulnerable to?")
* search for CVEs by Weakness

## Install

### Download and configure

```shell
# clone the latest code
git clone https://github.com/muchdogesec/vulmatch
```

### Configuration options

Vulmatch has various settings that are defined in an `.env` file.

To create one using the default settings:

```shell
cp .env.example .env
```

For the `ARANGODB_DATABASE`, on first run it is best to use an empty database in ArangoDB you've created. You can then add the CVE, CPE, etc. data by running POST request to the API. This will ensure the naming convention of the Collections will be correct.

### Build the Docker Image

```shell
sudo docker compose build
```

### Start the server

```shell
sudo docker compose up
```

### Access the server

The webserver (Django) should now be running on: http://127.0.0.1:8005/

You can access the Swagger UI for the API in a browser at: http://127.0.0.1:8005/api/schema/swagger-ui/

#### ArangoDB install

Note, this script will not install an ArangoDB instance.

If you're new to ArangoDB, [you can install the community edition quickly by following the instructions here](https://arangodb.com/community-server/).

If you are running ArangoDB locally, be sure to set `ARANGODB='http://host.docker.internal:8529/'` in the `.env` file otherwise you will run into networking errors.

#### Note on Django

The webserver is Django.

To create an admin user in Django

```shell
sudo docker-compose run django python manage.py createsuperuser
```

You can access the django admin UI at:

http://127.0.0.1:8005/admin

### Add data

By default, the `ARANGODB_DATABASE``

### Running in production

Note, if you intend on using this in production, you should also modify the variables in the `.env` file for `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASS`, `DJANGO_SECRET` and `DEBUG` (to `False`)

## Support

[Minimal support provided via the DOGESEC community](https://community.dogesec.com/).

## License

[Apache 2.0](/LICENSE).