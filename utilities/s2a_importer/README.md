## s2a_importer

### clone the repo and setup virtual environment

```shell
git clone https://github.com/muchdogesec/vulmatch
cd vulmatch
```

```shell
python3 -m venv vulmatch-venv
source vulmatch-venv/bin/activate
# install requirements
pip3 install stix2arango
````

### modify `.env` file

```shell
vi .env
```

Add these to the bottom of the file

```
# UTILITIES
ARANGODB_HOST=127.0.0.1
ARANGODB_PORT=8529
ALWAYS_LATEST=0 # change to 1 on first backfill for dates up to 2024-12-21
```

### run

Downloads and imports files to ArangoDB used as the base data for arango_cve_processor.

To run these scripts, from the root of stix2arango;

```shell
python3 utilities/s2a_importer/insert_archive_cve.py
```

Where:

* `--database` (required): is the name of the Arango database the objects should be stored in. If database does not exist, stix2arango will create it
* `--ignore_embedded_relationships` (optional): if flag passes this will stop any embedded relationships from being generated
* `--min_date` (optional): the first date to download data
* `--max_date` (optional): the last date to download data
* `--start_over` (optional): will delete logs from last run in sqlite

e.g.

Download only CVE data on `2025-12-25` through to, and including `2025-01-08`

```shell
python3 utilities/s2a_importer/insert_archive_cve.py \
	--database vulmatch \
	--min_date 2024-12-25 \
	--max_date 2025-01-04 \
	--ignore_embedded_relationships \
	--start_over
```

#### A note on complete backfill

You might see errors like this:

```txt
Failed to download file from https://cve2stix.vulmatch.com/2000-02/cve-bundle-2000_02_22-00_00_00-2000_02_22-23_59_59.json with status code 404
```

This is expected. It is expected because no data CVE exists between this time range, as such, no file exists and thus the download fails.

This is more of an issue when downloading all CVE data because in the earlier years large periods of time have no data (e.g. in 2007 there is no data until 2007-09).
