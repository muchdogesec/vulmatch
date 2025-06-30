## arango_cve_processor

Downloads and imports files to ArangoDB used as the base data for arango_cve_processor.

To run these scripts, from the root of stix2arango;

```shell
python3 utilities/arango_cve_processor/insert_archive_cve.py
```

Where:

* `--database` (required): is the name of the Arango database the objects should be stored in. If database does not exist, stix2arango will create it
* `--ignore_embedded_relationships` (optional): if flag passes this will stop any embedded relationships from being generated
* `--min_date` (optional): the first date to download data
* `--max_date` (optional): the last date to download data
* `--start_over` (optional): will delete logs from last run in sqlite

e.g.

Download all CVE data

```shell
python3 utilities/arango_cve_processor/insert_archive_cve.py \
	--database cti_knowledge_base_store \
	--ignore_embedded_relationships \
	--start_over
```

Download only CVE data on `2025-01-09` through to, and including `2025-01-31`

```shell
python3 utilities/arango_cve_processor/insert_archive_cve.py \
	--database cti_knowledge_base_store \
	--min_date 2025-01-09 \
	--max_date 2025-01-31 \
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