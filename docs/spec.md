# Vulmatch

## Overview

Vulmatch is a database of CVEs in STIX 2.1 format with a REST API. Some common reasons people use Vulmatch include 

* filter CVEs by CVSS and/or EPSS scoring
* get a list of CVEs being exploited (CISA KEV)
* search for CVEs by CPEs (i.e. "what CVEs am I vulnerable to?")
* search for CVEs by Weakness

## The backend

Vulmatch stores the following data in an ArangoDB to power the API;

* CVE records stored on Cloudflare 
* CPE records stored on Cloudflare
* CWE records stored on Cloudflare
* ATT&CK records stored on Cloudflare

The download logic can be seen in these scripts:

https://github.com/muchdogesec/stix2arango/tree/main/utilities

* insert_archive_cpe
* insert_archive_cve
* insert_archive_cwe
* insert_archive_attack_enterprise
* insert_archive_attack_ics
* insert_archive_attack_mobile

The user can define the database in the `.env` file, however, it expects the following collection to exist in the named database:

* NVD CVE: `nvd_cve_vertex_collection`/`nvd_cve_edge_collection`
* NVD CPE: `nvd_cpe_vertex_collection`/`nvd_cpe_edge_collection`
* MITRE CWE: `mitre_cwe_vertex_collection`/`mitre_cwe_edge_collection`
* MITRE ATT&CK Enterprise: `mitre_attack_enterprise_vertex_collection`/`mitre_attack_enterprise_edge_collection`
* MITRE ATT&CK Mobile: `mitre_attack_mobile_vertex_collection`/`mitre_attack_mobile_edge_collection`
* MITRE ATT&CK ICS: `mitre_attack_ics_vertex_collection`/`mitre_attack_ics_edge_collection`

## A note on CPE search logic

CPE strings follow the structure:

```
cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:<edition>:<language>:<sw_edition>:<target_sw:>:<target_hw>:<other>
```

CPE strings allow for wildcards (`*`) to be used for a value, e.g.

```txt
cpe:2.3:a:microsoft:windows_live_messenger:*:*:*:*:*:*:*:*
```

For example any `version` that exists, that would match...


```txt
cpe:2.3:a:microsoft:windows_live_messenger:8.5:*:*:*:*:*:*:*
cpe:2.3:a:microsoft:windows_live_messenger:8.6:*:*:*:*:*:*:*
```

etc.

Sometimes you will also see a `-` value in the CPE string, which means no value exists for the property. For example `cpe:2.3:a:vendor:product:-:*:*:*:*:*:*:*` would mean there is a product but it is never versioned by the vendor.

## API

### Schema

To make it easy for users to get up and running, we should build the API against the OpenAPI v3 spec (https://spec.openapis.org/oas/v3.1.0). We can then use Swagger (https://swagger.io/resources/open-api/) to automatically deliver a lightweight view to allow users to interact with the API in the browser.

### Pagination

We should add an `.env` variable that allows user to set max record returned per page.

All paginated responses should contain the header;

```json
{
    "page_number": "<NUMBER>",
    "page_size": "<SET IN ENV>",
    "page_results_count": "<COUNT OF RESULTS ON PAGE>",
    "total_results_count": "<COUNT OF RESULTS ON ALL PAGES>",
```

### Endpoints

#### CVE Objects

##### POST CVEs

Will download CVEs using cloudflare

```shell
POST <HOST>/api/v1/cve/
```

* `--last_modified_earliest` (`YYYY-MM-DD`): earliest date
	* default is `1980-01-01`
* `--last_modified_latest` (`YYYY-MM-DD`): latest date
	* default is `1980-01-01`

```json
{
	"jobs": [
		{
			"job_id": "<ID>",
			"job_type": "cve-update",
			"url_parameters": "<VALUES>",
			"datetime_start": "<datetime job triggered>",
			"state": "<state>"
		}
	]
}
```

Possible errors:

* 400 - The server did not understand the request
* 401 - The client needs to authenticate
* 404 - Not found, or the client does not have access to the resource

##### GET CVEs

```shell
GET <HOST>/api/v1/cve/
```

Accepts URL parameters:

* `id` (stix id): The STIX ID(s) of the object wanted (e.g. `vulnerability--1234`)
* `cve_id` (optional): ID of CVE (e.g. `CVE-2023-22518`)
* `description` (stix description): The description if the object. Is wildcard
* `created_min` (optional, in format `YYYY-MM-DDThh:mm:ss.sssZ`): is the minumum `created` value user wants
* `created_max` (optional, in format `YYYY-MM-DDThh:mm:ss.sssZ`): is the maximum `created` value user wants
* `modified_min` (optional, in format `YYYY-MM-DDThh:mm:ss.sssZ`): is the minumum `modified` value user wants
* `modified_max` (optional, in format `YYYY-MM-DDThh:mm:ss.sssZ`): is the maximum `modified` value user wants
* `has_kev` (optional, boolean), only returns CVEs that are reported by CISA KEV
	* this essentially searches for embedded relationships between sighting (`object-refs`) and CVE Vulnerability
* `cpes_vulnerable` (optional, cpe string), only returns results for which matching CPEs are vulnerable to matching CVEs
	* this essentially searches for CPE relationships to indicator with relationship_type = `in-vulnerable`
	* note, if wildcard value used, will consider any values for property. user must pass vendor and product not as wildcard values in string. Can omit end of string (rest will be treated as wildcard values)
	* this property searches `cwe-cpe (is-vulnerable)` relationships generated by arango_cti_processor
* `cpes_in_pattern` (optional, cpe string), only returns results for which matching CPEs are found in CVE pattern
	* this essentially searches for CPE relationships to indicator with relationship_type = `in-pattern`
	* note, if wildcard value used, will consider any values for property. user must pass vendor and product not as wildcard values in string. Can omit end of string (rest will be treated as wildcard values)
	* this property searches `cwe-cpe (in-pattern)` relationships generated by arango_cti_processor
* `cvss_base_score_min` (optional, between `0`-`10`)
	* searches for minimum base scores for v2_0, v3_0, v3_1 and v4_0 Vulnerability object
* `epss_score_min` (optional, between `0`-`1` to 2 decimal places)
* `epss_percentile_min` (optional, between `0`-`1` to 2 decimal places)
* `weakness_id` (optional, cwe id): list of CWEs that are linked to CVEs
	* this property searches `cve-cwe` relationships generated by arango_cti_processor
* `attack_id` (optional, attaxk id): list of ATT&CKS that are linked to CVEs
	* note, this is not a direct relationship, this property searches relationships generated by arango_cti_processor `cve-cwe`->`cwe-capec`->`capec-attack` to produce the list of ATT&CK techniques.
* `page_size` (max is 50, default is 50)
* `page`
    * default is 0
* `sort`:
    * modified_ascending
    * modified_descending (default)
    * created_ascending
    * created_descending
    * name_ascending
    * name_descending
    * epss_score_ascending
    * epss_score_descending
    * cvss_base_score_ascending
    * cvss_base_score_descending

This endpoint only returns the vulnerability object for matching CVEs, they must query the CVE ID endpoint for full information

```json
{
	"vulnerabilities": [
		"<PRINTED STIX VULNERABILITY OBJECT 1>",
		"<PRINTED STIX VULNERABILITY OBJECT N>"
	]
}
```

Possible errors:

* 400 - The server did not understand the request
* 401 - The client needs to authenticate
* 404 - Not found, or the client does not have access to the resource

##### GET CVE

```shell
GET <HOST>/api/v1/cves/:cve_id/
```

Accepts URL parameters

* `version`: (modified time): by default the API will only return the latest version of the object. You can pass a specific version ID to return that object (e.g. `2020-10-28T12:51:29.358Z`). Get available versions from the versions endpoint.

```json
{
	"vulnerabilities": [
		"<PRINTED STIX VULNERABILITY OBJECT 1>",
	]
}
```

Possible errors:

* 400 - The server did not understand the request
* 401 - The client needs to authenticate
* 404 - Not found, or the client does not have access to the resource

##### GET CVE Object Versions

```shell
GET <HOST>/api/v1/cves/:cve_id/versions/
```

Shows the version (`modified` times) of all the CVE vulnerability objects

```json
{
	"versions": [
		"2020-10-28T12:51:29.358Z",
		"2018-01-01T00:00:00.000Z"		
	]
}
```

Possible errors:

* 401 - The client needs to authenticate
* 404 - Not found, or the client does not have access to the resource

##### GET CVE Bundle

```shell
GET <HOST>/api/v1/cves/:cve_id/bundle
```

This endpoint prints all objects that representing the vulnerability and those directly linked (Weaknesses, ATT&CK, relationships, etc)

Accepts URL parameters

* `version`: (modified time): will return a snapshot of that vulnerability and the info held about it at the specific time. Get the versions available for a CVE from the versions endpoint.

```json
{
	"objects": [
		"<STIX OBJECT 1>",
		"<STIX OBJECT N>"
	]
}
```

Possible errors:

* 400 - The server did not understand the request
* 401 - The client needs to authenticate
* 404 - Not found, or the client does not have access to the resource

---

#### CPE Objects

##### POST CPEs

Will download CPEs using cloudflare

```shell
POST <HOST>/api/v1/cpe/
```

* `--last_modified_earliest` (`YYYY-MM-DD`): earliest date
	* default is `1980-01-01`
* `--last_modified_latest` (`YYYY-MM-DD`): latest date
	* default is `1980-01-01`

```json
{
	"jobs": [
		{
			"job_id": "<ID>",
			"job_type": "cpe-update",
			"url_parameters": "<VALUES>",
			"datetime_start": "<datetime job triggered>",
			"state": "<state>"
		}
	]
}
```

Possible errors:

* 400 - The server did not understand the request
* 404 - Not found, or the client does not have access to the resource

##### GET CPEs

Note the GET objects always return the latest version of objects.

```shell
GET <HOST>/api/v1/cpe/
```

Accepts URL parameters:

* `id` (stix id): The STIX ID(s) of the object wanted (e.g. `software--1234`)
* `type` (stix type): The STIX object `type`(s) of the object wanted (e.g. `software`).
	* available options are `software`,`identity`, `marking-definition`
* `cpe_match_string` (optional): ID of CVE (e.g. `cpe:2.3:o:microsoft:windows_10`). Can use wildcards or can omit end of string (rest will be treated as wildcard values)
* `product_type` (optional, uses cpe match string 2nd part): either `application`, `hardware`, `operating-system`
* `vendor` (optional, uses cpe match string 3rd part)
* `product` (optional, uses cpe match string 4th part)
* `in_cve_pattern` (optional, list of CVE ids): only returns CPEs in a CVEs Pattern
* `cve_vulnerable` (optional, list of CVE ids): only returns CPEs vulnerable to CVE
* `page_size` (max is 50, default is 50)
* `page`
    * default is 0
* `sort`:
    * vendor_ascending
    * vendor_descending (default)
    * product_ascending
    * product_descending

```json
{
	"objects": [
		"<PRINT SOFTWARE STIX OBJECT 1>",
		"<PRINT SOFTWARE STIX OBJECT N>"
	]
}
```

Possible errors:

* 400 - The server did not understand the request
* 401 - The client needs to authenticate
* 404 - Not found, or the client does not have access to the resource

##### GET CPE

Note the GET objects always return the latest version of objects.

```shell
GET <HOST>/api/v1/cpes/:cpe_match_string
```

:cpe_match_string cannot contain wildcard. Must match an existing CPE match string in a stix object exactly.

200:

```json
{
	"objects": [
		"<PRINT SOFTWARE STIX OBJECT 1>"
	]
}
```

Possible errors:

* 401 - The client needs to authenticate
* 404 - Not found, or the client does not have access to the resource

---

#### ATT&CK Objects

##### POST ATT&CK

Will download ATT&CK Enterprise/Mobile/ICS using cloudflare

```shell
POST <HOST>/api/v1/attack-<MATRIX_NAME>/
```

Accepts URL parameters

* `--version`: the version passed to the script

```json
{
	"jobs": [
		{
			"job_id": "<ID>",
			"job_type": "attack-update",
			"url_parameters": "<VALUES>",
			"datetime_start": "<datetime job triggered>",
			"state": "<state>"
		}
	]
}
```

Possible errors:

* 400 - The server did not understand the request
* 401 - The client needs to authenticate
* 404 - Not found, or the client does not have access to the resource

##### GET ATT&CK Objects

Note the GET objects always return the latest version of objects.

```shell
GET <HOST>/api/v1/attack-<MATRIX_NAME>/
```

Does not return relationship type objects. Use the relationships endpoint for this data.

Accepts URL parameters:

* `id` (stix id): The STIX ID(s) of the object wanted (e.g. `attack-pattern--1234`)
* `type` (stix type): The STIX object `type`(s) of the object wanted (e.g. `attack-pattern`).
	* available options are `attack-pattern`, `campaign`, `course-of-action`, `identity`, `intrusion-set`, `malware`, `marking-definition`, `tool`, `x-mitre-data-component`, `x-mitre-data-source`, `x-mitre-matrix`, `x-mitre-tactic`
* `attack_id` (attack ID): The ATTACK ids of the object wanted (e.g. `T1659`)
* `name` (stix name): The name if the object. Is wildcard
* `description` (stix description): The description if the object. Is wildcard

200 will return all matching objects (hiding any arangodb internal properties starting with `_`):

```json
{
	"objects": [
		"<STIX OBJECT 1>",
		"<STIX OBJECT 2>"
	]
}
```

Possible errors:

* 400 - The server did not understand the request
* 401 - The client needs to authenticate
* 404 - Not found, or the client does not have access to the resource

##### GET ATT&CK Object

Note the GET objects always return the latest version of objects.

```shell
GET <HOST>/api/v1/attack-<MATRIX_NAME>/:stix_id
```

200:

```json
{
	"objects": [
		"<STIX OBJECT 1>"
	]
}
```

Possible errors:

* 401 - The client needs to authenticate
* 404 - Not found, or the client does not have access to the resource

---

#### CWE Objects

##### POST CWEs

Will download CWEs using cloudflare

```shell
POST <HOST>/api/v1/cwes/
```

Accepts URL parameters

* `--version`: the version passed to the script

```json
{
	"jobs": [
		{
			"job_id": "<ID>",
			"job_type": "cwe-update",
			"url_parameters": "<VALUES>",
			"datetime_start": "<datetime job triggered>",
			"state": "<state>"
		}
	]
}
```

Possible errors:

* 400 - The server did not understand the request
* 401 - The client needs to authenticate
* 404 - Not found, or the client does not have access to the resource

##### GET CWE Objects

Note the GET objects always return the latest version of objects.


```shell
GET <HOST>/api/v1/cwes/objects/
```

Does not return relationship type objects. Use the relationships endpoint for this data.

Accepts URL parameters:

* `id` (stix id): The STIX ID(s) of the object wanted (e.g. `weakness--1234`)
* `type` (stix type): The STIX object `type`(s) of the object wanted (e.g. `weakness`).
	* available options are `weakness`, `grouping`, `identity`, `marking-definition`, `extension-definition`
* `cwe_id` (cwe ID): The CAPEC ids of the object wanted (e.g. `CWE-242`)
* `name` (stix name): The name if the object. Is wildcard
* `description` (stix description): The description if the object. Is wildcard

200 will return all matching objects (hiding any arangodb internal properties starting with `_`):

```json
{
	"objects": [
		"<STIX OBJECT 1>",
		"<STIX OBJECT 2>"
	]
}
```

Possible errors:

* 400 - The server did not understand the request
* 401 - The client needs to authenticate
* 404 - Not found, or the client does not have access to the resource

##### GET CWE Object

Note the GET objects always return the latest version of objects.


```shell
GET <HOST>/api/v1/cwes/objects/:stix_id/
```

200:

```json
{
	"objects": [
		"<STIX OBJECT 1>"
	]
}
```

Possible errors:

* 401 - The client needs to authenticate
* 404 - Not found, or the client does not have access to the resource


---

#### CAPEC Objects

##### POST CAPECs

Will download CAPECS using cloudflare

```shell
POST <HOST>/api/v1/capecs/
```

Accepts URL parameters

* `--version`: the version passed to the script

```json
{
	"jobs": [
		{
			"job_id": "<ID>",
			"job_type": "capec-update",
			"url_parameters": "<VALUES>",
			"datetime_start": "<datetime job triggered>",
			"state": "<state>"
		}
	]
}
```

Possible errors:

* 400 - The server did not understand the request
* 401 - The client needs to authenticate
* 404 - Not found, or the client does not have access to the resource

##### GET CAPEC Objects

Note the GET objects always return the latest version of objects.

```shell
GET <HOST>/api/v1/capecsafc/objects/
```

Does not return relationship type objects. Use the relationships endpoint for this data.

Accepts URL parameters:

* `id` (stix id): The STIX ID(s) of the object wanted (e.g. `attack-pattern--1234`)
* `type` (stix type): The STIX object `type`(s) of the object wanted (e.g. `attack-pattern`).
	* available options are `attack-pattern`, `course-of-action`, `identity`, `marking-definition`
* `capec_id` (capec ID): The CAPEC ids of the object wanted (e.g. `CAPEC-112`)
* `name` (stix name): The name if the object. Is wildcard
* `description` (stix description): The description if the object. Is wildcard

200 will return all matching objects (hiding any arangodb internal properties starting with `_`):

```json
{
	"objects": [
		"<STIX OBJECT 1>",
		"<STIX OBJECT 2>"
	]
}
```

Possible errors:

* 400 - The server did not understand the request
* 401 - The client needs to authenticate
* 404 - Not found, or the client does not have access to the resource

##### GET CAPEC Object

Note the GET objects always return the latest version of objects.

```shell
GET <HOST>/api/v1/capecs/objects/:stix_id/
```

200:

```json
{
	"objects": [
		"<STIX OBJECT 1>"
	]
}
```

Possible errors:

* 401 - The client needs to authenticate
* 404 - Not found, or the client does not have access to the resource

---

#### arango_cti_processor

These endpoints will trigger the relevant arango_cti_processor mode to generate relationships.

Each request generates a job.

##### Run `cwe-capec`

```shell
POST <HOST>/api/v1/arango_cti_processor/cwe-capec
```

```json
{
	"jobs": [
		{
			"job_id": "<ID>",
			"job_type": "arango_cti_processor-cve-cpe",
			"url_parameters": "<VALUES>",
			"datetime_start": "<datetime job triggered>",
			"state": "<state>"
		}
	]
}
```

Possible errors:

* 401 - The client needs to authenticate
* 404 - Not found, or the client does not have access to the resource

##### Run `capec-attack`

```shell
POST <HOST>/api/v1/arango_cti_processor/capec-attack
```

```json
{
	"jobs": [
		{
			"job_id": "<ID>",
			"job_type": "arango_cti_processor-cve-cpe",
			"url_parameters": "<VALUES>",
			"datetime_start": "<datetime job triggered>",
			"state": "<state>"
		}
	]
}
```

Possible errors:

* 401 - The client needs to authenticate
* 404 - Not found, or the client does not have access to the resource

##### Run `cve-epss`

```shell
POST <HOST>/api/v1/arango_cti_processor/cve-epss
```

URL parameters;

* `--created_min` (`YYYY-MM-DD`): will only update objects with a `created` time >= to date passed
	* default is `1980-01-01`
* `--modified_min` (`YYYY-MM-DD`): will only update objects with a `modified` time >= to date passed
	* default is `1980-01-01`

```json
{
	"jobs": [
		{
			"job_id": "<ID>",
			"job_type": "arango_cti_processor-cve-epss",
			"url_parameters": "<VALUES>",
			"datetime_start": "<datetime job triggered>",
			"state": "<state>"
		}
	]
}
```

Possible errors:

* 401 - The client needs to authenticate
* 404 - Not found, or the client does not have access to the resource

##### Run `cve-cpe`

```shell
POST <HOST>/api/v1/arango_cti_processor/cve-cpe
```

URL parameters;

* `--created_min` (`YYYY-MM-DD`): will only update objects with a `created` time >= to date passed
	* default is `1980-01-01`
* `--modified_min` (`YYYY-MM-DD`): will only update objects with a `modified` time >= to date passed
	* default is `1980-01-01`

```json
{
	"jobs": [
		{
			"job_id": "<ID>",
			"job_type": "arango_cti_processor-cve-cpe",
			"url_parameters": "<VALUES>",
			"datetime_start": "<datetime job triggered>",
			"state": "<state>"
		}
	]
}
```

Possible errors:

* 400 - The server did not understand the request
* 404 - Not found, or the client does not have access to the resource

##### Run `cve-cwe`

```shell
POST <HOST>/api/v1/arango_cti_processor/cve-cwe
```

URL parameters;

* `--created_min` (`YYYY-MM-DD`): will only update objects with a `created` time >= to date passed
	* default is `1980-01-01`
* `--modified_min` (`YYYY-MM-DD`): will only update objects with a `modified` time >= to date passed
	* default is `1980-01-01`

A 201 response returns the job id and job

```json
{
	"jobs": [
		{
			"job_id": "<ID>",
			"job_type": "arango_cti_processor-cve-cwe",
			"url_parameters": "<VALUES>",
			"datetime_start": "<datetime job triggered>",
			"state": "<state>"
		}
	]
}
```

Possible errors:

* 401 - The client needs to authenticate
* 404 - Not found, or the client does not have access to the resource

### Jobs

##### Get Jobs

```shell
POST <HOST>/api/v1/jobs
```

Url parameters

* `sort`:
    * datestime_start_ascending
    * datestime_start_descending (default)
* `page_size` (max is 50, default is 50)
* `page`
    * default is 0

Shows job info

```json
{
  "page_size": 50,
  "page_number": 3,
  "page_results_count": 50,
  "total_results_count": 2500,
	"jobs": [
		{
			"job_id": "<ID>",
			"job_type": "arango_cti_processor-cve-epss",
			"url_parameters": "<VALUES>",
			"datetime_start": "<datetime job triggered>",
			"state": "<state>"
		}
	]
}
```

Possible errors:

* 400 - The server did not understand the request
* 401 - The client needs to authenticate
* 404 - Not found, or the client does not have access to the resource

##### Get Job ID

```shell
POST <HOST>/api/v1/arango_cti_processor/jobs/:job_id
```

```json
{
	"jobs": [
		{
			"job_id": "<ID>",
			"job_type": "arango_cti_processor-cve-epss",
			"url_parameters": "<VALUES>",
			"datetime_start": "<datetime job triggered>",
			"state": "<state>"
		}
	]
}
```

Possible errors:

* 401 - The client needs to authenticate
* 404 - Not found, or the client does not have access to the resource