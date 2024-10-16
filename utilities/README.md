# Vulmatch Utilities

Run these to backfill Vulmatch with data.


## Enrichment backfill

### CPE

Generally very old CPEs are no longer observed, but that does not mean that recent CVEs will reference them.

To be safe backfill all CPEs (beware, this is over 1 million records).

If you want, you can also specify an earliest CPE date in the script below. Be aware though, if CVEs reference CPEs you havent imported (because they have a modified time earlier than that specified) you will miss the CVE -> CPE joins.

### ATT&CK Enterprise

Import all available versions (recommended)

```shell
python3 import_attack_enterprise_archive.py
```

Import specific versions

```shell
python3 import_attack_enterprise_archive.py 1.0 14.1 15.0 15.1
```

### ATT&CK ICS

Import all available versions (recommended)

```shell
python3 import_attack_ics_archive.py
```

Import specific versions

```shell
python3 import_attack_ics_archive.py 14.1 15.0 15.1
```

### ATT&CK Mobile

Import all available versions (recommended)

```shell
python3 import_attack_mobile_archive.py
```

Import specific versions

```shell
python3 import_attack_mobile_archive.py 15.1 11.1-beta
```

### CWE

Import all available versions (recommended)

```shell
python3 import_cwe_archive.py
```

Import specific versions

```shell
python3 import_cwe_archive.py 4.14 4.15
```

### CAPEC

Import all available versions (recommended)

```shell
python3 import_capec_archive.py
```

Import specific versions

```shell
python3 import_capec_archive.py 3.8 3.9
```
