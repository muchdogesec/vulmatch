# Tests

## Environment setup

```shell
python3 -m venv vulmatch-venv && \
source vulmatch-venv/bin/activate && \
pip3 install -r requirements.txt
````

You also need to download and install ACT:

https://github.com/nektos/act

## API schema tests

These tests are run via Github actions.

```shell
st run --checks all http://127.0.0.1:8005/api/schema --generation-allow-x00 true
```

## Functional tests

These tests are run via Github actions.

You must create a `.env` file with the following secrets (on Github they are stored in an environment called `vulmatch_tests`);

```txt
CTIBUTLER_BASE_URL=http://api.ctibutler.com
CTIBUTLER_API_KEY=YouR-CtibUTLer_Key
```

You can then execute these tests as follows;

```shell
act -W .github/workflows/schemathesis_test.yml --secret-file secrets.env
```
