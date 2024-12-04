# Tests

## Setup

```shell
python3 -m venv vulmatch-venv
source vulmatch-venv/bin/activate
# install requirements
pip3 install -r requirements.txt
````


## API schema tests

```shell
st run --checks all http://127.0.0.1:8005/api/schema --generation-allow-x00 true
```



## Run tests

```shell
python3 tests/import_knowledge_base_test_data.py
```