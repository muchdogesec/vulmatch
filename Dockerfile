FROM python:3.11
ENV PYTHONUNBUFFERED=1
WORKDIR /usr/src/app
COPY requirements.txt ./
RUN pip install -r requirements.txt

# COPY arango_cve_processor-0.0.1-py3-none-any.whl .
# RUN pip install --no-deps --force-reinstall arango_cve_processor-0.0.1-py3-none-any.whl