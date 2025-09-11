from datetime import date, timedelta
from enum import StrEnum, auto
from .models import Job
from rest_framework import serializers, validators

from vulmatch.server import models


ACP_MODES = {
    "cve-epss": "Add EPSS Report(s) for CVE objects",
    "cve-kev": "Add KEV Report(s) for CVE objects",
    "cve-vulncheck-kev": "Add KEV Report(s) for CVE objects",
    ###
    "cve-cwe": "Relate CVE objects to CWE objects",
    "cve-capec": "Relate CWE objects to CAPEC objects",
    "cve-attack": "Relate CAPEC objects to ATT&CK objects",
    "cve-epss-backfill": "Relate CAPEC objects to ATT&CK objects",
    "cpematch": "Relate CAPEC objects to ATT&CK objects",
}

class StixObjectsSerializer(serializers.Serializer):
    type = serializers.CharField()
    id = serializers.CharField()

class JobSerializer(serializers.ModelSerializer):
    class Meta:
        model = Job
        fields = '__all__'

class NVDTaskSerializer(serializers.Serializer):
    last_modified_earliest = serializers.DateField(help_text="(`YYYY-MM-DD`): earliest date")
    last_modified_latest = serializers.DateField(help_text="(`YYYY-MM-DD`): latest date")
    ignore_embedded_relationships = serializers.BooleanField(default=True)
    ignore_embedded_relationships_sro = serializers.BooleanField(default=True)
    ignore_embedded_relationships_smo = serializers.BooleanField(default=True)

    def validate(self, attrs):
        min_date: date = attrs['last_modified_earliest']
        max_date: date = attrs['last_modified_latest']
        if min_date > max_date:
            raise serializers.ValidationError(f'last_modified_earliest cannot be greater than last_modified_latest')
        time_difference = max_date - min_date
        if time_difference > timedelta(31):
            raise serializers.ValidationError(f'a maximum of 31 days difference allowed, last_modified_latest - last_modified_earliest = {time_difference.days} days')
        return super().validate(attrs)

class StixVersionsSerializer(serializers.Serializer):
    latest = serializers.DateTimeField(required=False, allow_null=True)
    versions = serializers.ListField(child=serializers.DateTimeField())

class VendorSerializer(serializers.Serializer):
    vendor = serializers.CharField()
    products_count  = serializers.IntegerField()
    softwares_count = serializers.IntegerField()

class ProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Products
        exclude = ['id']


class ACPSerializer(serializers.Serializer):
    mode = serializers.HiddenField(default=None)
    ignore_embedded_relationships = serializers.BooleanField(default=False)
    ignore_embedded_relationships_sro = serializers.BooleanField(default=True)
    ignore_embedded_relationships_smo = serializers.BooleanField(default=True)
    
    def validate(self, attrs):
        mode = self.context['request'].path.rstrip('/').split('/')[-1]
        if mode not in ACP_MODES:
            raise validators.ValidationError({"mode": f"This mode `{mode}` is not supported."})
        attrs['mode'] = mode
        return super().validate(attrs)

class ACPSerializerGeneral(ACPSerializer):
    modified_min = serializers.DateTimeField(required=False)
    created_min = serializers.DateTimeField(required=False)

class AcpCPEMatch(ACPSerializer):
    modified_min = serializers.DateTimeField(required=False)

class AcpEPSSBackfill(ACPSerializer):
    start_date = serializers.DateField()
    end_date = serializers.DateField()
    

class HealthCheckChoices(StrEnum):
    AUTHORIZED = auto()
    UNAUTHORIZED = auto()
    UNSUPPORTED = auto()
    NOT_CONFIGURED = "not-configured"
    UNKNOWN = auto()
    OFFLINE = auto()

class HealthCheckSerializer(serializers.Serializer):
    ctibutler = serializers.ChoiceField(choices=[m.value for m in HealthCheckChoices])
    vulncheck = serializers.ChoiceField(choices=[m.value for m in HealthCheckChoices])