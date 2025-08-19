from enum import StrEnum, auto
from .models import Job
from rest_framework import serializers, validators


ACP_MODES = {
    "cve-epss": "Add EPSS Report(s) for CVE objects",
    "cve-kev": "Add KEV Report(s) for CVE objects",
    "cve-vulncheck-kev": "Add KEV Report(s) for CVE objects",
    ###
    "cve-cwe": "Relate CVE objects to CWE objects",
    "cve-capec": "Relate CWE objects to CAPEC objects",
    "cve-attack": "Relate CAPEC objects to ATT&CK objects",
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
    last_modified_latest = serializers.DateField(help_text="(`YYYY-MM-DD`): latest date \n* default is `1980-01-01`")
    ignore_embedded_relationships = serializers.BooleanField(default=True)
    ignore_embedded_relationships_sro = serializers.BooleanField(default=True)
    ignore_embedded_relationships_smo = serializers.BooleanField(default=True)

    def validate(self, attrs):
        if attrs.get('last_modified_earliest') and attrs.get('last_modified_latest') and attrs['last_modified_earliest'] > attrs['last_modified_latest']:
            raise serializers.ValidationError(f'last_modified_earliest cannot be greater than last_modified_latest')
        return super().validate(attrs)

class StixVersionsSerializer(serializers.Serializer):
    latest = serializers.DateTimeField(required=False, allow_null=True)
    versions = serializers.ListField(child=serializers.DateTimeField())


class ACPSerializer(serializers.Serializer):
    ignore_embedded_relationships = serializers.BooleanField(default=False)
    ignore_embedded_relationships_sro = serializers.BooleanField(default=True)
    ignore_embedded_relationships_smo = serializers.BooleanField(default=True)
    modified_min = serializers.DateTimeField(required=False)
    created_min = serializers.DateTimeField(required=False)

class ACPSerializerWithMode(ACPSerializer):
    mode = serializers.ChoiceField(choices=list(ACP_MODES.items()))

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