from .models import Job
from rest_framework import serializers, validators


ACP_MODES = {
    "cve-cpe": "Relate CVE objects to CPE objects",
    "cve-epss": "Add EPSS Note(s) for CVE objects",
    ###
    "cve-cwe": "Relate CVE objects to CWE objects",
    "cwe-capec": "Relate CWE objects to CAPEC objects",
    "capec-attack": "Relate CAPEC objects to ATT&CK objects",
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
    ignore_embedded_relationships = serializers.BooleanField(default=False)

    def validate(self, attrs):
        if attrs.get('last_modified_earliest') and attrs.get('last_modified_latest') and attrs['last_modified_earliest'] > attrs['last_modified_latest']:
            raise serializers.ValidationError(f'last_modified_earliest cannot be greater than last_modified_latest')
        return super().validate(attrs)

class MitreTaskSerializer(serializers.Serializer):
    version = serializers.CharField(help_text="mitre version passed to the script")
    ignore_embedded_relationships = serializers.BooleanField(default=False)

class MitreVersionsSerializer(serializers.Serializer):
    latest = serializers.CharField(required=False, allow_null=True)
    versions = serializers.ListField(child=serializers.CharField())

class StixVersionsSerializer(serializers.Serializer):
    latest = serializers.DateTimeField(required=False, allow_null=True)
    versions = serializers.ListField(child=serializers.DateTimeField())

class MitreObjectVersions(serializers.Serializer):
    modified = serializers.DateTimeField(required=False, allow_null=True)
    notes = serializers.ListField(child=serializers.CharField())


class ACPSerializer(serializers.Serializer):
    ignore_embedded_relationships = serializers.BooleanField(default=False)
    modified_min = serializers.DateTimeField(required=False)
    created_min = serializers.DateTimeField(required=False)

class ACPSerializerWithMode(ACPSerializer):
    mode = serializers.ChoiceField(choices=list(ACP_MODES.items()))
