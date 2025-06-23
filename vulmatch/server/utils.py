from rest_framework import serializers


class ErrorSerializer(serializers.Serializer):
    message = serializers.CharField(required=True)
    code    = serializers.IntegerField(required=True)
    details = serializers.DictField(required=False)
