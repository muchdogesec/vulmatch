from datetime import datetime, timezone
import uuid
from django.db import models
from django.contrib.postgres.fields import ArrayField

# Create your models here.

class JobState(models.TextChoices):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
class JobType(models.TextChoices):
    ATTACK_UPDATE = "attack-update"
    CWE_UPDATE    = "cwe-update"
    CAPEC_UPDATE  = "capec-update"
    CVE_UPDATE    = "cve-update"
    CPE_UPDATE    = "cpe-update"
    CTI_PROCESSOR = "arango-cti-processor"

class Job(models.Model):
    # file = models.OneToOneField(File, on_delete=models.CASCADE)
    id = models.UUIDField(default=uuid.uuid4, primary_key=True)
    type = models.CharField(max_length=64, choices=JobType.choices)
    state = models.CharField(choices=JobState.choices, max_length=20, default=JobState.PENDING)
    # error = models.CharField(max_length=65536, null=True)
    errors = ArrayField(base_field=models.CharField(max_length=1024), null=True, default=list)
    run_datetime = models.DateTimeField(auto_now_add=True)
    completion_time = models.DateTimeField(null=True, default=None)
    parameters = models.JSONField()

    def save(self, *args, **kwargs) -> None:
        if not self.completion_time and self.state == JobState.COMPLETED:
            self.completion_time = datetime.now(timezone.utc)
        return super().save(*args, **kwargs)
    