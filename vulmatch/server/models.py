from datetime import datetime, timezone
import uuid
from django.db import models
from django.contrib.postgres.fields import ArrayField

# Create your models here.

class JobState(models.TextChoices):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
class JobType(models.TextChoices):
    CVE_UPDATE    = "cve-update"
    CVE_PROCESSOR = "arango-cve-processor"

class Job(models.Model):
    # file = models.OneToOneField(File, on_delete=models.CASCADE)
    id = models.UUIDField(default=uuid.uuid4, primary_key=True)
    type = models.CharField(max_length=64, choices=JobType.choices)
    state = models.CharField(choices=JobState.choices, max_length=20, default=JobState.PENDING)
    errors = ArrayField(base_field=models.CharField(max_length=1024), null=True, default=list)
    run_datetime = models.DateTimeField(auto_now_add=True)
    completion_time = models.DateTimeField(null=True, default=None)
    parameters = models.JSONField()

    def save(self, *args, **kwargs) -> None:
        if not self.completion_time and self.state in [JobState.COMPLETED, JobState.FAILED]:
            self.completion_time = datetime.now(timezone.utc)
        return super().save(*args, **kwargs)
    