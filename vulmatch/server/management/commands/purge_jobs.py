from datetime import timedelta
import itertools
from django.core.management.base import BaseCommand
from django.utils import timezone
from django.db import transaction
from vulmatch.server import models


class Command(BaseCommand):
    help = "Atomically purge all old jobs older than --days (defaults to 30)."

    def add_arguments(self, parser):
        parser.add_argument(
            "--days",
            type=int,
            default=30,
            help="Purge jobs older than this number of days. Defaults to 30.",
        )

    def handle(self, *args, **options):
        days = options["days"]
        cutoff = timezone.now() - timedelta(days=days)

        # Identify vulmatch jobs older than the cutoff
        jobs_qs = models.Job.objects.filter(run_datetime__lt=cutoff)
        count = jobs_qs.count()

        if count == 0:
            self.stdout.write(
                self.style.SUCCESS(
                    f"No jobs older than {days} days found (cutoff: {cutoff})."
                )
            )
            return

        self.stdout.write(
            self.style.WARNING(
                f"Found {count} jobs older than {days} days. Starting purge..."
            )
        )
        with transaction.atomic():
            _, counts2 = jobs_qs.delete()
            total_removed = 0
            all_keys = set(itertools.chain(counts2.keys()))
            for key in sorted(all_keys):
                deleted_count = counts2.get(key, 0)
                self.stdout.write(
                    f"  - {key}: " + self.style.SUCCESS(str(deleted_count))
                )
                total_removed += deleted_count
        self.stdout.write(
            self.style.SUCCESS("Successfully purged ")
            + self.style.WARNING(total_removed)
            + self.style.SUCCESS(" total records across all related models.")
        )