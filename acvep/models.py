from django.db import models
from arango_cve_processor.tools.epss import EPSSManager
import datetime
from vulmatch.server.apps import ServerConfig


class EPSSScore(models.Model):
    id = models.CharField(max_length=50, primary_key=True)
    cve = models.CharField(max_length=20)
    score = models.FloatField()
    percentile = models.FloatField()
    date = models.DateField()

    class Meta:
        unique_together = (("cve", "date"),)
        app_label = ServerConfig.label
        ordering = ["cve", "-date"]

    def __str__(self):
        return f"EPSS({self.cve}, score={self.score}, percentile={self.percentile}, date={self.date})"

    @staticmethod
    def _sync_for_date(date):
        if EPSSScore.objects.filter(date=date).exists():
            return
        manager = EPSSManager()
        data = manager.get_epss_data(date)

        objs = [
            EPSSScore(
                id=f"{cve}+{item['date']}",
                cve=cve,
                score=item["epss"],
                percentile=item["percentile"],
                date=date,
            )
            for cve, item in data.items()
        ]
        EPSSScore.objects.bulk_create(objs, ignore_conflicts=True, batch_size=5000)

    @staticmethod
    def get_for_date(date=None):
        date = date or EPSSScore.datenow()
        if not EPSSScore.objects.filter(date=date).exists():
            EPSSScore._sync_for_date(date)
        return EPSSScore.objects.filter(date=date)

    @classmethod
    def get_latest_date(cls):
        latest = cls.objects.order_by("-date").first()
        if latest:
            return latest.date
        return None

    @classmethod
    def datenow(cls):
        return EPSSManager.datenow()

    def dict(self):
        return {
            "epss": self.score,
            "percentile": self.percentile,
            "date": self.date.strftime("%Y-%m-%d"),
        }
