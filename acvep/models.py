import logging
from django.db import models
from acvep.tools.epss import EPSSManager
import datetime
from vulmatch.server.apps import ServerConfig
import concurrent.futures


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
    def _sync_for_dates(*dates):

        dates = {d for d in dates if not EPSSScore.objects.filter(date=d).exists()}

        def sync_task(date: datetime.date):
            logging.info(f"Syncing CVE <-> EPSS Backfill for date: {date.isoformat()}")
            logging.info("================================")
            data = EPSSManager.get_epss_date(date)
            return (
                date,
                [
                    dict(
                        id=f"{cve}+{item['date']}",
                        cve=cve,
                        score=item["epss"],
                        percentile=item["percentile"],
                        date=date,
                    )
                    for cve, item in data.items()
                ],
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(sync_task, d) for d in dates]
            for future in concurrent.futures.as_completed(futures):
                date, objs = future.result()
                logging.info(
                    f"Creating {len(objs)} EPSSScore entries for date: {date.isoformat()}"
                )
                objs = [EPSSScore(**obj) for obj in objs]
                if objs:
                    EPSSScore.objects.bulk_create(
                        objs, ignore_conflicts=True, batch_size=30_000
                    )

    @staticmethod
    def get_for_date(date=None):
        date = date or EPSSScore.datenow()
        if not EPSSScore.objects.filter(date=date).exists():
            EPSSScore._sync_for_dates(date)
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
