from datetime import UTC, date, datetime, timedelta
from acvep.tools.epss import EPSSManager


def test_datenow():
    d = EPSSManager.datenow()
    assert isinstance(d, date)
    today = datetime.now(UTC).date()
    yesterday = today - timedelta(days=1)
    assert d == today or d == yesterday
