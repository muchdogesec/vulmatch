from datetime import date
from unittest.mock import MagicMock, patch
from acvep.managers.cve_epss import (
    CveEpssManager,
)

def test_epss_cuts_off_date():
    acp_processor = MagicMock()
    manager = CveEpssManager(acp_processor, start_date=date(2025, 1, 1), end_date=date(2025, 5, 10))
    assert manager.end_date == date(2025, 5, 10)
    assert manager.start_date == date(2025, 1, 1)

    datenow_mock_value = date(2025, 9, 9)
    with patch('acvep.tools.epss.EPSSManager.datenow', return_value=datenow_mock_value):
        manager = CveEpssManager(acp_processor, start_date=date(2025, 1, 1), end_date=date(2025, 10, 10))
        assert manager.end_date == datenow_mock_value, "should be cut off at datenow"
        assert manager.start_date == date(2025, 1, 1)

        manager = CveEpssManager(acp_processor, start_date=date(2025, 1, 1), end_date=date(2025, 3, 10))
        assert manager.end_date == date(2025, 3, 10), "should not be cut off"
        assert manager.start_date == date(2025, 1, 1)
