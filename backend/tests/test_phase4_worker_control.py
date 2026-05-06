from services.worker_control import can_execute_scan


def test_can_execute_scan_blocks_terminal_statuses():
    assert can_execute_scan("queued") is True
    assert can_execute_scan("running") is True
    assert can_execute_scan("complete") is False
    assert can_execute_scan("failed") is False
    assert can_execute_scan("cancelled") is False
