from services.queueing import dead_letter_queue_name, queue_name_for_profile, worker_queue_list


def test_queue_name_for_profile_partitioning():
    assert queue_name_for_profile("quick") == "scan-jobs:quick"
    assert queue_name_for_profile("standard") == "scan-jobs:standard"
    assert queue_name_for_profile("deep") == "scan-jobs:deep"


def test_dead_letter_and_worker_queue_registry():
    assert dead_letter_queue_name() == "scan-jobs:dead"
    assert worker_queue_list() == ["scan-jobs:deep", "scan-jobs:standard", "scan-jobs:quick"]
