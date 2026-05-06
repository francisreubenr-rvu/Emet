from __future__ import annotations

from datetime import datetime


def estimate_queue_oldest_age_seconds(*, queue_items: list[str]) -> int:
    now = datetime.utcnow()
    ages: list[int] = []
    for item in queue_items:
        try:
            import json

            payload = json.loads(item)
            stamp = payload.get("enqueued_at")
            if not stamp:
                continue
            then = datetime.fromisoformat(str(stamp))
            age = int((now - then).total_seconds())
            if age >= 0:
                ages.append(age)
        except Exception:
            continue
    return max(ages) if ages else 0


def queue_name_for_profile(profile: str) -> str:
    mode = (profile or "standard").strip().lower()
    if mode == "quick":
        return "scan-jobs:quick"
    if mode == "deep":
        return "scan-jobs:deep"
    return "scan-jobs:standard"


def dead_letter_queue_name() -> str:
    return "scan-jobs:dead"


def worker_queue_list() -> list[str]:
    # Priority order: deep -> standard -> quick
    return ["scan-jobs:deep", "scan-jobs:standard", "scan-jobs:quick"]
