from __future__ import annotations

import argparse
import json
from pathlib import Path

from db.database import SessionLocal
from services.knowledge_ingest import ingest_nvd_payload


def ingest_file(path: Path) -> int:
    payload = json.loads(path.read_text(encoding="utf-8"))

    db = SessionLocal()
    try:
        result = ingest_nvd_payload(db, payload, origin=str(path))
    finally:
        db.close()

    return int(result.get("inserted", 0))


def main() -> None:
    parser = argparse.ArgumentParser(description="Ingest NVD CVE JSON into EMET cve_knowledge table")
    parser.add_argument("--input", required=True, help="Path to NVD JSON file")
    args = parser.parse_args()

    path = Path(args.input)
    if not path.exists():
        raise SystemExit(f"Input file not found: {path}")

    inserted = ingest_file(path)
    print(f"Ingest completed. Inserted records: {inserted}")


if __name__ == "__main__":
    main()
