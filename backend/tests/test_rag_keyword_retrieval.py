from datetime import datetime

from db.database import SessionLocal
from db.models import CveKnowledgeModel
from services.rag_service import build_grounded_response, keyword_retrieve


def test_keyword_retrieval_returns_knowledge_rows(client):
    db = SessionLocal()
    try:
        db.add(
            CveKnowledgeModel(
                cve_id="CVE-2024-9999",
                source="nvd",
                summary="Test CVE summary for retrieval",
                vector_text="test retrieval vector",
                embedding=[],
                metadata_json={"origin": "test"},
                created_at=datetime.utcnow(),
            )
        )
        db.commit()
        docs = keyword_retrieve(db, "CVE-2024-9999")
    finally:
        db.close()

    assert docs
    assert docs[0]["cve_id"] == "CVE-2024-9999"


def test_grounded_response_uses_docs_when_present():
    response, citations = build_grounded_response(
        "query",
        [{"source": "nvd", "cve_id": "CVE-2024-1234", "summary": "Sample", "metadata": {}}],
    )
    assert "grounded" in response.lower()
    assert citations
