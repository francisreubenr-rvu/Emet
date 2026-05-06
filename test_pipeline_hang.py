import asyncio
from normalizer.unified_schema import UnifiedFinding
from services.enrichment import enrich_findings
from ai.rag_pipeline import run_rag_pipeline
from ai.gemini_client import analyze_findings
from ai.zero_day_detector import detect_zero_day_risk
from ai.self_audit import run_self_audit

async def test_pipeline_funcs():
    print("Creating findings...")
    findings = [UnifiedFinding(scan_id="test", target="https://test", title="Test", description="Desc", scanner_source="test", affected_component="test") for _ in range(45)]
    
    print("Testing enrich_findings...")
    findings = await enrich_findings(findings)
    print("Done enrich_findings")
    
    print("Testing run_rag_pipeline...")
    rag = await run_rag_pipeline(findings)
    print("Done run_rag_pipeline")
    
    print("Testing analyze_findings...")
    unified = await analyze_findings(findings, rag_context=rag["context"], mode="unified")
    print("Done analyze_findings")
    
    print("Testing detect_zero_day_risk...")
    zero_day = await detect_zero_day_risk(findings, "https://test")
    print("Done detect_zero_day_risk")
    
    print("Testing run_self_audit...")
    self_audit = await run_self_audit(findings)
    print("Done run_self_audit")

if __name__ == "__main__":
    asyncio.run(test_pipeline_funcs())