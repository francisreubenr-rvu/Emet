from __future__ import annotations

import json
import os
from typing import List

import google.generativeai as genai

from normalizer.unified_schema import UnifiedFinding


SYSTEM_PROMPT = """
You are EMET's threat intelligence AI. You analyze vulnerability scan results
and produce clear, accurate security assessments. You ONLY report findings
that are supported by the provided context and verified data sources.
Never hallucinate CVE IDs, CVSS scores, or remediation steps.
If uncertain, say so explicitly with confidence percentage.
Always cross-reference against the provided RAG context before responding.
""".strip()


def _configure() -> None:
    key = (os.getenv("GEMINI_API_KEY") or "").strip()
    if not key:
        return
    genai.configure(api_key=key)


def _has_valid_key() -> bool:
    key = (os.getenv("GEMINI_API_KEY") or "").strip()
    if not key:
        return False
    lowered = key.lower()
    if lowered.startswith("your-") or lowered in {"changeme", "change-me", "replace-me"}:
        return False
    return True


def _fallback(findings: List[UnifiedFinding], mode: str, reason: str) -> dict:
    return {
        "mode": mode,
        "executive_summary": f"AI analysis unavailable ({reason}).",
        "key_findings": [f.title for f in findings[:5]],
        "zero_day_risk_assessment": "Insufficient external intelligence context.",
        "recommended_actions": [
            "Validate scanner evidence manually.",
            "Configure a valid Gemini API key to enable model-backed summarization.",
        ],
        "confidence": 22,
    }


async def analyze_findings(
    findings: List[UnifiedFinding],
    rag_context: str,
    mode: str = "unified",
) -> dict:
    if not _has_valid_key():
        return _fallback(findings, mode, "GEMINI_API_KEY missing or placeholder")

    try:
        _configure()
        model = genai.GenerativeModel("gemini-1.5-flash")
        payload = {
            "mode": mode,
            "findings": [item.model_dump(mode="json") for item in findings],
            "rag_context": rag_context,
            "output_contract": {
                "executive_summary": "string",
                "key_findings": ["string"],
                "zero_day_risk_assessment": "string",
                "recommended_actions": ["string"],
                "confidence": "number 0-100",
            },
        }

        response = await model.generate_content_async(
            f"{SYSTEM_PROMPT}\n\nReturn strict JSON only:\n{json.dumps(payload)}"
        )
        text = (response.text or "{}").strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {
                "mode": mode,
                "executive_summary": text[:800],
                "key_findings": ["Response parsing fallback used."],
                "zero_day_risk_assessment": "Could not parse structured model output.",
                "recommended_actions": ["Review model output formatting and retry."],
                "confidence": 40,
            }
    except Exception as exc:
        return _fallback(findings, mode, f"Gemini call failed: {str(exc)[:120]}")
