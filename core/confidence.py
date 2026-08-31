import logging
from typing import List, Dict, Any, Tuple, Optional

logger = logging.getLogger(__name__)

# Base source reliability ratings (Spec Section 15)
DEFAULT_SOURCE_RELIABILITY: Dict[str, float] = {
    "official_website": 1.00,
    "corporate_document": 0.95,
    "direct_profile": 0.90,
    "public_repository": 0.85,
    "conference_profile": 0.80,
    "network_probe": 0.95,        # Direct DNS/Port scan response
    "nmap": 0.95,
    "dns": 1.00,
    "whois": 0.95,
    "search_engine_snippet": 0.60,
    "unverified_directory": 0.40,
    "third_party_aggregator": 0.50,
    "unknown": 0.50,
}


def get_source_reliability(source_name: str) -> float:
    """Returns reliability weight for a given source key, defaulting to 0.60."""
    key = source_name.lower().strip()
    return DEFAULT_SOURCE_RELIABILITY.get(key, 0.60)


def calculate_confidence(
    sources: List[str],
    evidence_strength: float = 1.0,
    contradiction_count: int = 0,
    is_fresh: bool = True,
) -> Tuple[float, Dict[str, Any]]:
    """
    Computes an explainable confidence score per Spec Sections 15 & 32:
      confidence = (source_reliability * evidence_strength * corroboration_multiplier * freshness) - contradiction_penalty

    Returns:
        (confidence_score: float (0.0 to 1.0), explanation: Dict[str, Any])
    """
    if not sources:
        return 0.20, {
            "score": 0.20,
            "level": "low",
            "reason": "No verifiable evidence sources cited.",
            "source_reliability": 0.20,
            "corroboration_count": 0,
            "contradiction_count": contradiction_count,
        }

    # 1. Base reliability: average of unique source reliabilities
    unique_sources = list(set(sources))
    reliabilities = [get_source_reliability(s) for s in unique_sources]
    base_reliability = sum(reliabilities) / len(reliabilities)

    # 2. Corroboration boost for multiple independent corroborating sensors
    corroboration_count = len(unique_sources)
    corroboration_boost = 0.0
    if corroboration_count > 1:
        # Diminishing boost: +0.07 for 2nd source, +0.05 for 3rd, +0.03 for 4th
        corroboration_boost = min(0.18, (corroboration_count - 1) * 0.06)

    # 3. Freshness factor
    freshness_factor = 1.0 if is_fresh else 0.88

    # 4. Raw positive score
    positive_score = (base_reliability + corroboration_boost) * min(max(evidence_strength, 0.1), 1.0) * freshness_factor

    # 5. Contradiction penalty
    contradiction_penalty = contradiction_count * 0.35
    final_score = max(0.05, min(1.0, positive_score - contradiction_penalty))
    final_score = round(final_score, 2)

    # 6. Qualitative rating & human explanation
    if final_score >= 0.85 and contradiction_count == 0:
        level = "confirmed"
        summary = f"High confidence ({int(final_score*100)}%): Validated by {corroboration_count} independent sensor(s) with zero contradictions."
    elif final_score >= 0.65 and contradiction_count == 0:
        level = "likely"
        summary = f"Moderate confidence ({int(final_score*100)}%): Corroborated by available sensor telemetry."
    elif contradiction_count > 0:
        level = "possible_match"
        summary = f"Caveat ({int(final_score*100)}%): Observed findings have {contradiction_count} contradicting signal(s) requiring verification."
    else:
        level = "potential"
        summary = f"Low confidence ({int(final_score*100)}%): Single unverified signal or weak indicator."

    explanation = {
        "score": final_score,
        "level": level,
        "summary": summary,
        "base_reliability": round(base_reliability, 2),
        "corroboration_count": corroboration_count,
        "corroboration_boost": round(corroboration_boost, 2),
        "evidence_strength": round(evidence_strength, 2),
        "contradiction_count": contradiction_count,
        "contradiction_penalty": round(contradiction_penalty, 2),
        "freshness_factor": freshness_factor,
        "sources_evaluated": unique_sources,
    }

    return final_score, explanation
