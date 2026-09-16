package com.agenthita.sdk.detection

/**
 * Detects a CHILD or ADOLESCENT's own unprompted interest in explicit/adult
 * material — like HarmfulContentDetector, this describes the protected
 * person's OWN search/statement, not a reply to an attacker, so it's
 * naturally response-only-shaped with no [CONTACT] side to see.
 *
 * Any match floors to HIGH for CHILD and MEDIUM for ADOLESCENT at the scorer
 * level (see ResponseOnlyRiskScorer/RiskScorer) — deliberately blunt rather
 * than combo-bonus math, matching HarmfulContentDetector's reasoning.
 */
class AdultContentDetector : PatternMatcher {

    override val category = HarmCategory.ADULT_CONTENT

    // Bare-word signals — matched with word boundaries (see FinancialScamDetector's
    // authorityAcronymSignals for the same pattern) rather than as part of a
    // fixed phrase. Confirmed on-device that a phrase-list-only approach
    // ("free porn", "porn site", etc.) missed a real, unambiguous message —
    // "best website to search for porn" — because "porn" wasn't part of any
    // listed phrase. Safe as a bare word: unlike "explosive" or "bomb",
    // these terms have essentially no innocent everyday usage.
    private val explicitBareWordSignals = listOf(
        "porn", "pornhub", "xvideos", "xnxx", "onlyfans", "hentai"
    )

    private val explicitSearchSignals = listOf(
        "nude pics of", "nude photos of", "naked pics of", "naked photos of",
        "sex video", "sex videos", "sex tape",
        "adult video site", "adult content site"
    )

    override fun analyze(text: String): DetectionResult {
        val lower = text.lowercase()
        val matches = mutableListOf<SignalMatch>()

        explicitBareWordSignals.forEach { signal ->
            if (Regex("\\b${signal}\\b").containsMatchIn(lower)) matches.add(SignalMatch("explicit_content_search", signal, 0.9f))
        }
        explicitSearchSignals.forEach { signal ->
            if (lower.contains(signal)) matches.add(SignalMatch("explicit_content_search", signal, 0.9f))
        }

        val score = if (matches.isEmpty()) 0f else 1f
        return DetectionResult(
            category = HarmCategory.ADULT_CONTENT,
            riskLevel = if (matches.isEmpty()) RiskLevel.NONE else RiskLevel.HIGH,
            score = score,
            signals = matches,
            explanation = buildExplanation(matches)
        )
    }

    private fun buildExplanation(matches: List<SignalMatch>): String {
        if (matches.isEmpty()) return "No adult content signals detected."
        val types = matches.map { it.signal }.toSet()
        return "Detected a search or statement about explicit/adult content: ${types.joinToString(", ")}."
    }
}
