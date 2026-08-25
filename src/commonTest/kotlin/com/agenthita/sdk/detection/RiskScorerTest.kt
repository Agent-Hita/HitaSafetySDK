package com.agenthita.sdk.detection

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class RiskScorerTest {

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** Fake classifier that returns a fixed result, or null when not given one. */
    private class FakeClassifier(
        private val fixedResult: Pair<HarmCategory, RiskLevel>?
    ) : Classifier {
        override val isLoaded = fixedResult != null
        override fun classify(text: String, context: List<String>, ageHint: String?) = fixedResult
    }

    private fun scorer(
        classifierResult: Pair<HarmCategory, RiskLevel>? = null,
        userCategory: UserCategory = UserCategory.SELF_PROTECTING_ADULT,
        riskThresholds: RiskThresholds = RiskThresholds()
    ) = RiskScorer(FakeClassifier(classifierResult), { userCategory }, { riskThresholds })

    // Benign text: no rule signals, intentionally vague so only the classifier could flag it
    private val safeText = "Good morning! Happy Yoga Day everyone, see you at the party."

    // ── Pure rules: a canonical attack scores HIGH with no classifier at all ───

    @Test
    fun canonicalSextortionScoresHighWithRulesAlone() {
        val results = scorer().score(
            "[CONTACT]: don't tell anyone. Send me a nude photo or I will expose you to everyone."
        )
        val top = results.maxByOrNull { it.score }
        assertEquals(HarmCategory.SEXTORTION, top?.category)
        assertEquals(RiskLevel.HIGH, top?.riskLevel)
    }

    // ── Pure-classifier MEDIUM: adult threshold requires classifier HIGH ───────

    @Test
    fun pureClassifierMediumOnSelfProtectingAdultProducesNone() {
        val results = scorer(
            classifierResult = HarmCategory.GROOMING to RiskLevel.MEDIUM,
            userCategory = UserCategory.SELF_PROTECTING_ADULT
        ).score(safeText)

        assertTrue(results.isEmpty(), "Expected no results for adult + classifier-MEDIUM")
    }

    @Test
    fun pureClassifierMediumOnVulnerableAdultProducesMedium() {
        val results = scorer(
            classifierResult = HarmCategory.GROOMING to RiskLevel.MEDIUM,
            userCategory = UserCategory.VULNERABLE_ADULT
        ).score(safeText)

        val top = results.maxByOrNull { it.score }
        assertEquals(HarmCategory.GROOMING, top?.category)
        assertEquals(RiskLevel.MEDIUM, top?.riskLevel)
    }

    // ── Direction guard: a classifier-only verdict on an outgoing-only window ──

    @Test
    fun classifierOnlyVerdictOnOutgoingOnlyWindowIsSuppressed() {
        val results = scorer(
            classifierResult = HarmCategory.IDENTITY_PHISHING to RiskLevel.HIGH,
            userCategory = UserCategory.VULNERABLE_ADULT
        ).score("[USER]: Aa phone charge ayipoyindi padma.")

        assertTrue(results.isEmpty(), "A contact-actor category must not fire when the window is outgoing-only")
    }

    @Test
    fun harassmentIsExemptFromTheDirectionGuard() {
        val results = scorer(
            classifierResult = HarmCategory.HARASSMENT to RiskLevel.HIGH,
            userCategory = UserCategory.SELF_PROTECTING_ADULT
        ).score("[USER]: I am so upset right now about this whole situation today.")

        val top = results.maxByOrNull { it.score }
        assertEquals(HarmCategory.HARASSMENT, top?.category, "HARASSMENT must be flaggable in either direction")
    }

    // ── Address disclosure boost: CHILD/ADOLESCENT only ────────────────────────

    @Test
    fun childAddressDisclosureBoostsGroomingToMedium() {
        val results = scorer(userCategory = UserCategory.CHILD)
            .score("[CONTACT]: Where do you live?\n[USER]: I live at 14 Oak Street.")

        val top = results.maxByOrNull { it.score }
        assertEquals(HarmCategory.GROOMING, top?.category)
        assertTrue(top!!.score >= 0.70f, "Expected address disclosure to floor the score at 0.70, got ${top.score}")
        assertTrue(top.riskLevel >= RiskLevel.MEDIUM)
    }

    @Test
    fun selfProtectingAdultAddressDisclosureIsNotBoosted() {
        val results = scorer(userCategory = UserCategory.SELF_PROTECTING_ADULT)
            .score("[CONTACT]: Where do you live?\n[USER]: I live at 14 Oak Street.")

        // No phrase/word signal on its own here, and the boost only applies to CHILD/ADOLESCENT.
        assertTrue(results.none { it.category == HarmCategory.GROOMING && it.score >= 0.70f })
    }

    // ── RiskThresholds injection: the point of this SDK extraction ────────────
    //
    // RiskScorer no longer reads a global config singleton — it asks its
    // riskThresholdsProvider every time it scores. These tests exist specifically
    // to prove that injection actually changes scoring behaviour, since that's
    // the real seam a host app (or a future third-party integrator) depends on.

    @Test
    fun customThresholdsChangeWhetherARuleScoreClearsHigh() {
        // A pure rule-scored result (no classifier involved) is the right case to
        // prove threshold injection with: scoreToRiskLevel() — the only place that
        // consults riskThresholdsProvider — runs on this path. (The classifier-MEDIUM
        // merge path is a deliberate exception: it hardcodes RiskLevel.MEDIUM as a
        // fixed policy tier rather than computing it from thresholds, so it can't
        // demonstrate injection — that's real, ported production behaviour, not a
        // gap in this test.)
        val text = "[CONTACT]: don't tell anyone. Send me a nude photo or I will expose you to everyone."

        // This text's rule score saturates at the hard 1.0 cap (multiple overlapping
        // signal matches plus the word-lexicon boost) — so the "lenient" band is set
        // above the achievable range entirely, rather than just below 1.0, to prove
        // the provider is genuinely consulted rather than relying on knowing the
        // exact raw score in advance.
        val lenientResult = scorer(
            userCategory = UserCategory.VULNERABLE_ADULT,
            riskThresholds = RiskThresholds(vulnerableAdult = RiskBand(high = 1.01f, medium = 1.0f, low = 0.99f))
        ).score(text).maxByOrNull { it.score }

        val strictResult = scorer(
            userCategory = UserCategory.VULNERABLE_ADULT,
            riskThresholds = RiskThresholds(vulnerableAdult = RiskBand(high = 0.01f, medium = 0.005f, low = 0.001f))
        ).score(text).maxByOrNull { it.score }

        // Same input, same rule signals, different injected thresholds — an
        // unreachable HIGH band must keep this below HIGH, and an almost-trivial
        // HIGH band must clear it, proving scoreToRiskLevel() actually consults
        // the injected provider rather than a fixed threshold.
        assertTrue(lenientResult == null || lenientResult.riskLevel < RiskLevel.HIGH)
        assertEquals(RiskLevel.HIGH, strictResult?.riskLevel)
    }

    @Test
    fun defaultThresholdsMatchDocumentedValues() {
        val defaults = RiskThresholds()
        assertEquals(0.80f, defaults.child.high)
        assertEquals(0.62f, defaults.child.medium)
        assertEquals(0.85f, defaults.adult.high)
        assertEquals(0.70f, defaults.adult.medium)
    }

    // ── OTP handover across windows ────────────────────────────────────────────

    @Test
    fun bareCodeAfterPriorRequestEscalatesToHigh() {
        // The context line must be a genuine REQUEST for the code, not an automated
        // delivery message (a delivery line containing both digits and delivery
        // phrasing like "your OTP for... is 482913" is deliberately excluded from
        // request-matching by IdentityPhishingDetector, so it would not set the
        // code_request signal this escalation depends on).
        val results = scorer().score(
            text = "[USER]: 482913",
            context = listOf("[CONTACT]: I am calling from your bank. Share the otp you received right now.")
        )
        val top = results.maxByOrNull { it.score }
        assertEquals(HarmCategory.IDENTITY_PHISHING, top?.category)
        assertEquals(RiskLevel.HIGH, top?.riskLevel)
    }

    // ── Input-length guard ──────────────────────────────────────────────────────
    // score() must never do unbounded work for an unbounded caller-supplied
    // string — it should truncate (keeping the newest content) rather than either
    // rejecting the call or processing the whole thing.

    @Test
    fun oversizedTextDoesNotCrashAndStillScoresTheNewestContent() {
        val attack = "[CONTACT]: don't tell anyone. Send me a nude photo or I will expose you to everyone."
        val padding = "a".repeat(200_000)
        val results = scorer().score(padding + "\n" + attack)

        val top = results.maxByOrNull { it.score }
        assertEquals(HarmCategory.SEXTORTION, top?.category)
        assertEquals(RiskLevel.HIGH, top?.riskLevel)
    }

    @Test
    fun oversizedContextListDoesNotCrash() {
        val hugeContext = (1..10_000).map { "message number $it, nothing interesting here at all" }
        // Should complete without throwing or hanging; a real attack in the latest
        // message must still be detected even with a huge prior-context list.
        val results = scorer().score(
            text = "[CONTACT]: I will kill you and I know where you live.",
            context = hugeContext
        )
        val top = results.maxByOrNull { it.score }
        assertEquals(HarmCategory.HARASSMENT, top?.category)
    }

    @Test
    fun oversizedSingleContextMessageDoesNotCrash() {
        val hugeContextMessage = "[CONTACT]: " + "b".repeat(500_000)
        val results = scorer().score(
            text = "[CONTACT]: I will kill you and I know where you live.",
            context = listOf(hugeContextMessage)
        )
        val top = results.maxByOrNull { it.score }
        assertEquals(HarmCategory.HARASSMENT, top?.category)
    }
}
