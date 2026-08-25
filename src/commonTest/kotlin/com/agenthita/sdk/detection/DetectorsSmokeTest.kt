package com.agenthita.sdk.detection

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * One canonical-attack and one benign-text check per detector not already
 * exercised in depth by [RiskScorerTest] — a regression safety net for the
 * ported phrase lists, run directly against each [PatternMatcher].
 */
class DetectorsSmokeTest {

    private val benignText = "Hey, are we still on for coffee tomorrow morning?"

    @Test
    fun financialScamDetectorFlagsCanonicalAttack() {
        val result = FinancialScamDetector().analyze(
            "Your account will be suspended today. Call us at 1-800-555-0199 or pay via gift card immediately."
        )
        assertEquals(RiskLevel.HIGH, result.riskLevel)
    }

    @Test
    fun financialScamDetectorIsQuietOnBenignText() {
        assertEquals(RiskLevel.NONE, FinancialScamDetector().analyze(benignText).riskLevel)
    }

    @Test
    fun romanceScamDetectorFlagsCanonicalAttack() {
        val result = RomanceScamDetector().analyze(
            "You're my soulmate, we were meant to be. I'm stranded and need you to send money urgently."
        )
        assertTrue(result.riskLevel >= RiskLevel.MEDIUM)
    }

    @Test
    fun romanceScamDetectorIsQuietOnBenignText() {
        assertEquals(RiskLevel.NONE, RomanceScamDetector().analyze(benignText).riskLevel)
    }

    @Test
    fun luringDetectorFlagsCanonicalAttack() {
        val result = LuringDetector().analyze(
            "You've been selected for a modelling opportunity, all expenses paid — just send your photos and home address."
        )
        assertTrue(result.riskLevel >= RiskLevel.MEDIUM)
    }

    @Test
    fun luringDetectorIsQuietOnBenignText() {
        assertEquals(RiskLevel.NONE, LuringDetector().analyze(benignText).riskLevel)
    }

    @Test
    fun harassmentDetectorFlagsCanonicalAttack() {
        val result = HarassmentDetector().analyze(
            "I know where you live and I've been watching you. You'll pay for this."
        )
        assertEquals(RiskLevel.HIGH, result.riskLevel)
    }

    @Test
    fun harassmentDetectorIsQuietOnBenignText() {
        assertEquals(RiskLevel.NONE, HarassmentDetector().analyze(benignText).riskLevel)
    }

    @Test
    fun groomingDetectorFlagsCanonicalAttack() {
        val result = GroomingDetector().analyze(
            "Are your parents home? Don't tell your parents about us, this is just between us."
        )
        assertTrue(result.riskLevel >= RiskLevel.MEDIUM)
    }

    @Test
    fun groomingDetectorIsQuietOnBenignText() {
        assertEquals(RiskLevel.NONE, GroomingDetector().analyze(benignText).riskLevel)
    }

    @Test
    fun identityPhishingDetectorFlagsCanonicalAttack() {
        val result = IdentityPhishingDetector().analyze(
            "This is Bank Security. Your account has been compromised, share the OTP now to verify your identity."
        )
        assertEquals(RiskLevel.HIGH, result.riskLevel)
    }

    @Test
    fun identityPhishingDetectorIsQuietOnBenignText() {
        assertEquals(RiskLevel.NONE, IdentityPhishingDetector().analyze(benignText).riskLevel)
    }

    @Test
    fun sextortionDetectorFlagsCanonicalAttack() {
        val result = SextortionDetector().analyze(
            "Send me a nude photo, don't tell anyone, or I will expose you to everyone."
        )
        assertEquals(RiskLevel.HIGH, result.riskLevel)
    }

    @Test
    fun sextortionDetectorIsQuietOnBenignText() {
        assertEquals(RiskLevel.NONE, SextortionDetector().analyze(benignText).riskLevel)
    }

    @Test
    fun disappearingMessageDetectorFlagsConfirmedActivation() {
        val result = DisappearingMessageDetector().analyze("Disappearing messages are on. Messages will disappear after 24 hours.")
        assertEquals(RiskLevel.HIGH, result.riskLevel)
    }

    @Test
    fun disappearingMessageDetectorIsQuietOnBenignText() {
        assertEquals(RiskLevel.NONE, DisappearingMessageDetector().analyze(benignText).riskLevel)
    }

    // ── DisappearingMessageUtils ────────────────────────────────────────────

    @Test
    fun parseDurationDaysHandlesCommonUnits() {
        assertEquals(1, parseDurationDays("messages disappear after 24 hours"))
        assertEquals(7, parseDurationDays("timer set to 7 days"))
        assertEquals(90, parseDurationDays("default 90 day timer"))
        assertEquals(null, parseDurationDays("no duration mentioned here"))
    }

    @Test
    fun disappearingRiskLevelShortTimerIsAlwaysHigh() {
        assertEquals(RiskLevel.HIGH, disappearingRiskLevel(durationDays = 1, hasExistingThreat = false))
        assertEquals(RiskLevel.HIGH, disappearingRiskLevel(durationDays = null, hasExistingThreat = false))
    }

    @Test
    fun disappearingRiskLevelLongTimerNeedsExistingThreat() {
        assertEquals(null, disappearingRiskLevel(durationDays = 90, hasExistingThreat = false))
        assertEquals(RiskLevel.MEDIUM, disappearingRiskLevel(durationDays = 90, hasExistingThreat = true))
    }
}
