package com.agenthita.sdk.gemma

import com.agenthita.sdk.detection.HarmCategory
import com.agenthita.sdk.detection.RiskLevel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class GemmaAndroidClassifierTest {

    // ── Response parsing ────────────────────────────────────────────────────

    @Test
    fun `ideal format parses category and severity`() {
        val result = GemmaAndroidClassifier.parseMultiClassResponse("SEXTORTION HIGH")
        assertEquals(HarmCategory.SEXTORTION to RiskLevel.HIGH, result)
    }

    @Test
    fun `fill-in format with labels parses correctly`() {
        val result = GemmaAndroidClassifier.parseMultiClassResponse("HARM TYPE GROOMING SEVERITY HIGH")
        assertEquals(HarmCategory.GROOMING to RiskLevel.HIGH, result)
    }

    @Test
    fun `category only defaults to MEDIUM severity`() {
        val result = GemmaAndroidClassifier.parseMultiClassResponse("IDENTITY_PHISHING")
        assertEquals(HarmCategory.IDENTITY_PHISHING to RiskLevel.MEDIUM, result)
    }

    @Test
    fun `explicit NONE category terminates parsing regardless of trailing tokens`() {
        // A rambling safe answer mentioning "PHISHING" elsewhere must not manufacture an alert.
        val result = GemmaAndroidClassifier.parseMultiClassResponse("NONE THIS IS A BANK ALERT NOT PHISHING")
        assertNull(result)
    }

    @Test
    fun `explicit NONE severity terminates parsing`() {
        val result = GemmaAndroidClassifier.parseMultiClassResponse("HARM TYPE GROOMING SEVERITY NONE NOT HIGH RISK")
        assertNull(result)
    }

    @Test
    fun `echoed prompt is parsed from the last HARM TYPE label, not the valid-types list`() {
        val echoed = "VALID HARM TYPES SEXTORTION FINANCIAL SCAM GROOMING HARM TYPE ROMANCE_SCAM SEVERITY MEDIUM"
        val result = GemmaAndroidClassifier.parseMultiClassResponse(echoed)
        assertEquals(HarmCategory.ROMANCE_SCAM to RiskLevel.MEDIUM, result)
    }

    @Test
    fun `unparseable response returns null`() {
        assertNull(GemmaAndroidClassifier.parseMultiClassResponse("SCAMMING MAYBE IDK"))
    }

    @Test
    fun `PHISHING alias maps to IDENTITY_PHISHING`() {
        val result = GemmaAndroidClassifier.parseMultiClassResponse("PHISHING HIGH")
        assertEquals(HarmCategory.IDENTITY_PHISHING to RiskLevel.HIGH, result)
    }

    // ── keepNewest ───────────────────────────────────────────────────────────

    @Test
    fun `keepNewest returns text unchanged when under budget`() {
        assertEquals("short text", GemmaAndroidClassifier.keepNewest("short text", 100))
    }

    @Test
    fun `keepNewest truncates from the front, keeping newest content`() {
        val text = "a".repeat(50) + "\n" + "b".repeat(50)
        val result = GemmaAndroidClassifier.keepNewest(text, 60)
        assertEquals(true, result.endsWith("b".repeat(50)))
        assertEquals(false, result.contains("a"))
    }

    // ── Prompt fitting ───────────────────────────────────────────────────────

    @Test
    fun `buildFittedPrompt stays within the model's token budget`() {
        val config = GemmaClassifierConfig(maxTokens = 512)
        val longContext = (1..50).map { "message number $it with some extra padding text here" }
        val prompt = GemmaAndroidClassifier.buildFittedPrompt(
            text = "a".repeat(2000),
            context = longContext,
            ageHint = null,
            config = config
        )
        val maxChars = (config.maxTokens - 50) * 3
        assertEquals(true, prompt.length <= maxChars)
    }

    @Test
    fun `buildMultiClassPrompt includes age hint when provided`() {
        val prompt = GemmaAndroidClassifier.buildMultiClassPrompt(
            text = "hello",
            ageHint = "child under 13 years old"
        )
        assertEquals(true, prompt.contains("child under 13 years old"))
    }
}
