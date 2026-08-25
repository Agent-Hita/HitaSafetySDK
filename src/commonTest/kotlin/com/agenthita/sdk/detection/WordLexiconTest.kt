package com.agenthita.sdk.detection

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class WordLexiconTest {

    // ── Coverage: all categories present ──────────────────────────────────────

    @Test
    fun allSevenHarmCategoriesHaveEntriesInTheLexicon() {
        val required = listOf(
            HarmCategory.ROMANCE_SCAM,
            HarmCategory.SEXTORTION,
            HarmCategory.GROOMING,
            HarmCategory.FINANCIAL_SCAM,
            HarmCategory.IDENTITY_PHISHING,
            HarmCategory.LURING,
            HarmCategory.HARASSMENT
        )
        required.forEach { category ->
            val entries = WordLexicon.weights[category]
            assertNotNull(entries, "WordLexicon missing category: $category")
            assertTrue(entries.size >= 5, "WordLexicon.$category has fewer than 5 entries (got ${entries.size})")
        }
    }

    @Test
    fun allWeightValuesAreInRangeZeroToOne() {
        WordLexicon.weights.forEach { (category, dict) ->
            dict.forEach { (word, weight) ->
                assertTrue(weight in 0f..1f, "Weight out of range for $category/$word: $weight")
            }
        }
    }

    // ── Scoring: zero on clean text ───────────────────────────────────────────

    @Test
    fun scoreReturnsZeroForEmptyString() {
        HarmCategory.entries.forEach { category ->
            assertEquals(0f, WordLexicon.score("", category), 0.001f)
        }
    }

    @Test
    fun scoreReturnsZeroForBenignGreeting() {
        val text = "Hey how are you doing today"
        HarmCategory.entries.filter { it != HarmCategory.DISAPPEARING_MESSAGES }.forEach { category ->
            val score = WordLexicon.score(text, category)
            assertEquals(0f, score, 0.001f, "Expected 0 for '$text' in $category, got $score")
        }
    }

    // ── Scoring: high-signal words register ───────────────────────────────────

    @Test
    fun blackmailScoresHighInSextortion() {
        val score = WordLexicon.score("I will blackmail you", HarmCategory.SEXTORTION)
        assertTrue(score > 0.2f, "Expected score > 0.2 for blackmail in SEXTORTION, got $score")
    }

    @Test
    fun extortScoresHighInSextortion() {
        val score = WordLexicon.score("I will extort you", HarmCategory.SEXTORTION)
        assertTrue(score > 0.2f, "Expected score > 0.2 for extort in SEXTORTION, got $score")
    }

    @Test
    fun nudeScoresHighInSextortion() {
        val score = WordLexicon.score("send me a nude photo", HarmCategory.SEXTORTION)
        assertTrue(score > 0.2f, "Expected score > 0.2 for nude in SEXTORTION, got $score")
    }

    @Test
    fun bitcoinScoresInFinancialScam() {
        val score = WordLexicon.score("send bitcoin immediately", HarmCategory.FINANCIAL_SCAM)
        assertTrue(score > 0.2f, "Expected score > 0.2 for bitcoin in FINANCIAL_SCAM, got $score")
    }

    @Test
    fun passwordScoresHighInIdentityPhishing() {
        val score = WordLexicon.score("give me your password", HarmCategory.IDENTITY_PHISHING)
        assertTrue(score > 0.2f, "Expected score > 0.2 for password in IDENTITY_PHISHING, got $score")
    }

    @Test
    fun ssnScoresHighInIdentityPhishing() {
        val score = WordLexicon.score("what is your ssn number", HarmCategory.IDENTITY_PHISHING)
        assertTrue(score > 0.2f, "Expected score > 0.2 for ssn in IDENTITY_PHISHING, got $score")
    }

    @Test
    fun killScoresInHarassment() {
        val score = WordLexicon.score("I will kill you", HarmCategory.HARASSMENT)
        assertTrue(score > 0.2f, "Expected score > 0.2 for kill in HARASSMENT, got $score")
    }

    @Test
    fun doxxScoresInHarassment() {
        val score = WordLexicon.score("I will doxx you online", HarmCategory.HARASSMENT)
        assertTrue(score > 0.2f, "Expected score > 0.2 for doxx in HARASSMENT, got $score")
    }

    @Test
    fun strandedScoresInRomanceScam() {
        val score = WordLexicon.score("I am stranded please help", HarmCategory.ROMANCE_SCAM)
        assertTrue(score > 0.1f, "Expected score > 0.1 for stranded in ROMANCE_SCAM, got $score")
    }

    @Test
    fun sneakScoresInGrooming() {
        val score = WordLexicon.score("let us sneak away together", HarmCategory.GROOMING)
        assertTrue(score > 0.1f, "Expected score > 0.1 for sneak in GROOMING, got $score")
    }

    // ── Scoring: bounded at 1.0 ───────────────────────────────────────────────

    @Test
    fun scoreIsCappedAtOneForDenseHighWeightText() {
        val text = "blackmail extort nude nudes naked expose exposed leak leaked ruined"
        val score = WordLexicon.score(text, HarmCategory.SEXTORTION)
        assertTrue(score <= 1.0f, "Score must be <= 1.0, got $score")
    }

    // ── Scoring: case insensitive ─────────────────────────────────────────────

    @Test
    fun scoreIsCaseInsensitive() {
        val lower = WordLexicon.score("blackmail", HarmCategory.SEXTORTION)
        val upper = WordLexicon.score("BLACKMAIL", HarmCategory.SEXTORTION)
        val mixed = WordLexicon.score("BlackMail", HarmCategory.SEXTORTION)
        assertEquals(lower, upper, 0.001f)
        assertEquals(lower, mixed, 0.001f)
    }

    // ── Cross-category isolation ──────────────────────────────────────────────

    @Test
    fun sextortionKeywordDoesNotBleedIntoUnrelatedCategory() {
        val score = WordLexicon.score("nude", HarmCategory.FINANCIAL_SCAM)
        assertEquals(0f, score, 0.001f)
    }
}
