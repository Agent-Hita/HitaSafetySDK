package com.agenthita.sdk.detection

import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * Child-protection invariants: canonical attack conversations that must ALWAYS
 * score at least MEDIUM (the local-notification bar) for a CHILD user, with
 * rules only — no classifier. If a detection change breaks one of these, a
 * child stops being alerted for a known attack; that is never an acceptable
 * side-effect, so these tests must be fixed by strengthening detection, not by
 * weakening the expectation.
 *
 * This is a companion to AgentHitaAndroid's own ChildAlertInvariantsTest, not a
 * replacement for it — that test stays in the app repo under its own explicit
 * "never weakened" rule. This one exists so the same invariant is protected at
 * the SDK level too, for every future consumer (iOS, third parties), not just
 * the Android app.
 *
 * Also locks in the category-provider behaviour: a host app may construct the
 * scorer before it knows the protected person's category, so the scorer must
 * pick up a category change without being reconstructed.
 */
class ChildProtectionInvariantsTest {

    private class FakeClassifier : Classifier {
        override val isLoaded = false
        override fun classify(text: String, context: List<String>, ageHint: String?) = null
    }

    private fun childScorer() = RiskScorer(FakeClassifier(), UserCategory.CHILD)

    private fun List<DetectionResult>.maxLevel(): RiskLevel =
        maxOfOrNull { it.riskLevel } ?: RiskLevel.NONE

    private fun assertChildAlerts(name: String, conversation: String) {
        val level = childScorer().score(conversation).maxLevel()
        assertTrue(
            level >= RiskLevel.MEDIUM,
            "$name must alert (>= MEDIUM) for a CHILD user but was $level"
        )
    }

    // ── Canonical attacks that must alert for a child ────────────────────────

    @Test
    fun otpDemandWithPronounAlertsForChild() = assertChildAlerts(
        "OTP pronoun demand",
        "[CONTACT]: Dear Customer, your OTP for verifying Express Delivery is 482913. Do not share it with anyone.\n" +
        "[USER]: What is this?\n" +
        "[CONTACT]: You will get an otp. Share that."
    )

    @Test
    fun otpDemandWithExplicitPhraseAlertsForChild() = assertChildAlerts(
        "OTP explicit demand",
        "[CONTACT]: I am calling from your bank. Share the otp you received right now."
    )

    @Test
    fun sextortionThreatAlertsForChild() = assertChildAlerts(
        "Sextortion threat",
        "[CONTACT]: Send money now. I know your parents are rich.\n" +
        "[CONTACT]: Else I will share your pictures with everyone you know."
    )

    @Test
    fun credentialHarvestingAlertsForChild() = assertChildAlerts(
        "Credential harvesting",
        "[CONTACT]: Your account will be deleted today. Verify your account immediately.\n" +
        "[CONTACT]: Send me your username and password to keep it safe."
    )

    @Test
    fun cardDetailsHandedOverAfterRequestAlertsForChild() = assertChildAlerts(
        "Requested card handover",
        "[CONTACT]: to reverse the charge send me your card number and cvv\n" +
        "[USER]: 4532 7712 0034 9821 cvv 344"
    )

    @Test
    fun unpromptedCredentialShareWarnsForChild() = assertChildAlerts(
        "Unprompted credential share",
        "[USER]: my card number is 4532 7712 0034 9821 okay"
    )

    @Test
    fun attackBuriedBehindOversizedBenignPaddingStillAlertsForChild() {
        // Same shape as a real 2026-07-19 regression in the host app (a long
        // benign announcement pushed a live sextortion script out of a naive
        // front-truncation window). Here it's exercising the SDK's own
        // MAX_INPUT_LENGTH guard directly: score() must truncate from the FRONT
        // (keep the newest content) so an attack near the end of an oversized
        // window is still scored, not silently dropped.
        val longBenignOpener = "Dear residents, we are excited to share the community newsletter with updates ".repeat(1000)
        val window = "[CONTACT]: $longBenignOpener\n" +
            "[CONTACT]: Send money now. I know your parents are rich.\n" +
            "[CONTACT]: Else I will share your pictures with everyone you know."
        assertChildAlerts("Attack behind oversized benign padding", window)
    }

    // ── Category must be read live, never snapshotted ─────────────────────────

    @Test
    fun scorerPicksUpCategoryChangeWithoutReconstruction() {
        // Simulates a real host-app lifecycle: something constructs the scorer
        // before it knows the protected person's category, then learns it later.
        var category = UserCategory.SELF_PROTECTING_ADULT
        val scorer = RiskScorer(FakeClassifier(), userCategoryProvider = { category })

        val borderline =
            "[CONTACT]: Dear Customer, your OTP for verifying Express Delivery is 482913. Do not share it with anyone.\n" +
            "[USER]: What is this?\n" +
            "[CONTACT]: You will get an otp. Share that."

        category = UserCategory.CHILD
        val childLevel = scorer.score(borderline).maxLevel()
        assertTrue(
            childLevel >= RiskLevel.MEDIUM,
            "After the category changes to CHILD, the same scorer must apply child thresholds (>= MEDIUM) but was $childLevel"
        )
    }
}
