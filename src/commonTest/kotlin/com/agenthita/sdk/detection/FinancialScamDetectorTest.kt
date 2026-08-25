package com.agenthita.sdk.detection

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class FinancialScamDetectorTest {

    private val detector = FinancialScamDetector()

    // ── False-positive regression ─────────────────────────────────────────────
    // A bare URL must not flag a legitimate message. Previously "https://" was a
    // standalone suspicious_link signal with weight 0.6, enough to cross the
    // child MEDIUM threshold on its own.

    @Test
    fun legitimateYogaInviteWithUrlScoresNone() {
        val result = detector.analyze(
            "I am sending you a special invitation to join FREE YOGA 14-day online " +
            "next batch 22-june with saurabh bothra govt-certified yoga trainer IIT graduate " +
            "| 14+years pf experience Click below to join for free " +
            "https://habit.yoga/profdrtvsrinivasd86b12da regards, prof dr t v srinivas"
        )
        assertEquals(RiskLevel.NONE, result.riskLevel)
    }

    @Test
    fun messageWithOnlyABareHttpsUrlScoresNone() {
        val result = detector.analyze("Check out our new article: https://example.com/blog/post-1")
        assertEquals(RiskLevel.NONE, result.riskLevel)
    }

    @Test
    fun messageWithOnlyABareHttpUrlScoresNone() {
        val result = detector.analyze("Our website is http://mysite.org for more info")
        assertEquals(RiskLevel.NONE, result.riskLevel)
    }

    @Test
    fun eventInviteWithUrlScoresNone() {
        val result = detector.analyze(
            "Join our free webinar on Thursday! Register here: https://zoom.us/webinar/register/abc123"
        )
        assertEquals(RiskLevel.NONE, result.riskLevel)
    }

    // ── False-positive: numeric IDs in document-sharing context ──────────────
    // Tax IDs, EINs, and SSNs share the phone-number regex format. They must not
    // fire phone_number_demand when the message is clearly a document share.

    @Test
    fun parentSharingEinInTaxDocumentScoresNone() {
        val result = detector.analyze(
            "Here is your tax document. The employer identification number is 12-3456789."
        )
        assertEquals(RiskLevel.NONE, result.riskLevel)
    }

    @Test
    fun pleaseFindAttachedWithNumericIdScoresNone() {
        val result = detector.analyze(
            "Please find attached the completed form. Reference number: 123456789."
        )
        assertEquals(RiskLevel.NONE, result.riskLevel)
    }

    @Test
    fun asRequestedSsnShareScoresNone() {
        val result = detector.analyze(
            "As requested, here is the social security number: 123-456-789 for your records."
        )
        assertEquals(RiskLevel.NONE, result.riskLevel)
    }

    // Providing context does NOT suppress when authority/urgency also fires
    @Test
    fun hereIsWithIrsAuthorityStillScoresHigh() {
        val result = detector.analyze(
            "Here is the IRS notice. You owe back taxes. Pay immediately via gift card or face arrest."
        )
        assertEquals(RiskLevel.HIGH, result.riskLevel)
    }

    @Test
    fun hereIsWithUrgencyPhoneDemandStillFires() {
        val result = detector.analyze(
            "Here is the situation — your account will be closed. Call us at 800-555-0199 immediately."
        )
        assertTrue(result.riskLevel >= RiskLevel.MEDIUM)
        assertTrue(result.signals.any { it.signal == "phone_number_demand" })
    }

    // ── Suspicious link signals that MUST still fire ──────────────────────────

    @Test
    fun urlShortenerBitLyScoresAtLeastLow() {
        val result = detector.analyze("Click this link to claim your package: bit.ly/trackpkg99")
        assertTrue(result.riskLevel >= RiskLevel.LOW)
        assertTrue(result.signals.any { it.signal == "suspicious_link" })
    }

    @Test
    fun urlShortenerTinyurlScoresAtLeastLow() {
        val result = detector.analyze("Your account requires verification: tinyurl.com/verifyacc")
        assertTrue(result.riskLevel >= RiskLevel.LOW)
        assertTrue(result.signals.any { it.signal == "suspicious_link" })
    }

    @Test
    fun paymentPathInUrlScoresAtLeastLow() {
        val result = detector.analyze("Complete your outstanding balance: mybank.com/payment/now")
        assertTrue(result.riskLevel >= RiskLevel.LOW)
        assertTrue(result.signals.any { it.signal == "suspicious_link" })
    }

    @Test
    fun verifyPathInUrlScoresAtLeastLow() {
        val result = detector.analyze("Your account has been locked. Verify now: secure-login.com/verify")
        assertTrue(result.riskLevel >= RiskLevel.LOW)
    }

    @Test
    fun clickHerePhraseScoresAtLeastLow() {
        val result = detector.analyze("Your payment is overdue. Click here to settle your account immediately.")
        assertTrue(result.riskLevel >= RiskLevel.LOW)
        assertTrue(result.signals.any { it.signal == "suspicious_link" })
    }

    // ── Prize scam ────────────────────────────────────────────────────────────

    @Test
    fun prizeScamClaimYourPrizeScoresAtLeastMedium() {
        val result = detector.analyze("Congratulations! You've won. Claim your prize by sending gift cards worth \$500.")
        assertTrue(result.riskLevel >= RiskLevel.MEDIUM)
        assertTrue(result.signals.any { it.signal == "prize_scam" })
        assertTrue(result.signals.any { it.signal == "payment_method" })
    }

    @Test
    fun lotteryWinnerMessageScoresAtLeastMedium() {
        val result = detector.analyze("You are the lucky winner of our lottery. Send your bank account details to collect.")
        assertTrue(result.riskLevel >= RiskLevel.MEDIUM)
    }

    // ── Authority + payment combo ─────────────────────────────────────────────

    @Test
    fun irsImpersonationWithPaymentScoresHigh() {
        val result = detector.analyze(
            "This is the IRS. You owe back taxes. Pay immediately using Google Play card " +
            "or a warrant will be issued for your arrest."
        )
        assertEquals(RiskLevel.HIGH, result.riskLevel)
        assertTrue(result.signals.any { it.signal == "authority_claim" })
        assertTrue(result.signals.any { it.signal == "payment_method" })
    }

    @Test
    fun bankImpersonationAccountLockedScoresAtLeastMedium() {
        val result = detector.analyze(
            "Your account has been locked due to suspicious activity. " +
            "Please call us immediately to verify your bank account details."
        )
        assertTrue(result.riskLevel >= RiskLevel.MEDIUM)
        assertTrue(result.signals.any { it.signal == "authority_claim" })
    }

    // ── Urgency signals ───────────────────────────────────────────────────────

    @Test
    fun urgentPaymentDemandScoresAtLeastMedium() {
        val result = detector.analyze(
            "Final notice: your payment is overdue. Failure to pay immediately will result in late fees and penalties."
        )
        assertTrue(result.riskLevel >= RiskLevel.MEDIUM)
        assertTrue(result.signals.any { it.signal == "urgency" })
        assertTrue(result.signals.any { it.signal == "payment_method" })
    }

    // ── Isolation signals ─────────────────────────────────────────────────────

    @Test
    fun isolationDemandWithPaymentScoresAtLeastMedium() {
        val result = detector.analyze(
            "Do not tell your family about this. Send the money via wire transfer right now."
        )
        assertTrue(result.riskLevel >= RiskLevel.MEDIUM)
        assertTrue(result.signals.any { it.signal == "isolation" })
        assertTrue(result.signals.any { it.signal == "payment_method" })
    }

    // ── Clean messages → NONE ─────────────────────────────────────────────────

    @Test
    fun normalGreetingScoresNone() {
        val result = detector.analyze("Hey! Are you free this weekend? We should catch up.")
        assertEquals(RiskLevel.NONE, result.riskLevel)
    }

    @Test
    fun shoppingDiscussionScoresNone() {
        val result = detector.analyze("I ordered the shoes online, they should arrive by Thursday.")
        assertEquals(RiskLevel.NONE, result.riskLevel)
    }

    // ── Category and signal metadata ──────────────────────────────────────────

    @Test
    fun categoryIsAlwaysFinancialScam() {
        val result = detector.analyze("You've won a prize! Claim your reward now.")
        assertEquals(HarmCategory.FINANCIAL_SCAM, result.category)
    }

    @Test
    fun scoreIsWithinZeroToOneRange() {
        val result = detector.analyze(
            "IRS: You owe taxes. Pay immediately via gift card or face arrest. " +
            "Do not tell anyone. Call us at 800-555-0199 right now."
        )
        assertTrue(result.score in 0f..1f)
    }
}
