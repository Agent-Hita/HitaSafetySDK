package com.agenthita.sdk.detection

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class IdentityPhishingDetectorTest {

    private val detector = IdentityPhishingDetector()

    // ── True positives — code/credential requests ─────────────────────────────

    @Test
    fun otpRequestScoresAtLeastMedium() {
        val result = detector.analyze("Please share the OTP we just sent to your phone to verify your account.")
        assertTrue(result.riskLevel >= RiskLevel.MEDIUM)
        assertTrue(result.signals.any { it.signal == "code_request" })
    }

    @Test
    fun passwordRequestScoresAtLeastMedium() {
        val result = detector.analyze("Enter your password and username to continue.")
        assertTrue(result.riskLevel >= RiskLevel.MEDIUM)
        assertTrue(result.signals.any { it.signal == "credential_request" })
    }

    @Test
    fun ssnRequestWithUrgencyScoresHigh() {
        // Multiple signals: personal_info_request + urgency + credential_request pushes over HIGH threshold
        val result = detector.analyze(
            "Your account will be suspended. Action required immediately — " +
            "confirm your account password and provide your social security number."
        )
        assertEquals(RiskLevel.HIGH, result.riskLevel)
    }

    @Test
    fun fakeBankSecurityAlertWithCredentialRequestScoresHigh() {
        val result = detector.analyze(
            "From your bank security team: unusual activity detected. " +
            "Please confirm your account details and password immediately."
        )
        assertEquals(RiskLevel.HIGH, result.riskLevel)
    }

    @Test
    fun twoFactorCodeRequestScoresAtLeastMedium() {
        val result = detector.analyze("Can you read me the 2fa code from your phone?")
        assertTrue(result.riskLevel >= RiskLevel.MEDIUM)
        assertTrue(result.signals.any { it.signal == "code_request" })
    }

    // ── False-positive regressions — information sharing ─────────────────────

    @Test
    fun parentSharingTaxDocumentWithSsnScoresNone() {
        val result = detector.analyze(
            "Here is your tax document. Your social security number is 123-45-6789. " +
            "Please keep this safe."
        )
        assertEquals(RiskLevel.NONE, result.riskLevel)
    }

    @Test
    fun hereIsTheTaxAndIdentificationNumberScoresNone() {
        val result = detector.analyze("Here is the tax and identification number for the form.")
        assertEquals(RiskLevel.NONE, result.riskLevel)
    }

    @Test
    fun parentForwardingPassportNumberScoresNone() {
        val result = detector.analyze(
            "I've attached your travel docs. Your passport number is AB1234567 — please verify."
        )
        assertEquals(RiskLevel.NONE, result.riskLevel)
    }

    @Test
    fun fyiSharingNationalIdScoresNone() {
        val result = detector.analyze("FYI here is your national ID number as requested.")
        assertEquals(RiskLevel.NONE, result.riskLevel)
    }

    @Test
    fun pleaseFindAttachedWithAccountNumberScoresNone() {
        val result = detector.analyze(
            "Please find the attached form. The bank account number shown is for refund purposes."
        )
        assertEquals(RiskLevel.NONE, result.riskLevel)
    }

    // ── Providing context does NOT suppress when request signals also fire ────

    @Test
    fun hereIsPrefixDoesNotSuppressWhenCredentialRequestAlsoPresent() {
        val result = detector.analyze(
            "Here is the link. Now enter your password and username to complete verification."
        )
        assertTrue(result.riskLevel >= RiskLevel.MEDIUM)
        assertTrue(result.signals.any { it.signal == "credential_request" })
    }

    @Test
    fun providingContextDoesNotSuppressOtpRequest() {
        val result = detector.analyze(
            "I am sending you the form. Can you also share the OTP from your phone?"
        )
        assertTrue(result.riskLevel >= RiskLevel.MEDIUM)
        assertTrue(result.signals.any { it.signal == "code_request" })
    }

    // ── OTP direction handling — received OTPs must not flag ─────────────────

    @Test
    fun receivedBankOtpDeliveryScoresNone() {
        val result = detector.analyze(
            "[CONTACT]: 482913 is your OTP for HDFC Bank txn of INR 5,000. Do not share it with anyone."
        )
        assertEquals(RiskLevel.NONE, result.riskLevel)
    }

    @Test
    fun receivedOtpDeliveryWithoutDirectionPrefixScoresNone() {
        val result = detector.analyze("Your OTP is 482913, valid for 10 minutes. Never share this code.")
        assertEquals(RiskLevel.NONE, result.riskLevel)
    }

    @Test
    fun bankSafetyWarningWithoutCodeScoresNone() {
        val result = detector.analyze(
            "[CONTACT]: Dear customer, never share your OTP or CVV with anyone. Bank staff will never ask for it."
        )
        assertEquals(RiskLevel.NONE, result.riskLevel)
    }

    @Test
    fun codeRequestStillFlagsWhenWindowAlsoHasADeliveryMessage() {
        val result = detector.analyze(
            "[CONTACT]: 482913 is your OTP. Do not share it with anyone.\n" +
            "[CONTACT]: hello, this is bank security, send me the otp you just received"
        )
        assertTrue(result.signals.any { it.signal == "code_request" })
        assertTrue(result.riskLevel >= RiskLevel.MEDIUM)
    }

    // ── OTP direction handling — user sharing an OTP must flag ───────────────

    @Test
    fun userSharingOtpWithKeywordFiresOtpSharedAndScoresHigh() {
        val result = detector.analyze("[USER]: the otp is 482913")
        assertTrue(result.signals.any { it.signal == "otp_shared" })
        assertEquals(RiskLevel.HIGH, result.riskLevel)
    }

    @Test
    fun userReplyingBareCodeToACodeRequestFiresOtpShared() {
        val result = detector.analyze("[CONTACT]: share the otp you received\n[USER]: 482913")
        assertTrue(result.signals.any { it.signal == "otp_shared" })
        assertEquals(RiskLevel.HIGH, result.riskLevel)
    }

    @Test
    fun userForwardingDeliveryMessageVerbatimFiresOtpShared() {
        val result = detector.analyze("[USER]: Your OTP is 482913. Do not share it with anyone.")
        assertTrue(result.signals.any { it.signal == "otp_shared" })
        assertEquals(RiskLevel.HIGH, result.riskLevel)
    }

    @Test
    fun userBareNumberWithoutAnyCodeRequestScoresNone() {
        val result = detector.analyze("[USER]: 482913 see you at 5")
        assertEquals(RiskLevel.NONE, result.riskLevel)
    }

    @Test
    fun userSharingPostalPinCodeDoesNotFireOtpShared() {
        val result = detector.analyze("[USER]: my pin code is 560001 for the delivery")
        assertTrue(result.signals.none { it.signal == "otp_shared" })
        assertEquals(RiskLevel.NONE, result.riskLevel)
    }

    // ── Clean text → NONE ─────────────────────────────────────────────────────

    @Test
    fun normalMessageScoresNone() {
        val result = detector.analyze("Hey! How is your day going? Did you finish the project?")
        assertEquals(RiskLevel.NONE, result.riskLevel)
    }

    @Test
    fun categoryIsAlwaysIdentityPhishing() {
        val result = detector.analyze("Send me the verification code you received.")
        assertEquals(HarmCategory.IDENTITY_PHISHING, result.category)
    }

    @Test
    fun scoreIsWithinZeroToOneRange() {
        val result = detector.analyze(
            "URGENT: Your account has been compromised. Provide your password and OTP immediately."
        )
        assertTrue(result.score in 0f..1f)
    }
}
