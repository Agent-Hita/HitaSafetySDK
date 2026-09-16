package com.agenthita.sdk.detection

/**
 * Sibling to [RiskScorer] for callers that structurally can only ever see the
 * protected person's own outgoing text — a keyboard extension, concretely,
 * which has no API to read the other side of a conversation at all (see
 * AgentHitaFeedbackService/docs/DETECTION_DECISIONS.md decision #11).
 *
 * [RiskScorer]'s merge step includes a direction guard that discards a
 * classifier-only verdict (zero rule signals) for every category except
 * HARASSMENT whenever the scored window contains no [CONTACT] line — sound
 * reasoning for a two-sided transcript ("a contact who said nothing can't be
 * victimising the user"), but it silently caps a response-only caller to
 * HARASSMENT-only classifier coverage, since a response-only window can
 * *never* contain a [CONTACT] line by definition — every window here is
 * outgoing-only by construction. This scorer drops that guard entirely: a
 * classifier verdict is trusted on its own terms instead of treated as
 * suspect for lacking a [CONTACT] line that could never have existed.
 *
 * Everything else — phrase/word-lexicon matching, disclosure boosting, OTP
 * escalation, and classifier merge severity bands — is intentionally
 * IDENTICAL to [RiskScorer], including [mergeClassifierResult] and
 * [scoreToRiskLevel] duplicated verbatim rather than shared. That duplication
 * is a known tradeoff (see decision #11): kept separate for now so this
 * class can evolve independently without risking [RiskScorer]'s existing,
 * approved behaviour; worth extracting to a shared base if the two drift
 * apart in practice, but not upfront.
 *
 * Input contract is also simplified: callers pass a plain [message], never a
 * "[USER]: "-prefixed string — there is never a [CONTACT] line to
 * distinguish it from here, so the prefix requirement served no purpose for
 * this shape of caller. The "[USER]: " prefix is added once, internally, so
 * the shared [PatternMatcher] detectors (which do expect it) see the exact
 * same input shape they always have.
 */
class ResponseOnlyRiskScorer(
    private val classifier: Classifier,
    private val userCategoryProvider: () -> UserCategory = { UserCategory.SELF_PROTECTING_ADULT },
    private val riskThresholdsProvider: () -> RiskThresholds = { RiskThresholds() }
) {

    constructor(classifier: Classifier, userCategory: UserCategory) :
        this(classifier, { userCategory })

    // Read per scoring pass, never snapshotted — see RiskScorer's identical comment.
    private val userCategory: UserCategory
        get() = userCategoryProvider()

    private val detectors: List<PatternMatcher> = listOf(
        SextortionDetector(),
        FinancialScamDetector(),
        GroomingDetector(),
        RomanceScamDetector(),
        IdentityPhishingDetector(),
        LuringDetector(),
        HarassmentDetector(),
        HarmfulContentDetector(),
        AdultContentDetector()
    )

    /**
     * Score [message] — the protected person's own latest outgoing text,
     * unprefixed — with optional [context]: their own prior outgoing
     * messages, oldest first, also unprefixed. There is no [CONTACT] side to
     * pass here; this scorer only ever reasons about one side of a
     * conversation, structurally, not by omission.
     */
    fun score(message: String, context: List<String> = emptyList()): List<DetectionResult> {
        if (message.isBlank() || message.length < 10) return emptyList()

        @Suppress("NAME_SHADOWING")
        val text = keepNewest("[USER]: $message", MAX_INPUT_LENGTH)
        @Suppress("NAME_SHADOWING")
        val context = context.takeLast(MAX_CONTEXT_MESSAGES)
            .map { keepNewest("[USER]: $it", MAX_INPUT_LENGTH) }

        // Layer 1a: phrase detectors on latest message only
        val ruleResults: Map<HarmCategory, DetectionResult> =
            detectors.associate { it.category to it.analyze(text) }

        // Layer 1b: word lexicon — identical to RiskScorer, see its own comment.
        val wordBoosted: Map<HarmCategory, DetectionResult> = ruleResults.mapValues { (cat, result) ->
            val rawWordScore = WordLexicon.score(text, cat)
            val wordScore = if (
                cat == HarmCategory.HARASSMENT &&
                (userCategory == UserCategory.ADOLESCENT || userCategory == UserCategory.CHILD)
            ) rawWordScore * 0.4f else rawWordScore
            val unpromptedCredentialShare = cat == HarmCategory.IDENTITY_PHISHING &&
                result.signals.isNotEmpty() &&
                result.signals.all { it.signal == "credential_shared" }
            val boost = if (wordScore > 0f && !unpromptedCredentialShare) (wordScore * 0.5f).coerceAtMost(0.26f) else 0f
            val combined = (result.score + boost).coerceIn(0f, 1f)
            result.copy(score = combined, riskLevel = scoreToRiskLevel(combined))
        }

        // Location/address disclosure boost — identical to RiskScorer.
        val disclosureBoosted: Map<HarmCategory, DetectionResult> = if (
            (userCategory == UserCategory.CHILD || userCategory == UserCategory.ADOLESCENT) &&
            containsUserAddressDisclosure(text)
        ) {
            wordBoosted.mapValues { (cat, result) ->
                if (cat != HarmCategory.GROOMING && cat != HarmCategory.LURING) return@mapValues result
                val boosted = (result.score + 0.40f).coerceAtLeast(0.70f).coerceIn(0f, 1f)
                result.copy(
                    score     = boosted,
                    riskLevel = scoreToRiskLevel(boosted),
                    signals   = result.signals + SignalMatch(
                        signal        = "location_disclosure",
                        matchedPhrase = "Minor sharing address or location",
                        weight        = 0.80f
                    )
                )
            }
        } else {
            wordBoosted
        }

        // Context escalation (mild — cannot create new alerts) — identical to RiskScorer.
        val contextResults: Map<HarmCategory, DetectionResult> = if (context.isEmpty()) emptyMap()
        else {
            val ctxText = context.joinToString("\n")
            detectors.associate { it.category to it.analyze(ctxText) }
        }

        val escalated: Map<HarmCategory, DetectionResult> = disclosureBoosted.mapValues { (cat, result) ->
            if (result.riskLevel == RiskLevel.NONE) return@mapValues result
            val ctxBoost = ((contextResults[cat]?.score ?: 0f) * 0.2f).coerceAtMost(0.15f)
            val s = (result.score + ctxBoost).coerceIn(0f, 1f)
            result.copy(score = s, riskLevel = scoreToRiskLevel(s))
        }

        // OTP handed over across windows — identical to RiskScorer.
        val ctxCodeRequest = contextResults[HarmCategory.IDENTITY_PHISHING]
            ?.signals?.any { it.signal == "code_request" } == true
        val otpEscalated: Map<HarmCategory, DetectionResult> =
            if (!ctxCodeRequest || !userSharesBareCode(text)) escalated
            else escalated.mapValues { (cat, result) ->
                if (cat != HarmCategory.IDENTITY_PHISHING) return@mapValues result
                if (result.signals.any { it.signal == "otp_shared" }) return@mapValues result
                val boosted = maxOf(result.score, 0.87f)
                result.copy(
                    score       = boosted,
                    riskLevel   = scoreToRiskLevel(boosted),
                    signals     = result.signals + SignalMatch(
                        signal        = "otp_shared",
                        matchedPhrase = "One-time passcode shared after a code request",
                        weight        = 0.87f
                    ),
                    explanation = "A one-time passcode (OTP) was shared after the contact asked for it. " +
                                  "Legitimate services never ask anyone to share an OTP — sharing one can " +
                                  "let a scammer take over accounts or approve payments."
                )
            }

        // ADULT_CONTENT/HARMFUL_CONTENT are CHILD/ADOLESCENT-specific by
        // design (an adult account searching for adult content isn't a
        // safety concern) and their detectors already return a blunt
        // NONE-or-HIGH result on any match — this step is purely the
        // per-age-band policy on top of that: suppressed entirely for adult
        // accounts, HARMFUL_CONTENT stays HIGH for both CHILD and
        // ADOLESCENT, ADULT_CONTENT stays HIGH for CHILD but is capped to
        // MEDIUM (local warning, no guardian email) for ADOLESCENT. Placed
        // after every step that recomputes riskLevel from score via the
        // age-band-aware scoreToRiskLevel (escalated/otpEscalated above) —
        // doing this earlier let a later recompute silently erase the
        // explicit MEDIUM override, since 0.30 doesn't clear ADOLESCENT's
        // own medium threshold (0.65) even though it's well above the flat
        // 0.28 the detector's own internal scoreToRiskLevel uses. Confirmed
        // via NewContentCategoriesScorerTest failing exactly this way.
        val ageGatedNewCategories: Map<HarmCategory, DetectionResult> = otpEscalated.mapValues { (cat, result) ->
            if (cat != HarmCategory.ADULT_CONTENT && cat != HarmCategory.HARMFUL_CONTENT) return@mapValues result
            if (result.riskLevel == RiskLevel.NONE) return@mapValues result
            when (userCategory) {
                UserCategory.SELF_PROTECTING_ADULT, UserCategory.VULNERABLE_ADULT ->
                    result.copy(riskLevel = RiskLevel.NONE, score = 0f)
                UserCategory.ADOLESCENT ->
                    if (cat == HarmCategory.ADULT_CONTENT) result.copy(riskLevel = RiskLevel.MEDIUM, score = 0.30f)
                    else result
                UserCategory.CHILD -> result
            }
        }

        // A CHILD or ADOLESCENT agreeing to send money is floored on the
        // rules signal alone — never gated behind the classifier, which has
        // been observed to return a blank/degenerate response on-device for
        // this exact kind of message. CHILD floors all the way to HIGH
        // (triggers the guardian email — a parent should hear about this
        // regardless of what the classifier says) since under-alerting a
        // child actually agreeing to send money is worse than the rare false
        // positive from the regex-based money_send_compliance signal.
        // ADOLESCENT floors only to MEDIUM (local warning, no guardian
        // email) — same reasoning as every other CHILD-vs-ADOLESCENT split
        // in mergeClassifierResult below, just applied to the rules layer.
        val childMoneyFloored: Map<HarmCategory, DetectionResult> =
            when (userCategory) {
                UserCategory.CHILD, UserCategory.ADOLESCENT -> ageGatedNewCategories.mapValues { (cat, result) ->
                    if (cat != HarmCategory.FINANCIAL_SCAM) return@mapValues result
                    if (result.signals.none { it.signal == "money_send_compliance" }) return@mapValues result
                    val floor = if (userCategory == UserCategory.CHILD) RiskLevel.HIGH else RiskLevel.MEDIUM
                    val floorScore = if (userCategory == UserCategory.CHILD) 0.85f else 0.30f
                    if (result.riskLevel >= floor) result
                    else result.copy(riskLevel = floor, score = maxOf(result.score, floorScore))
                }
                else -> ageGatedNewCategories
            }

        // Layer 2: single classifier multi-class inference — identical to RiskScorer.
        val ageHint: String? = when (userCategory) {
            UserCategory.CHILD      -> "child under 13 years old; being a child does NOT by itself make a message suspicious — ordinary messages about school, activities, hobbies, games, schedules, or caretaking (e.g. mentioning a sport, a plan, or a time) are normal and NOT evidence of grooming or any other harm on their own. Only flag if the message itself contains a specific coercive demand (secrecy, images, money, credentials) or expresses fear/distress in response to pressure — not merely because a shared activity or interest is mentioned"
            UserCategory.ADOLESCENT -> "adolescent aged 13 to 17; note that casual profanity and hyperbolic language (e.g. 'this kills', 'I'll destroy you at the game') are developmentally normal for this age group and should not alone be treated as harassment — only flag if there are specific targeting signals such as explicit threats, doxxing, or coercive control"
            else                    -> null
        }
        val classifierResult: Pair<HarmCategory, RiskLevel>? = if (classifier.isLoaded) {
            classifier.classify(text, context, ageHint)
        } else {
            null
        }

        // Merge classifier result into rule results — NO direction guard here.
        // See this class's own header comment for why: every window scored by
        // this class is outgoing-only by construction, so the guard's premise
        // ("no [CONTACT] line = suspicious") never applies — it would just
        // discard every non-HARASSMENT classifier verdict, always.
        val merged: Map<HarmCategory, DetectionResult> = if (classifierResult == null) {
            childMoneyFloored
        } else {
            val (classifierCat, classifierSeverity) = classifierResult
            childMoneyFloored.mapValues { (cat, result) ->
                if (cat != classifierCat) return@mapValues result
                mergeClassifierResult(result, classifierSeverity)
            }
        }

        // Post-classifier context escalation — identical to RiskScorer, minus
        // the "held at NONE by the direction guard" carve-out (no such guard
        // exists here to have held anything at NONE).
        val finalResults: Map<HarmCategory, DetectionResult> = if (
            classifierResult == null || classifierResult.second != RiskLevel.HIGH
        ) {
            merged
        } else {
            val classifierCat = classifierResult.first
            val isVulnerable = userCategory != UserCategory.SELF_PROTECTING_ADULT
            merged.mapValues { (cat, result) ->
                if (cat != classifierCat) return@mapValues result
                val ctxScore = contextResults[cat]?.score ?: 0f
                if (ctxScore <= 0f) return@mapValues result
                val ctxAlreadyHigh = contextResults[cat]?.riskLevel == RiskLevel.HIGH
                if (!isVulnerable) {
                    return@mapValues if (ctxAlreadyHigh) result.copy(suppressGuardianAlert = true) else result
                }
                result.copy(
                    riskLevel = RiskLevel.HIGH,
                    score = maxOf(result.score, 0.87f),
                    signals = result.signals + SignalMatch(
                        signal       = "ai_context_pattern",
                        matchedPhrase = "Cross-message behavioural pattern",
                        weight       = 0.87f
                    ),
                    suppressGuardianAlert = ctxAlreadyHigh
                )
            }
        }

        return finalResults.values.filter { it.riskLevel != RiskLevel.NONE }
    }

    /**
     * Cheap, rules-only check: did any detector match at least one phrase or
     * word signal for [message], regardless of whether it cleared the
     * age-band threshold? Deliberately separate from [score] rather than
     * changing what that method returns — [score]'s empty-result contract is
     * what triggers the `[ProtectedPersonSignals]` fallback in
     * `AgentHitaSafety.scoreResponseOnly` on iOS, and folding sub-threshold
     * signals into [score]'s return value would silently suppress that
     * fallback for texts that only ever produced a trivial, unrelated
     * sub-threshold match — a real coverage regression, not just a filter
     * tweak. This method exists purely so a caller on the live-typing path
     * can decide whether a sub-threshold rule match is worth a second,
     * classifier-corroborated pass (see `ProtectionMonitor.analyze` on iOS),
     * without touching [score]'s existing behaviour at all.
     */
    fun hasAnyRuleSignal(message: String): Boolean {
        if (message.isBlank() || message.length < 10) return false
        val text = keepNewest("[USER]: $message", MAX_INPUT_LENGTH)
        return detectors.any { it.analyze(text).signals.isNotEmpty() }
    }

    /** Duplicated verbatim from RiskScorer — see this file's header comment. */
    private fun mergeClassifierResult(ruleResult: DetectionResult, classifierSeverity: RiskLevel): DetectionResult {
        val ruleLevel = ruleResult.riskLevel
        val isVulnerable = userCategory != UserCategory.SELF_PROTECTING_ADULT
        return when {
            classifierSeverity == RiskLevel.NONE                               -> ruleResult
            // Both new branches below are guarded by `ruleLevel != HIGH` —
            // when rules alone already reached HIGH (e.g. a combo-bonus-
            // driven score well above the age band's HIGH cutoff), that
            // result must never be touched here regardless of what the
            // classifier says, same as the pre-existing `else -> ruleResult`
            // fallback already does for every other ruleLevel==HIGH case.
            // Omitting this guard downgraded an already-correct rules-only
            // HIGH result to MEDIUM whenever the classifier also happened to
            // agree it was HIGH — confirmed via AgentHitaKeyboardAdolescentUITests'
            // own HIGH-severity suite, hand-tuned to reach HIGH from rules
            // alone with no classifier involvement needed.
            //
            // For CHILD specifically, a HIGH classifier verdict is trusted on
            // its own — even when rules found nothing at all (ruleLevel ==
            // NONE, ruleResult.signals empty). This deliberately removes the
            // hallucination-guard ceiling every other branch below still
            // enforces (rules-NONE + classifier-HIGH capped at MEDIUM) for
            // this one category, on the reasoning that under-alerting on a
            // genuine HIGH read for a child is worse than the classifier's
            // occasional false positive. NOT extended to ADOLESCENT or
            // VULNERABLE_ADULT — scoped to CHILD only, deliberately.
            userCategory == UserCategory.CHILD && ruleLevel != RiskLevel.HIGH && classifierSeverity == RiskLevel.HIGH ->
                ruleResult.copy(
                    riskLevel   = RiskLevel.HIGH,
                    score       = maxOf(ruleResult.score, 0.85f),
                    signals     = ruleResult.signals.ifEmpty { listOf(SignalMatch("ai_analysis", "AI-detected behavioural pattern", 0.85f)) },
                    explanation = "Detected by AI analysis — behavioural patterns in this conversation are consistent with ${ruleResult.category.name.lowercase().replace('_', ' ')}."
                )
            // Everyone else (ADOLESCENT, SELF_PROTECTING_ADULT,
            // VULNERABLE_ADULT) gets the same middle tier: a HIGH classifier
            // verdict is still trusted (never silently dropped), but caps at
            // MEDIUM rather than HIGH regardless of ruleLevel (short of
            // ruleLevel already being HIGH — see the guard note above) —
            // deliberately below CHILD's unconditional promotion to HIGH
            // above. Teen and adult are intentionally treated the same here
            // — only CHILD is privileged to jump straight to HIGH from the
            // classifier alone. This also caps what would otherwise reach
            // HIGH via the ruleLevel==LOW/MEDIUM branches further below for
            // every category but CHILD; placed before those branches so it
            // takes precedence.
            userCategory != UserCategory.CHILD && ruleLevel != RiskLevel.HIGH && classifierSeverity == RiskLevel.HIGH ->
                ruleResult.copy(
                    riskLevel   = RiskLevel.MEDIUM,
                    score       = maxOf(ruleResult.score, 0.65f),
                    signals     = ruleResult.signals.ifEmpty { listOf(SignalMatch("ai_analysis", "AI-detected behavioural pattern", 0.65f)) },
                    explanation = "Detected by AI analysis — behavioural patterns in this conversation are consistent with ${ruleResult.category.name.lowercase().replace('_', ' ')}."
                )
            ruleLevel == RiskLevel.NONE && classifierSeverity == RiskLevel.MEDIUM && isVulnerable ->
                ruleResult.copy(
                    riskLevel   = RiskLevel.MEDIUM,
                    score       = 0.65f,
                    signals     = listOf(SignalMatch("ai_analysis", "AI-detected behavioural pattern", 0.65f)),
                    explanation = "Detected by AI analysis — behavioural patterns in this conversation are consistent with ${ruleResult.category.name.lowercase().replace('_', ' ')}."
                )
            ruleLevel == RiskLevel.NONE && classifierSeverity == RiskLevel.HIGH ->
                ruleResult.copy(
                    riskLevel   = RiskLevel.MEDIUM,
                    score       = 0.65f,
                    signals     = listOf(SignalMatch("ai_analysis", "AI-detected behavioural pattern", 0.65f)),
                    explanation = "Detected by AI analysis — behavioural patterns in this conversation are consistent with ${ruleResult.category.name.lowercase().replace('_', ' ')}."
                )
            ruleLevel == RiskLevel.LOW  && classifierSeverity == RiskLevel.MEDIUM ->
                ruleResult.copy(riskLevel = RiskLevel.MEDIUM, score = 0.65f,
                    signals = ruleResult.signals.ifEmpty { listOf(SignalMatch("ai_analysis", "AI-detected behavioural pattern", 0.65f)) })
            ruleLevel == RiskLevel.LOW  && classifierSeverity == RiskLevel.HIGH ->
                ruleResult.copy(riskLevel = RiskLevel.HIGH,   score = 0.82f,
                    signals = ruleResult.signals.ifEmpty { listOf(SignalMatch("ai_analysis", "AI-detected behavioural pattern", 0.82f)) })
            ruleLevel == RiskLevel.MEDIUM && classifierSeverity == RiskLevel.HIGH ->
                ruleResult.copy(riskLevel = RiskLevel.HIGH,   score = 0.83f)
            else                                                          -> ruleResult
        }
    }

    /** Returns the single highest-risk result from a scored set. */
    fun highestRisk(results: List<DetectionResult>): DetectionResult? =
        results.maxByOrNull { it.score }

    /** Duplicated verbatim from RiskScorer — see this file's header comment. */
    private fun userSharesBareCode(text: String): Boolean {
        val codeRegex = Regex("""\b\d{3}[-\s]\d{3}\b|\b\d{4,8}\b""")
        val benignCodeContexts = listOf(
            "pin code", "pincode", "postal code", "zip code", "area code",
            "promo code", "coupon code", "discount code", "referral code",
            "tracking", "order number"
        )
        return text.lines().any { line ->
            val trimmed = line.trimStart()
            if (!trimmed.startsWith("[USER]:", ignoreCase = true)) return@any false
            val body = trimmed.substring("[USER]:".length).trim().lowercase()
            body.length <= 24 &&
                codeRegex.containsMatchIn(body) &&
                benignCodeContexts.none { body.contains(it) }
        }
    }

    /** Duplicated verbatim from RiskScorer — see this file's header comment. */
    private fun containsUserAddressDisclosure(text: String): Boolean {
        val userText = text.lines()
            .filter { it.trimStart().startsWith("[USER]:", ignoreCase = true) }
            .joinToString(" ")
            .lowercase()
        if (userText.isBlank()) return false

        val locationPhrases = listOf(
            "i live at", "my address is", "my house is at",
            "i stay at", "we live at", "my home is at",
            "come to my house", "come to my place", "come to my home",
            "my place is at", "here's my address", "here is my address",
            "my home address is", "my location is"
        )
        if (locationPhrases.any { userText.contains(it) }) return true

        val streetAddress = Regex(
            """\b\d+\s+\w[\w\s]{0,30}(street|avenue|road|boulevard|lane|drive|court|way|place|circle|terrace|\bst\b|\bave\b|\brd\b|\bblvd\b|\bln\b|\bdr\b|\bct\b|\bpl\b)"""
        )
        return streetAddress.containsMatchIn(userText)
    }

    /** Duplicated verbatim from RiskScorer — see this file's header comment. */
    private fun scoreToRiskLevel(score: Float): RiskLevel {
        val t = riskThresholdsProvider()
        val band = when (userCategory) {
            UserCategory.CHILD            -> t.child
            UserCategory.ADOLESCENT       -> t.adolescent
            UserCategory.VULNERABLE_ADULT -> t.vulnerableAdult
            else                          -> t.adult
        }
        return when {
            score >= band.high   -> RiskLevel.HIGH
            score >= band.medium -> RiskLevel.MEDIUM
            score >= band.low    -> RiskLevel.LOW
            else                 -> RiskLevel.NONE
        }
    }

    companion object {
        private const val MAX_INPUT_LENGTH = 50_000
        private const val MAX_CONTEXT_MESSAGES = 200

        /** Duplicated verbatim from RiskScorer — see this file's header comment. */
        private fun keepNewest(text: String, maxLength: Int): String {
            if (text.length <= maxLength) return text
            val tail = text.takeLast(maxLength)
            val newlineIndex = tail.indexOf('\n')
            return if (newlineIndex in 0 until tail.length - 40) tail.substring(newlineIndex + 1) else tail
        }
    }
}
