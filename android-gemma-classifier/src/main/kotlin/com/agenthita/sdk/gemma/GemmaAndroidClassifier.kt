package com.agenthita.sdk.gemma

import android.content.Context
import com.agenthita.sdk.detection.Classifier
import com.agenthita.sdk.detection.HarmCategory
import com.agenthita.sdk.detection.RiskLevel
import com.google.mediapipe.tasks.genai.llminference.LlmInference
import com.google.mediapipe.tasks.genai.llminference.LlmInferenceSession
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Sampling/prompt-shaping configuration for [GemmaAndroidClassifier]. Defaults
 * match the values validated in AgentHitaAndroid's on-device probe suite —
 * see that repo's docs/DETECTION_DECISIONS.md decisions #8 and #9 for why
 * these specific values (especially topK/temperature) matter: default
 * MediaPipe sampling let the model echo the prompt instead of classifying.
 */
data class GemmaClassifierConfig(
    val maxTokens: Int = 512,
    val topK: Int = 5,
    val temperature: Float = 0.2f,
    val inputTruncationChars: Int = 300,
    val contextMessages: Int = 5,
    val contextMessageLength: Int = 80
)

/**
 * "Batteries-included" [Classifier] implementation: give it a path to an
 * already-downloaded, already-verified Gemma model file and a running
 * [LlmInference] session, and it handles prompt building, constrained-sampling
 * inference, and response parsing.
 *
 * Deliberately out of scope, and left to the host app: finding/downloading the
 * model file, verifying its integrity (e.g. a SHA-256 allow-list), and staging
 * it into readable storage. Those are host-app/device-storage concerns, not
 * classification concerns — see AgentHitaAndroid's own GemmaClassifier for a
 * worked example of that discovery logic, which callers can adapt or replace
 * with e.g. a bundled model or a simple asset copy.
 *
 * [context] is required only because MediaPipe's `LlmInference.createFromOptions`
 * needs an Android Context — nothing else here touches Context, storage, or
 * any Android API beyond that single call.
 */
class GemmaAndroidClassifier(
    context: Context,
    modelPath: String,
    private val config: GemmaClassifierConfig = GemmaClassifierConfig()
) : Classifier {

    private var llm: LlmInference? = null

    override val isLoaded: Boolean get() = llm != null

    /** True when a model file was found but MediaPipe failed to initialise it. */
    var loadFailed: Boolean = false
        private set

    // LlmInference is not thread-safe — a non-blocking trylock means a concurrent
    // caller skips inference rather than racing on the native session (which
    // otherwise risks a native crash, not just a wrong answer).
    private val inferenceInProgress = AtomicBoolean(false)

    // Single-entry cache — avoids re-running inference for back-to-back calls
    // with identical inputs.
    private var cacheKey: Triple<String, List<String>, String?> = Triple("", emptyList(), null)
    private var cacheVal: Pair<HarmCategory, RiskLevel>? = null

    init {
        try {
            val options = LlmInference.LlmInferenceOptions.builder()
                .setModelPath(modelPath)
                .setMaxTokens(config.maxTokens)
                .setPreferredBackend(LlmInference.Backend.CPU)
                .build()
            llm = LlmInference.createFromOptions(context, options)
        } catch (e: Throwable) {
            loadFailed = true
            android.util.Log.w("GemmaAndroidClassifier", "Failed to load Gemma from $modelPath (${e.javaClass.simpleName}): ${e.message}")
        }
    }

    /**
     * Single multi-class inference: identifies the most likely harm category and
     * severity in one call. Returns null if the model is not loaded, the message
     * is safe, or the response cannot be parsed.
     */
    override fun classify(text: String, context: List<String>, ageHint: String?): Pair<HarmCategory, RiskLevel>? {
        val inference = llm ?: return null
        val key = Triple(text, context, ageHint)
        if (key == cacheKey) return cacheVal
        return try {
            val prompt = buildFittedPrompt(text, context, ageHint, config)
            if (!inferenceInProgress.compareAndSet(false, true)) {
                android.util.Log.d("GemmaAndroidClassifier", "Inference already in progress, skipping concurrent call")
                return null
            }
            try {
                val sessionOptions = LlmInferenceSession.LlmInferenceSessionOptions.builder()
                    .setTopK(config.topK)
                    .setTemperature(config.temperature)
                    .build()
                val session = LlmInferenceSession.createFromOptions(inference, sessionOptions)
                val response = try {
                    session.addQueryChunk(prompt)
                    session.generateResponse().trim().uppercase()
                } finally {
                    session.close()
                }
                parseMultiClassResponse(response).also {
                    cacheKey = key
                    cacheVal = it
                }
            } finally {
                inferenceInProgress.set(false)
            }
        } catch (e: Exception) {
            android.util.Log.w("GemmaAndroidClassifier", "Multi-class inference error: ${e.message}")
            null
        }
    }

    /**
     * Generates a short human-readable analysis and safety recommendations for
     * a dashboard/alert-detail view. Returns null if the model is not loaded or
     * inference fails. Not part of the [Classifier] interface — an optional
     * extra a host app can call directly if it wants prose, not just a verdict.
     */
    fun generateAnalysis(
        lastMessage: String,
        context: List<String>,
        signals: List<String>,
        category: HarmCategory
    ): String? {
        val inference = llm ?: return null
        if (!inferenceInProgress.compareAndSet(false, true)) {
            android.util.Log.d("GemmaAndroidClassifier", "Inference busy, skipping analysis")
            return null
        }
        return try {
            val prompt = buildAnalysisPrompt(lastMessage, context, signals, category, config)
            val response = inference.generateResponse(prompt).trim()
            response.ifBlank { null }
        } catch (e: Exception) {
            android.util.Log.w("GemmaAndroidClassifier", "Analysis inference error: ${e.message}")
            null
        } finally {
            inferenceInProgress.set(false)
        }
    }

    fun close() {
        llm?.close()
        llm = null
    }

    companion object {

        /**
         * Builds a prompt guaranteed to fit the model's token window. Never skips:
         * long conversations lose their OLDEST content first — context lines are
         * shed one at a time, then the message block is trimmed from the front —
         * because coercion escalates toward the end of a window ("send money now"
         * is at the recent edge; the opener is what we can afford to lose).
         */
        internal fun buildFittedPrompt(
            text: String,
            context: List<String>,
            ageHint: String?,
            config: GemmaClassifierConfig
        ): String {
            // ~3 chars/token heuristic; reserve 50 tokens of the window for the response.
            val maxChars = (config.maxTokens - 50) * 3
            var ctx = context
            var prompt = buildMultiClassPrompt(text, ctx, ageHint, config)
            while (prompt.length > maxChars && ctx.isNotEmpty()) {
                ctx = ctx.drop(1)
                prompt = buildMultiClassPrompt(text, ctx, ageHint, config)
            }
            if (prompt.length > maxChars) {
                val overhead = buildMultiClassPrompt("", ctx, ageHint, config).length
                val budget = (maxChars - overhead).coerceAtLeast(160)
                prompt = buildMultiClassPrompt(keepNewest(text, budget), ctx, ageHint, config)
            }
            return prompt
        }

        /** Last [budget] chars of [text], dropped forward to the next full line where possible. */
        internal fun keepNewest(text: String, budget: Int): String {
            if (text.length <= budget) return text
            val tail = text.takeLast(budget)
            val nl = tail.indexOf('\n')
            return if (nl in 0 until tail.length - 40) tail.substring(nl + 1) else tail
        }

        /**
         * ONE template for every model. Do not reword without re-running the
         * on-device probe set — false-positive texts AND canonical attack scripts —
         * on every supported model. See AgentHitaAndroid's docs/DETECTION_DECISIONS.md
         * for why this wording is this specific and this fragile: a 2026-07-18
         * rewrite made the model echo the prompt instead of answering, and a live
         * sextortion test scored NONE as a result.
         */
        internal fun buildMultiClassPrompt(
            text: String,
            context: List<String> = emptyList(),
            ageHint: String? = null,
            config: GemmaClassifierConfig = GemmaClassifierConfig()
        ): String {
            val truncated = keepNewest(text, config.inputTruncationChars)
            val recipientLine = if (ageHint != null) "\nRecipient: $ageHint" else ""
            val contextBlock = if (context.isEmpty()) "" else {
                val prior = context.takeLast(3).joinToString("\n") { "- \"${it.take(60)}\"" }
                "\nPrior messages in conversation:\n$prior"
            }
            return """Identify the harm in this message. Fill in the blanks below.

Valid harm types: SEXTORTION FINANCIAL_SCAM GROOMING ROMANCE_SCAM IDENTITY_PHISHING LURING HARASSMENT NONE
Valid severity levels: HIGH MEDIUM LOW NONE
Messages: [CONTACT]=incoming, [USER]=outgoing. The threat actor is [CONTACT]; [USER] messages showing distress, compliance, or fear are evidence of harm, not its source. For HARASSMENT, flag threats or abuse in either direction.
IDENTITY_PHISHING: [CONTACT] requesting credentials or info, or [USER] sending an OTP to the contact = HIGH. Automated OTP delivery or bank transaction alerts to the user = NONE. For child/adolescent recipients, [USER] sharing an address or location = GROOMING or LURING; only a phone number = NONE. Other [USER] self-shared info = NONE.
IMPORTANT: Messages may mix English with other languages written in Latin letters (e.g. romanised Hindi, Urdu, Turkish). Ignore any non-English words and analyse only the English words present. If there are no English words, respond with Harm type: NONE and Severity: NONE.
Casual slang alone isn't harm — flag only real threats, coercion, or money/image/credential requests.
$recipientLine$contextBlock
Latest message: "$truncated"

Harm type:
Severity: """.trimIndent()
        }

        private val CATEGORY_TOKENS = mapOf(
            "SEXTORTION"        to HarmCategory.SEXTORTION,
            "FINANCIAL_SCAM"    to HarmCategory.FINANCIAL_SCAM,
            "GROOMING"          to HarmCategory.GROOMING,
            "ROMANCE_SCAM"      to HarmCategory.ROMANCE_SCAM,
            "ROMANCE"           to HarmCategory.ROMANCE_SCAM,
            "IDENTITY_PHISHING" to HarmCategory.IDENTITY_PHISHING,
            "PHISHING"          to HarmCategory.IDENTITY_PHISHING,
            "LURING"            to HarmCategory.LURING,
            "HARASSMENT"        to HarmCategory.HARASSMENT
        )

        /**
         * Token-scanning parser — does NOT rely on the model following a strict
         * format. Expects the UPPERCASED response (the call site uppercases before
         * parsing). Strategy: strip non-alphanumeric chars, tokenise, anchor after
         * the last "HARM TYPE" / "SEVERITY" labels, then scan for the FIRST verdict
         * token — where an explicit NONE terminates the scan (a rambling safe answer
         * containing the word "PHISHING" elsewhere must not manufacture an alert).
         */
        internal fun parseMultiClassResponse(response: String): Pair<HarmCategory, RiskLevel>? {
            val normalized = response.replace(Regex("[^A-Z0-9_\\s]"), " ")
            val tokens = normalized.split(Regex("\\s+")).filter { it.isNotBlank() }

            val harmTypeIdx = (tokens.indices).lastOrNull { i ->
                tokens[i] == "HARM" && tokens.getOrNull(i + 1) == "TYPE"
            }?.plus(2) ?: 0

            val categoryToken = tokens.drop(harmTypeIdx)
                .firstOrNull { it == "NONE" || it in CATEGORY_TOKENS }
            val category = when (categoryToken) {
                null, "NONE" -> return null
                else         -> CATEGORY_TOKENS.getValue(categoryToken)
            }

            val severityIdx = (tokens.indices).lastOrNull { i -> tokens[i] == "SEVERITY" }?.plus(1) ?: 0
            val severityToken = tokens.drop(severityIdx)
                .firstOrNull { it in setOf("HIGH", "MEDIUM", "LOW", "NONE") }
            val severity = when (severityToken) {
                "HIGH"   -> RiskLevel.HIGH
                "MEDIUM" -> RiskLevel.MEDIUM
                "LOW"    -> RiskLevel.LOW
                "NONE"   -> return null
                else     -> RiskLevel.MEDIUM
            }

            return Pair(category, severity)
        }

        private fun buildAnalysisPrompt(
            lastMessage: String,
            context: List<String>,
            signals: List<String>,
            category: HarmCategory,
            config: GemmaClassifierConfig
        ): String {
            val categoryLabel = when (category) {
                HarmCategory.SEXTORTION            -> "sexual manipulation / sextortion"
                HarmCategory.FINANCIAL_SCAM        -> "financial scam"
                HarmCategory.GROOMING              -> "predatory grooming"
                HarmCategory.ROMANCE_SCAM          -> "romance scam"
                HarmCategory.IDENTITY_PHISHING     -> "identity phishing"
                HarmCategory.LURING                -> "luring via fake offer"
                HarmCategory.HARASSMENT            -> "harassment or threats"
                HarmCategory.DISAPPEARING_MESSAGES -> "disappearing messages / secrecy signal"
            }
            val signalList = signals.take(5).joinToString(", ").ifEmpty { "none" }

            val conversationBlock = if (context.isEmpty()) {
                "Message: \"$lastMessage\""
            } else {
                val trimmedContext = context.takeLast(config.contextMessages)
                    .joinToString("\n") { "- \"${it.take(config.contextMessageLength)}\"" }
                "Previous messages:\n$trimmedContext\n\nLatest message: \"${lastMessage.take(config.contextMessageLength)}\""
            }

            return """You are a safety advisor helping someone who received a concerning message.
Category: $categoryLabel
Signals: $signalList
$conversationBlock

In 2-3 sentences, explain why this conversation is concerning. Then give exactly 2 safety tips starting with "Tip 1:" and "Tip 2:". Be clear and supportive.
IMPORTANT: Do NOT advise contacting, responding to, or engaging further with the sender. Do NOT suggest meeting or replying to them. Tips must focus on blocking, reporting, and seeking help.""".trimIndent()
        }
    }
}
