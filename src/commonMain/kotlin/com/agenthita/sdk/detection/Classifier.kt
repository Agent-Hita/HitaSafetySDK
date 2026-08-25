package com.agenthita.sdk.detection

/**
 * Minimal interface over an on-device ML classifier consumed by [RiskScorer].
 *
 * The SDK ships no concrete implementation — each host platform supplies its
 * own, backed by whatever on-device LLM runtime it uses (e.g. MediaPipe LLM
 * Inference / LiteRT-LM on Android, LiteRT-LM's native Swift API on iOS).
 * This keeps the SDK's common code free of any platform-specific ML runtime
 * dependency, and lets [RiskScorer] be unit-tested with a pure-Kotlin fake.
 */
interface Classifier {
    val isLoaded: Boolean
    fun classify(text: String, context: List<String>, ageHint: String?): Pair<HarmCategory, RiskLevel>?
}
