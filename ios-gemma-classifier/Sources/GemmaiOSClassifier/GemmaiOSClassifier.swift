// GemmaiOSClassifier.swift
//
// iOS counterpart to GemmaAndroidClassifier (android-gemma-classifier module),
// using Google's LiteRT-LM Swift API rather than MediaPipe — MediaPipe's LLM
// Inference API is in maintenance-only mode and Google recommends LiteRT-LM for
// new iOS work (see https://developers.google.com/edge/litert-lm/swift).
//
// IMPORTANT — verification status, read before using:
// The classification logic here (prompt template, response parsing, sampling
// config) is a direct Swift port of GemmaAndroidClassifier's logic and should be
// correct. The LiteRT-LM API calls below (EngineConfig/Engine/Conversation) are
// transcribed from Google's own published Swift API docs, not verified against
// a real compile — there is no Xcode toolchain in the environment this was
// written in, only Command Line Tools, so this file has never been built.
// Before relying on it: add the LiteRT-LM Swift package (File > Add Package
// Dependencies > https://github.com/google-ai-edge/LiteRT-LM in Xcode), build
// this file, and fix any API drift against whatever LiteRT-LM version you add.
//
// Conforming this class to the SDK's `Classifier` Kotlin interface (so it can
// be handed directly to a Kotlin `RiskScorer` running inside a KMP-consuming
// iOS app) is a deliberately separate, follow-up step. Kotlin/Native exports
// Kotlin interfaces to Objective-C/Swift with generated names and generic-type
// bridging (e.g. Pair<HarmCategory, RiskLevel>? does not map to a plain Swift
// tuple) that can only be pinned down by inspecting the actual generated
// `HitaSafetySDK.framework` header on a machine that has built it — guessing at
// that bridging syntax here would be more likely to mislead than help. This
// class's `classify` method uses plain Swift types for that reason; wiring it
// to the exported Kotlin protocol is expected to be a thin adapter once that
// header exists.

import Foundation
import LiteRTLM

public enum HarmCategory: String {
    case sextortion = "SEXTORTION"
    case financialScam = "FINANCIAL_SCAM"
    case grooming = "GROOMING"
    case romanceScam = "ROMANCE_SCAM"
    case identityPhishing = "IDENTITY_PHISHING"
    case luring = "LURING"
    case harassment = "HARASSMENT"
    case disappearingMessages = "DISAPPEARING_MESSAGES"
}

public enum RiskLevel: Int, Comparable {
    case none = 0, low = 1, medium = 2, high = 3
    public static func < (lhs: RiskLevel, rhs: RiskLevel) -> Bool { lhs.rawValue < rhs.rawValue }
}

public struct GemmaClassifierConfig {
    public var maxTokens: Int
    public var topK: Int
    public var temperature: Float
    public var inputTruncationChars: Int
    public var contextMessages: Int
    public var contextMessageLength: Int

    public init(
        maxTokens: Int = 512,
        topK: Int = 5,
        temperature: Float = 0.2,
        inputTruncationChars: Int = 300,
        contextMessages: Int = 5,
        contextMessageLength: Int = 80
    ) {
        self.maxTokens = maxTokens
        self.topK = topK
        self.temperature = temperature
        self.inputTruncationChars = inputTruncationChars
        self.contextMessages = contextMessages
        self.contextMessageLength = contextMessageLength
    }
}

/// "Batteries-included" classifier: give it a path to an already-downloaded,
/// already-verified Gemma model file and it handles prompt building,
/// constrained-sampling inference, and response parsing.
///
/// Deliberately out of scope, same as GemmaAndroidClassifier: finding/
/// downloading the model file and verifying its integrity are left to the
/// host app.
public final class GemmaiOSClassifier {

    private let config: GemmaClassifierConfig
    private var engine: Engine?
    private var conversation: Conversation?
    private var loadFailed = false

    public var isLoaded: Bool { engine != nil && conversation != nil }

    public init(modelPath: String, config: GemmaClassifierConfig = GemmaClassifierConfig()) {
        self.config = config
    }

    /// Must be called once before `classify` — LiteRT-LM's Engine/Conversation
    /// setup is async, unlike MediaPipe's synchronous `createFromOptions` on
    /// Android, so loading can't happen inside a plain `init`.
    public func load(modelPath: String) async {
        do {
            let engineConfig = try EngineConfig(
                modelPath: modelPath,
                backend: .cpu(),
                maxNumTokens: config.maxTokens,
                cacheDir: NSTemporaryDirectory()
            )
            let engine = Engine(engineConfig: engineConfig)
            try await engine.initialize()
            let samplerConfig = try SamplerConfig(
                topK: config.topK,
                topP: 1.0,
                temperature: config.temperature
            )
            self.conversation = try await engine.createConversation(with: samplerConfig)
            self.engine = engine
        } catch {
            loadFailed = true
            print("GemmaiOSClassifier: failed to load model at \(modelPath): \(error)")
        }
    }

    /// Single multi-class inference: identifies the most likely harm category
    /// and severity in one call. Returns nil if the model is not loaded, the
    /// message is safe, or the response cannot be parsed.
    public func classify(text: String, context: [String], ageHint: String?) async -> (HarmCategory, RiskLevel)? {
        guard let conversation = conversation else { return nil }
        let prompt = Self.buildFittedPrompt(text: text, context: context, ageHint: ageHint, config: config)
        do {
            let response = try await conversation.sendMessage(Message(prompt))
            return Self.parseMultiClassResponse(response.toString.uppercased())
        } catch {
            print("GemmaiOSClassifier: inference error: \(error)")
            return nil
        }
    }

    // MARK: - Prompt building (ported verbatim from GemmaAndroidClassifier)

    /// Builds a prompt guaranteed to fit the model's token window. Long
    /// conversations lose their OLDEST content first — context lines are shed
    /// one at a time, then the message block is trimmed from the front —
    /// because coercion escalates toward the end of a window ("send money now"
    /// is at the recent edge; the opener is what we can afford to lose).
    static func buildFittedPrompt(text: String, context: [String], ageHint: String?, config: GemmaClassifierConfig) -> String {
        let maxChars = (config.maxTokens - 50) * 3
        var ctx = context
        var prompt = buildMultiClassPrompt(text: text, context: ctx, ageHint: ageHint, config: config)
        while prompt.count > maxChars && !ctx.isEmpty {
            ctx.removeFirst()
            prompt = buildMultiClassPrompt(text: text, context: ctx, ageHint: ageHint, config: config)
        }
        if prompt.count > maxChars {
            let overhead = buildMultiClassPrompt(text: "", context: ctx, ageHint: ageHint, config: config).count
            let budget = max(maxChars - overhead, 160)
            prompt = buildMultiClassPrompt(text: keepNewest(text, budget: budget), context: ctx, ageHint: ageHint, config: config)
        }
        return prompt
    }

    /// Last `budget` characters of `text`, dropped forward to the next full
    /// line where possible.
    static func keepNewest(_ text: String, budget: Int) -> String {
        guard text.count > budget else { return text }
        let tail = String(text.suffix(budget))
        if let newlineIndex = tail.firstIndex(of: "\n") {
            let distanceFromEnd = tail.distance(from: newlineIndex, to: tail.endIndex)
            if distanceFromEnd > 40 {
                return String(tail[tail.index(after: newlineIndex)...])
            }
        }
        return tail
    }

    /// ONE template for every model — mirrors GemmaAndroidClassifier's template
    /// exactly. Do not reword without re-running the on-device probe set (false
    /// positives AND canonical attack scripts) on every supported model; see
    /// AgentHitaAndroid's docs/DETECTION_DECISIONS.md for why this wording is
    /// this specific and this fragile.
    static func buildMultiClassPrompt(text: String, context: [String] = [], ageHint: String? = nil, config: GemmaClassifierConfig = GemmaClassifierConfig()) -> String {
        let truncated = keepNewest(text, budget: config.inputTruncationChars)
        let recipientLine = ageHint.map { "\nRecipient: \($0)" } ?? ""
        let contextBlock: String
        if context.isEmpty {
            contextBlock = ""
        } else {
            let prior = context.suffix(3).map { "- \"\($0.prefix(60))\"" }.joined(separator: "\n")
            contextBlock = "\nPrior messages in conversation:\n\(prior)"
        }
        return """
        Identify the harm in this message. Fill in the blanks below.

        Valid harm types: SEXTORTION FINANCIAL_SCAM GROOMING ROMANCE_SCAM IDENTITY_PHISHING LURING HARASSMENT NONE
        Valid severity levels: HIGH MEDIUM LOW NONE
        Messages: [CONTACT]=incoming, [USER]=outgoing. The threat actor is [CONTACT]; [USER] messages showing distress, compliance, or fear are evidence of harm, not its source. For HARASSMENT, flag threats or abuse in either direction.
        IDENTITY_PHISHING: [CONTACT] requesting credentials or info, or [USER] sending an OTP to the contact = HIGH. Automated OTP delivery or bank transaction alerts to the user = NONE. For child/adolescent recipients, [USER] sharing an address or location = GROOMING or LURING; only a phone number = NONE. Other [USER] self-shared info = NONE.
        IMPORTANT: Messages may mix English with other languages written in Latin letters (e.g. romanised Hindi, Urdu, Turkish). Ignore any non-English words and analyse only the English words present. If there are no English words, respond with Harm type: NONE and Severity: NONE.
        Casual slang alone isn't harm — flag only real threats, coercion, or money/image/credential requests.
        \(recipientLine)\(contextBlock)
        Latest message: "\(truncated)"

        Harm type:
        Severity:
        """
    }

    // MARK: - Response parsing (ported verbatim from GemmaAndroidClassifier)

    private static let categoryTokens: [String: HarmCategory] = [
        "SEXTORTION": .sextortion,
        "FINANCIAL_SCAM": .financialScam,
        "GROOMING": .grooming,
        "ROMANCE_SCAM": .romanceScam,
        "ROMANCE": .romanceScam,
        "IDENTITY_PHISHING": .identityPhishing,
        "PHISHING": .identityPhishing,
        "LURING": .luring,
        "HARASSMENT": .harassment
    ]

    /// Token-scanning parser — does NOT rely on the model following a strict
    /// format. Expects the UPPERCASED response. Strategy: strip non-alphanumeric
    /// chars, tokenise, anchor after the last "HARM TYPE" / "SEVERITY" labels,
    /// then scan for the FIRST verdict token — where an explicit NONE terminates
    /// the scan (a rambling safe answer containing the word "PHISHING" elsewhere
    /// must not manufacture an alert).
    static func parseMultiClassResponse(_ response: String) -> (HarmCategory, RiskLevel)? {
        let normalized = response.replacingOccurrences(of: "[^A-Z0-9_\\s]", with: " ", options: .regularExpression)
        let tokens = normalized.split(whereSeparator: { $0.isWhitespace }).map(String.init)

        var harmTypeIdx = 0
        for i in tokens.indices {
            if tokens[i] == "HARM" && i + 1 < tokens.count && tokens[i + 1] == "TYPE" {
                harmTypeIdx = i + 2
            }
        }

        let categoryToken = tokens[harmTypeIdx...].first { $0 == "NONE" || categoryTokens[$0] != nil }
        let category: HarmCategory
        switch categoryToken {
        case nil, "NONE":
            return nil
        case let token?:
            category = categoryTokens[token]!
        }

        var severityIdx = 0
        for i in tokens.indices where tokens[i] == "SEVERITY" {
            severityIdx = i + 1
        }
        let severityToken = tokens[severityIdx...].first { ["HIGH", "MEDIUM", "LOW", "NONE"].contains($0) }
        let severity: RiskLevel
        switch severityToken {
        case "HIGH": severity = .high
        case "MEDIUM": severity = .medium
        case "LOW": severity = .low
        case "NONE": return nil
        default: severity = .medium
        }

        return (category, severity)
    }

    public func close() {
        conversation = nil
        engine = nil
    }
}
