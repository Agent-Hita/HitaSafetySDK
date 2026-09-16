# Hita Safety SDK

**On-device conversation-risk detection, as a portable Kotlin Multiplatform library.**

This SDK is the detection engine that powers [Agent Hita](https://github.com/Agent-Hita/AgentHitaAndroid),
extracted so a host application — Agent Hita's own Android app, an iOS app, or a
third-party platform integrating it directly — can run the same rule-based +
on-device-classifier pipeline over conversation text it already has, entirely
on-device, and get back a scored risk assessment.

The SDK never reads messages itself, never performs network I/O, and never
decides what to do with a result. It scores text you hand it and returns a
result; what a host app does with that result — a local warning, a guardian
alert, blocking a conversation — is a decision the host app owns.

## What it detects

Eight harm categories, each backed by phrase-pattern detectors plus an
order-independent word lexicon:

- Grooming
- Sextortion
- Financial scams
- Romance scams
- Identity phishing
- Luring
- Harassment / coercive control
- Disappearing-message / secrecy activation

Detection is two-layer: fast, explainable rule matching runs first and always;
an on-device ML classifier (supplied by the host platform — see below) can
rescue signal the rules miss, but a pure-classifier verdict is deliberately
capped so it can never manufacture a high-severity alert without some rule
corroboration.

## Platform support

| Target | Status |
|---|---|
| Android (`androidTarget`) | Buildable and tested in this repo |
| iOS (`iosArm64`, `iosSimulatorArm64`, `iosX64`) | Declared and structurally correct; full compile/link verification requires a machine with Xcode installed |

## What's in the SDK, and what isn't

**In the SDK** (`commonMain`, fully portable Kotlin, zero platform dependencies):
`RiskScorer`, all category detectors, `WordLexicon`, `PatternMatcher`,
`DetectionResult`/`HarmCategory`/`RiskLevel`/`SignalMatch`, `UserCategory`,
and the `Classifier` interface.

**Not in the SDK — supplied by the host app:**
- **The on-device LLM classifier itself.** The SDK depends only on the
  `Classifier` interface; it ships no MediaPipe, LiteRT-LM, or any other ML
  runtime dependency. The host app is responsible for loading a model and
  implementing `Classifier` against it.
- **Configuration.** `RiskScorer` takes a `RiskThresholds` provider rather than
  reading a config singleton — a host app owns how thresholds are sourced
  (static, remote-config/OTA-backed, or otherwise).
- **Message extraction, storage, and disclosure policy.** How conversation
  text is obtained, whether/how a result is persisted, and what action (if
  any) follows a HIGH result are all host-app decisions.

## Usage

```kotlin
val scorer = RiskScorer(
    classifier = myClassifier,                      // your Classifier implementation
    userCategoryProvider = { UserCategory.CHILD },   // or ADOLESCENT / VULNERABLE_ADULT / SELF_PROTECTING_ADULT
    riskThresholdsProvider = { myConfig.riskThresholds } // defaults to RiskThresholds() if omitted
)

val results = scorer.score(
    text = "[CONTACT]: Where do you live?",
    context = listOf("[USER]: hey!", "[CONTACT]: hi there")
)

val topResult = scorer.highestRisk(results)
```

Messages should be prefixed with `[USER]:` or `[CONTACT]:` to indicate
direction — several detectors and the direction guard rely on this.

## License

Source available, not open source. Free for individual, non-commercial use;
commercial or enterprise use (including integrating this SDK into another
company's product) requires a written license from Agent Hita LLC. See
[LICENSE](LICENSE). Contact admin@agenthita.org for commercial licensing.
