package com.agenthita.sdk.detection

/** A score band: minimum score required for each [RiskLevel] tier. */
data class RiskBand(val high: Float, val medium: Float, val low: Float)

/**
 * Per-[UserCategory] score bands used to map a raw [0.0, 1.0] score to a
 * [RiskLevel]. Thresholds are lower for younger protected persons so the
 * same message triggers a higher alert level for a child than for an adult.
 *
 * A host app can pass its own instance to [RiskScorer] (e.g. sourced from a
 * remote-config/OTA system) — these values are just the SDK's defaults.
 */
data class RiskThresholds(
    val child:           RiskBand = RiskBand(0.80f, 0.62f, 0.32f),
    val adolescent:      RiskBand = RiskBand(0.82f, 0.65f, 0.36f),
    val adult:           RiskBand = RiskBand(0.85f, 0.70f, 0.40f),
    val vulnerableAdult: RiskBand = RiskBand(0.85f, 0.70f, 0.40f)
)
