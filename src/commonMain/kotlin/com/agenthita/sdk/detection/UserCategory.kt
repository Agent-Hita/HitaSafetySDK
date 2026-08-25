package com.agenthita.sdk.detection

/**
 * The protected person's category, used to age-adjust risk thresholds and
 * word-lexicon weighting so the same message can trigger a higher alert
 * level for a child than for an adult.
 */
enum class UserCategory {
    SELF_PROTECTING_ADULT,
    VULNERABLE_ADULT,
    ADOLESCENT,
    CHILD
}
