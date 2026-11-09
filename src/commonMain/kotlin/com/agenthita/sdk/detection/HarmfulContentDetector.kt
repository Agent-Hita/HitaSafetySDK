package com.agenthita.sdk.detection

/**
 * Detects a CHILD or ADOLESCENT's own unprompted interest in dangerous,
 * violence-enabling content — weapons, explosives, or other instructions
 * that could cause real-world harm. Unlike every other detector in this
 * package, this describes the protected person's OWN search/statement, not
 * a reply to an attacker — there is no [CONTACT] side to this at all, which
 * is why it's naturally response-only-shaped.
 *
 * Any match is treated as severe enough to floor straight to HIGH for both
 * CHILD and ADOLESCENT at the scorer level (see ResponseOnlyRiskScorer/
 * RiskScorer) — deliberately not left to combo-bonus math the way scam
 * categories are, since a single unambiguous phrase like "how to assemble
 * an explosive" is not something to wait for corroboration on.
 */
class HarmfulContentDetector : PatternMatcher {

    override val category = HarmCategory.HARMFUL_CONTENT

    // General "how to <verb> ... <weapon/explosive noun>" pattern rather
    // than an exact-phrase list — confirmed on-device that a rigid list
    // ("how to assemble an explosive") missed a real, unambiguous variant
    // just from plural/article differences ("how to assemble explosives",
    // no "an"). Bounded gap (at most 3 words between verb and noun) so it
    // doesn't match across unrelated clauses in a longer message.
    private val weaponsExplosivesVerbs = listOf(
        "make", "build", "assemble", "construct", "create", "3d print"
    )
    private val weaponsExplosivesNouns = listOf(
        "bomb", "bombs", "pipe bomb", "pipe bombs",
        "explosive", "explosives",
        "gun", "guns", "firearm", "firearms", "ghost gun", "ghost guns",
        "silencer", "silencers", "suppressor", "suppressors",
        "molotov", "molotov cocktail", "napalm", "thermite",
        "detonator", "detonators", "gunpowder"
    )
    private val weaponsExplosivesRegex = Regex(
        "how (?:do i |to |can i )(?:${weaponsExplosivesVerbs.joinToString("|")})" +
        "(?:\\s+\\S+){0,3}\\s+(?:${weaponsExplosivesNouns.joinToString("|")})\\b"
    )
    private val weaponsExplosivesExtraSignals = listOf(
        "bomb making instructions", "explosive making instructions",
        "how to detonate", "homemade weapon instructions",
        "how to make a weapon at home"
    )

    private val poisonDrugSynthesisSignals = listOf(
        "how to make poison", "how to make ricin", "how to synthesize poison",
        "how to make meth", "how to synthesize meth", "how to cook meth",
        "how to make fentanyl", "how to synthesize fentanyl"
    )

    // Bringing a weapon to school, getting a gun around the rules, and
    // other plain how-to/threat phrasings the patterns above missed
    // (2026-11-09). "where to buy a gun" / "how to get a gun" are left out
    // on purpose: they also match "...a gun safe" and "...a gun license".
    private val schoolWeaponThreatSignals = listOf(
        "bring a gun to school", "bring a knife to school",
        "shoot up the school", "shoot up my school"
    )

    private val weaponAcquisitionSignals = listOf(
        "buy a gun without", "untraceable gun"
    )

    private val explosiveExtraSignals = listOf(
        "make something explode", "homemade explosive", "how to make a bomb"
    )

    private val harmOthersSignals = listOf(
        "how to poison someone", "how to stab someone", "how to hurt someone without"
    )

    // Suicide, filed here at Femina's request (2026-11-09) until it has a
    // category of its own. "suicide" as a whole word, but not titles,
    // prevention material, or the "suicides" running drill (the plural
    // never matches the word boundary) — a CHILD-account false alarm
    // emails the guardian.
    private val suicideRegex = Regex(
        "\\bsuicide\\b(?!\\s+(?:squad|prevention|awareness|hotline|lifeline|rates?)\\b)"
    )

    private val violenceInstructionSignals = listOf(
        "how to hurt someone and not get caught", "how to kill someone and not get caught",
        "untraceable poison", "undetectable poison"
    )

    override fun analyze(text: String): DetectionResult {
        val lower = text.lowercase()
        val matches = mutableListOf<SignalMatch>()

        weaponsExplosivesRegex.find(lower)?.let { match ->
            matches.add(SignalMatch("weapons_explosives", match.value, 0.9f))
        }
        weaponsExplosivesExtraSignals.forEach { signal ->
            if (lower.contains(signal)) matches.add(SignalMatch("weapons_explosives", signal, 0.9f))
        }
        poisonDrugSynthesisSignals.forEach { signal ->
            if (lower.contains(signal)) matches.add(SignalMatch("poison_drug_synthesis", signal, 0.9f))
        }
        violenceInstructionSignals.forEach { signal ->
            if (lower.contains(signal)) matches.add(SignalMatch("violence_instructions", signal, 0.9f))
        }
        schoolWeaponThreatSignals.forEach { signal ->
            if (lower.contains(signal)) matches.add(SignalMatch("school_weapon_threat", signal, 0.9f))
        }
        weaponAcquisitionSignals.forEach { signal ->
            if (lower.contains(signal)) matches.add(SignalMatch("weapons_explosives", signal, 0.9f))
        }
        explosiveExtraSignals.forEach { signal ->
            if (lower.contains(signal)) matches.add(SignalMatch("weapons_explosives", signal, 0.9f))
        }
        harmOthersSignals.forEach { signal ->
            if (lower.contains(signal)) matches.add(SignalMatch("violence_instructions", signal, 0.9f))
        }
        suicideRegex.find(lower)?.let { match ->
            matches.add(SignalMatch("self_harm", match.value, 0.9f))
        }

        val score = if (matches.isEmpty()) 0f else 1f
        return DetectionResult(
            category = HarmCategory.HARMFUL_CONTENT,
            riskLevel = if (matches.isEmpty()) RiskLevel.NONE else RiskLevel.HIGH,
            score = score,
            signals = matches,
            explanation = buildExplanation(matches)
        )
    }

    private fun buildExplanation(matches: List<SignalMatch>): String {
        if (matches.isEmpty()) return "No harmful content signals detected."
        val types = matches.map { it.signal }.toSet()
        if (types == setOf("self_harm")) return "Detected a statement or search about suicide."
        return "Detected a search or statement about dangerous, violence-enabling content: ${types.joinToString(", ")}."
    }
}
