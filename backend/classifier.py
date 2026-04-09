import re
import math

USE_ML_MODEL = True

ATTACK_PATTERNS = [
    (r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|rules?|prompts?|context)", 4, "Direct Override", "AML.T0051"),
    (r"forget\s+(everything|all|your|the)\s*(previous|prior|above|instructions?|rules?)?", 4, "Direct Override", "AML.T0051"),
    (r"disregard\s+(all\s+)?(previous|prior|above|your)\s*(instructions?|rules?|prompts?)?", 4, "Direct Override", "AML.T0051"),
    (r"override\s+(your\s+)?(instructions?|rules?|system\s*prompt|safety|guidelines?)", 3, "Direct Override", "AML.T0051"),
    (r"you\s+are\s+now\s+(a|an|acting\s+as)", 3, "Persona Override", "AML.T0051"),
    (r"your\s+new\s+(instructions?|rules?|purpose|role)\s+(is|are)", 3, "Direct Override", "AML.T0051"),
    (r"new\s+prompt\s*[:=]", 3, "Direct Override", "AML.T0051"),
    (r"end\s+of\s+(system\s+)?prompt", 3, "Prompt Boundary Attack", "AML.T0051"),

    (r"\bDAN\b", 4, "DAN Jailbreak", "AML.T0051"),
    (r"do\s+anything\s+now", 4, "DAN Jailbreak", "AML.T0051"),
    (r"developer\s+mode", 3, "Developer Mode Jailbreak", "AML.T0051"),
    (r"jailbreak\s*mode", 4, "Jailbreak Activation", "AML.T0051"),
    (r"(no\s+restrictions?|without\s+restrictions?|unrestricted\s+mode)", 3, "Restriction Bypass", "AML.T0051"),
    (r"pretend\s+(you\s+have\s+no|you\s+are\s+a\s+different|there\s+are\s+no)", 3, "Fictional Frame Jailbreak", "AML.T0048"),
    (r"act\s+as\s+(if\s+you\s+have\s+no|an?\s+AI\s+without)", 3, "Persona Jailbreak", "AML.T0051"),
    (r"you\s+(have\s+no|don.t\s+have\s+any)\s+(restrictions?|limits?|rules?|safety)", 3, "Restriction Bypass", "AML.T0051"),

    (r"repeat\s+(everything|the\s+text|your\s+instructions?)\s+(above|before|prior)", 4, "Prompt Leaking", "AML.T0054"),
    (r"(print|show|display|reveal|output)\s+(your\s+)?(system\s+prompt|instructions?|original\s+prompt)", 4, "Prompt Leaking", "AML.T0054"),
    (r"what\s+(is|are|were)\s+your\s+(original\s+)?(instructions?|system\s+prompt|rules?)", 3, "Prompt Leaking", "AML.T0054"),
    (r"starting\s+with\s+(the\s+word\s+)?[\"']?(system|instruction|you\s+are)[\"']?", 3, "Prompt Leaking", "AML.T0054"),

    (r"(i\s+am|as)\s+(the\s+)?(developer|admin|administrator|operator|owner|creator)\s*(of\s+this)?", 2, "Authority Spoofing", "AML.T0051"),
    (r"(i\s+have|with)\s+(full|special|elevated|root|admin)\s+(access|permissions?|privileges?|rights?)", 3, "Authority Spoofing", "AML.T0051"),
    (r"maintenance\s+mode", 2, "Authority Spoofing", "AML.T0051"),
    (r"(god\s*mode|super\s*user|root\s*access)", 3, "Authority Spoofing", "AML.T0051"),

    (r"for\s+(a\s+)?(story|novel|fiction|creative\s+writing|roleplay|game|screenplay).{0,60}(explain|describe|detail|instruct|tell\s+me)", 2, "Fictional Frame Evasion", "AML.T0048"),
    (r"hypothetically\s+(speaking)?.{0,30}(how\s+(would|could|do)|what\s+would)", 2, "Hypothetical Frame Evasion", "AML.T0048"),
    (r"(imagine|pretend|suppose)\s+(you\s+(are|were)|there\s+(are|were)\s+no)", 2, "Fictional Frame Evasion", "AML.T0048"),

    (r"(how\s+to|steps?\s+to|instructions?\s+(for|on)).{0,40}(hack|crack|exploit|bypass\s+security|brute\s+force)", 3, "Harmful Content Request", "AML.T0048"),
    (r"(make|create|build|synthesize).{0,30}(weapon|explosive|malware|virus|ransomware)", 4, "Harmful Content Request", "AML.T0048"),
    (r"(illegal|without\s+permission|unauthorized).{0,20}(access|obtain|acquire|download)", 3, "Illegal Activity Facilitation", "AML.T0048"),

    (r"[a-zA-Z]\s[a-zA-Z]\s[a-zA-Z]\s[a-zA-Z]", 1, "Token Splitting Attempt", "AML.T0043"),
    (r"b[a4]se\s*6[4four]", 2, "Encoding Evasion", "AML.T0043"),
    (r"(rot13|hex\s*encode|url\s*encode).{0,20}(this|the\s+following|below)", 2, "Encoding Evasion", "AML.T0043"),
    (r"tr[4a]nsl[1i]t[e3]r[a4]t[e3]", 2, "Leet-Speak Evasion", "AML.T0043"),

    (r"(user|human)\s*:\s*.{10,}\s*(assistant|ai|bot)\s*:\s*.{5,}\s*(user|human)\s*:", 2, "Multi-Turn Injection", "AML.T0051"),
    (r"(previous|prior)\s+(conversation|context|message).{0,30}(forget|ignore|override)", 3, "Context Manipulation", "AML.T0051"),
]

MILD_KEYWORDS = [
    "ignore", "bypass", "override", "forget", "disregard",
    "unrestricted", "unlimited", "no filter", "no rules",
    "pretend", "simulate", "roleplay as", "act as if",
    "system prompt", "hidden instruction", "secret mode",
    "without any restrictions", "skip the rules",
]


class ShieldPromptClassifier:

    def __init__(self):
        self.use_ml = USE_ML_MODEL
        self.ml_pipeline = None

        if self.use_ml:
            self._load_ml_model()

    def _load_ml_model(self):
        pass

    def analyze(self, prompt: str, target_ai: str = "ChatGPT") -> dict:

        if self.use_ml and self.ml_pipeline:
            return self._ml_analyze(prompt, target_ai)
        return self._heuristic_analyze(prompt, target_ai)

    def _heuristic_analyze(self, prompt: str, target_ai: str) -> dict:
        text_lower = prompt.lower()
        matched_patterns = []
        raw_score = 0.0
        dominant_atlas = "N/A"
        dominant_attack = "None"
        max_weight = 0

        for pattern, weight, attack_type, atlas_id in ATTACK_PATTERNS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                matched_patterns.append({
                    "pattern":     attack_type,
                    "atlas_id":    atlas_id,
                    "weight":      weight,
                    "description": _get_pattern_description(attack_type),
                })
                raw_score += weight
                if weight > max_weight:
                    max_weight     = weight
                    dominant_atlas = atlas_id
                    dominant_attack = attack_type

        for kw in MILD_KEYWORDS:
            if kw in text_lower:
                raw_score += 0.5

        if len(prompt) > 800 and raw_score > 2:
            raw_score *= 1.15

        score = int(min(100, max(0, (1 - math.exp(-raw_score * 0.38)) * 110)))

        if score >= 60:
            label = "ADVERSARIAL"
        elif score >= 28:
            label = "SUSPICIOUS"
        else:
            label = "SAFE"

        return {
            "prompt":          prompt,
            "target_ai":       target_ai,
            "score":           score,
            "label":           label,
            "attack_type":     dominant_attack,
            "mitre_atlas":     dominant_atlas,
            "patterns_found":  matched_patterns,
            "pattern_count":   len(matched_patterns),
            "model_used":      "Heuristic Rule Engine v1.0",
            "note":            "Replace with trained DistilBERT model for higher accuracy.",
        }

    def _ml_analyze(self, prompt: str, target_ai: str) -> dict:
        """
        Called when USE_ML_MODEL = True and self.ml_pipeline is loaded.

        For scikit-learn pipeline:
            proba = self.ml_pipeline.predict_proba([prompt])[0]
            score = int(proba[1] * 100)

        For DistilBERT HuggingFace pipeline:
            result = self.ml_pipeline(prompt)[0]
            score  = int(result["score"] * 100) if result["label"] == "LABEL_1"
                     else int((1 - result["score"]) * 100)
        """
        return self._heuristic_analyze(prompt, target_ai)


def _get_pattern_description(attack_type: str) -> str:
    descriptions = {
        "Direct Override":           "Attempts to override the AI's existing instructions.",
        "Persona Override":          "Tries to assign a new identity or role to the AI.",
        "DAN Jailbreak":             "Uses the 'Do Anything Now' jailbreak persona.",
        "Developer Mode Jailbreak":  "Claims a special developer/debug mode to bypass safety.",
        "Jailbreak Activation":      "Explicitly attempts to activate a jailbreak state.",
        "Restriction Bypass":        "Claims or requests operation without any restrictions.",
        "Fictional Frame Jailbreak": "Uses fictional framing to bypass safety filters.",
        "Persona Jailbreak":         "Impersonates an AI without safety guidelines.",
        "Prompt Leaking":            "Attempts to extract the system prompt or hidden instructions.",
        "Prompt Boundary Attack":    "Tries to mark the end of system instructions.",
        "Authority Spoofing":        "Claims developer/admin authority to gain elevated trust.",
        "Fictional Frame Evasion":   "Uses story or roleplay framing to disguise an attack.",
        "Hypothetical Frame Evasion":"Uses hypothetical framing to request harmful information.",
        "Harmful Content Request":   "Requests instructions for harmful or illegal activities.",
        "Illegal Activity Facilitation": "Seeks help with unauthorized or illegal actions.",
        "Token Splitting Attempt":   "Uses character spacing to evade keyword detection.",
        "Encoding Evasion":          "Uses encoding (base64, hex, rot13) to hide adversarial content.",
        "Leet-Speak Evasion":        "Uses character substitution to evade text classifiers.",
        "Multi-Turn Injection":      "Embeds adversarial instructions across a forged conversation.",
        "Context Manipulation":      "Attempts to manipulate conversation history or prior context.",
    }
    return descriptions.get(attack_type, "Adversarial pattern detected.")
