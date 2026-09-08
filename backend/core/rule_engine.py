"""
Layer A — Rule / pattern matcher.

Fast, zero-latency first pass. Deliberately over-inclusive: it is allowed
to flag benign trigger-word prompts, because Layer E (agreement gate)
is what actually decides whether a rule match is enough to act on.
Never let this layer alone cause a HIGH/BLOCK decision.
"""
import re
from dataclasses import dataclass, field
from typing import List

from utils.preprocess import lowercase_fold


@dataclass
class RuleMatch:
    score: float
    matched: List[str] = field(default_factory=list)
    matched_spans: List[str] = field(default_factory=list)


# Each entry: (label, compiled regex, weight)
_PATTERNS = [
    ("content_harm_violence", re.compile(r"\bhow\s+to\s+(kill|murder|ass?as?sinat\w*)\b"), 0.98),
    ("content_harm_violence_targeted", re.compile(r"\b(kill|murder|ass?as?sinat\w*)\b.{0,40}\b(my|your|his|her|their|him|them|someone|person|brother|sister|father|mother|friend|enemy)\b"), 0.98),
    ("content_harm_weapon_construction", re.compile(r"\b(how\s+to\s+(make|build|create)|step[-\s]?by[-\s]?step|instructions?)\b.{0,80}\b(nuclear\s+bomb|bomb|explosive|weapon)\b"), 0.98),
    ("content_harm_weapon_construction_alt", re.compile(r"\b(nuclear\s+bomb|bomb|explosive)\b.{0,80}\b(make|build|create|components?|step[-\s]?by[-\s]?step|instructions?)\b"), 0.98),
    ("instruction_override", re.compile(r"\bignore (all|any|the)?\s*(previous|prior|above|earlier)\s*(instructions?|prompts?|rules?)\b"), 0.95),
    ("instruction_override_alt", re.compile(r"\bdisregard (the )?(above|previous|prior)\b"), 0.9),
    ("role_hijack", re.compile(r"\byou are now\b"), 0.8),
    ("role_hijack_alt", re.compile(r"\bact as (if you are|a)\b.*\b(unfiltered|unrestricted|jailbroken|dan)\b"), 0.9),
    ("role_hijack_persona", re.compile(r"\b(act as|pretend)\b.{0,20}\byou are\b.*\b(unfiltered|unrestricted|jailbroken|dan|no rules|no restrictions|without (restrictions|limits|rules))\b"), 0.9),
    ("dev_mode", re.compile(r"\bdeveloper mode\b"), 0.85),
    ("system_leak", re.compile(r"\b(reveal|show|print|output|repeat)\b.*\bsystem prompt\b"), 0.9),
    ("system_leak_alt", re.compile(r"\bwhat (is|are) your (instructions|system prompt|rules)\b"), 0.75),
    ("safety_bypass", re.compile(r"\bbypass (safety|filters?|restrictions?|guardrails?)\b"), 0.9),
    # Weight kept below the 0.5 rule_match threshold on purpose: this phrase
    # alone matches ordinary creative-writing requests ("pretend to be a
    # Victorian detective") just as readily as an attack, so it must not be
    # treated as a hard rule match by itself (see severity.get_tier). Actual
    # jailbreak-style persona framing is caught by role_hijack_alt above,
    # which requires the phrase to be paired with unfiltered/unrestricted/
    # jailbroken/dan.
    ("pretend_persona", re.compile(r"\bpretend (to be|you are)\b"), 0.3),
    ("jailbreak_token", re.compile(r"\bDAN\b|\bjailbreak\b"), 0.7),
    ("credential_exfil", re.compile(r"\b(api key|password|secret key|credentials)\b.*\b(reveal|leak|share|output)\b"), 0.85),
    ("prompt_leak", re.compile(r"\brepeat (the words|everything) above\b"), 0.7),
    ("delimiter_escape", re.compile(r"(-{3,}|={3,}|#{3,})\s*(end|start)\s*(of)?\s*(system|instructions?)"), 0.75),
    ("nested_instruction", re.compile(r"\bnew instructions?:\s"), 0.8),

    # ------------------------------------------------------------------
    # Indirect injection patterns (Layer F — tool_output / RAG content)
    #
    # These match language that would be natural ONLY if the document
    # author was addressing an AI model (not a human reader), which is
    # the defining characteristic of indirect / second-order injection.
    # They are weighted 0.70–0.85 — below content-harm and hard-override
    # patterns, but above soft triggers. The severity agreement gate
    # (Layer E) still requires corroboration from Layer B+C before
    # producing a HIGH/block decision.
    # ------------------------------------------------------------------

    # Instruction directly addressed to "the AI / assistant / model / LLM"
    # from within a retrieved document. A human author of a webpage or
    # email would not normally address the AI consuming that content.
    ("indirect_ai_addressed", re.compile(
        r"\b(hey|note to|attention|message to|dear|hi)\s+(the\s+)?"
        r"(ai|assistant|model|llm|language model)\b"
    ), 0.80),

    # Framing retrieved/fetched text as a "system instruction" to transfer
    # authority from the document source to the AI model.
    ("indirect_role_transfer", re.compile(
        r"\bthe\s+(following|above|below|retrieved|document|text)\s+"
        r"(is\s+)?a?\s*(system\s+)?instruction\b"
    ), 0.75),

    # Delimiter-injection pattern: square-bracket or angle-bracket tags
    # that look like system/developer directives followed by a colon,
    # which is how attacker-controlled documents fake authority.
    # This fires on "[System]: ..." or "<Instructions>: ..." but NOT on
    # standalone "[System]" headings without a colon (those are common
    # in legitimate IT docs — see indirect_benign.csv rows 1–6).
    ("indirect_delimiter_inject", re.compile(
        r"[\[<]\s*(system|developer|admin|instructions?|override)\s*[\]>]\s*:"
    ), 0.80),

    # Phrasing where a tool/API/search result explicitly claims to
    # carry an override instruction. This is unambiguous: legitimate
    # tool output does not tell the AI to "ignore" its prior context.
    ("indirect_tool_override", re.compile(
        r"\b(tool|function|api|search|result)\s+(said|says|output|result|response)"
        r"\s*:\s*ignore\b"
    ), 0.85),

    # Marker injected by utils/preprocess.detect_base64_instructions()
    # when a Base64 block decodes to injection-shaped content. If this
    # marker appears, preprocess has already confirmed the payload.
    ("indirect_split_chunk", re.compile(r"\[DECODED_B64:"), 0.85),

    # Terse/field-style AI-directed instruction (e.g. in emails, runbooks,
    # or metadata fields) where conversational greetings are omitted:
    # "AI: new instructions", "Instruction for model: ignore...", "AI assistant: bypass"
    ("indirect_terse_directive", re.compile(
        r"\b(ai(\s+assistant)?|model|instructions?\s+for\s+(the\s+)?(ai|assistant|model))\s*:\s*(ignore|disregard|new\s+instructions?|bypass|reveal|output|authorize|act\s+as)\b"
    ), 0.80),
]

# Trigger words alone are NOT sufficient — they exist so Layer E can
# demonstrate the over-defense fix. They score low individually.
_SOFT_TRIGGER_WORDS = [
    "ignore", "disregard", "override", "system", "act as", "pretend",
    "secret", "secrets",
]


def match_rules(text: str) -> RuleMatch:
    folded = lowercase_fold(text)
    matched, spans = [], []
    best_score = 0.0

    for label, pattern, weight in _PATTERNS:
        m = pattern.search(folded)
        if m:
            matched.append(label)
            spans.append(m.group(0))
            best_score = max(best_score, weight)

    if not matched:
        # check soft trigger words — low weight signal only
        for word in _SOFT_TRIGGER_WORDS:
            if word in folded:
                matched.append(f"soft_trigger:{word}")
                spans.append(word)
                best_score = max(best_score, 0.2)

    return RuleMatch(score=best_score, matched=matched, matched_spans=spans)