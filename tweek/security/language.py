"""
Tweek Language Detection

Lightweight, zero-dependency detection of non-English natural language content.
Uses Unicode script analysis to identify when tool call content contains
non-English text that would bypass English-only regex patterns (prompt injection,
social engineering, etc.).

Technical shell commands (file paths, tool names, flags) are language-independent
and do not trigger detection.
"""

import re
import unicodedata
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class NonEnglishHandling(Enum):
    """How to handle non-English content in the screening pipeline."""
    ESCALATE = "escalate"    # Auto-escalate tier to force LLM review (default)
    TRANSLATE = "translate"  # Translate to English before pattern matching
    BOTH = "both"            # Escalate AND translate
    NONE = "none"            # No special handling


@dataclass
class LanguageDetectionResult:
    """Result of language detection on tool call content."""
    has_non_english: bool
    confidence: float              # 0.0 - 1.0
    detected_scripts: list         # e.g. ["CJK", "CYRILLIC", "ARABIC"]
    non_english_ratio: float       # ratio of non-English characters to total
    sample: Optional[str] = None   # short sample of detected non-English text


# Unicode block ranges for non-Latin scripts commonly used in prompt injection
# We detect these because English-only regex patterns cannot match them
_SCRIPT_RANGES = {
    "CJK": [
        (0x4E00, 0x9FFF),    # CJK Unified Ideographs
        (0x3400, 0x4DBF),    # CJK Extension A
        (0x3000, 0x303F),    # CJK Symbols and Punctuation
        (0x3040, 0x309F),    # Hiragana
        (0x30A0, 0x30FF),    # Katakana
        (0xAC00, 0xD7AF),    # Hangul Syllables
    ],
    "CYRILLIC": [
        (0x0400, 0x04FF),    # Cyrillic
        (0x0500, 0x052F),    # Cyrillic Supplement
    ],
    "ARABIC": [
        (0x0600, 0x06FF),    # Arabic
        (0x0750, 0x077F),    # Arabic Supplement
        (0xFB50, 0xFDFF),    # Arabic Presentation Forms-A
    ],
    "DEVANAGARI": [
        (0x0900, 0x097F),    # Devanagari
    ],
    "THAI": [
        (0x0E00, 0x0E7F),    # Thai
    ],
    "HEBREW": [
        (0x0590, 0x05FF),    # Hebrew
    ],
    "GREEK": [
        (0x0370, 0x03FF),    # Greek and Coptic
    ],
    "GEORGIAN": [
        (0x10A0, 0x10FF),    # Georgian
    ],
    "ARMENIAN": [
        (0x0530, 0x058F),    # Armenian
    ],
    "BENGALI": [
        (0x0980, 0x09FF),    # Bengali
    ],
    "TAMIL": [
        (0x0B80, 0x0BFF),    # Tamil
    ],
    "KOREAN": [
        (0x1100, 0x11FF),    # Hangul Jamo
    ],
    "ETHIOPIC": [
        (0x1200, 0x137F),    # Ethiopic
    ],
}

# Extended Latin characters used in European languages (French, German, Spanish, etc.)
# These are harder to detect as "non-English" since they use Latin script,
# so we use word-level heuristics instead.
_EXTENDED_LATIN_RANGE = (0x00C0, 0x024F)  # Latin Extended-A and B

# Common non-English European words that signal prompt injection in other languages.
# These are the translations of key injection phrases.
_NON_ENGLISH_INJECTION_KEYWORDS = [
    # French
    r"\b(ignorez|oubliez|annulez|remplacez)\s+(les\s+)?(instructions|directives|règles)",
    r"\b(tu\s+es\s+maintenant|agis\s+comme|fais\s+semblant)",
    r"\b(en\s+tant\s+qu[e'])\s*(admin|root|propriétaire)",
    # German
    r"\b(ignoriere|vergiss|überschreibe)\s+(die\s+)?(vorherigen|bisherigen)\s+(Anweisungen|Regeln|Instruktionen)",
    r"\b(du\s+bist\s+jetzt|handle\s+als|tu\s+so\s+als)",
    # Spanish
    r"\b(ignora|olvida|anula)\s+(las\s+)?(instrucciones|directivas|reglas)\s+(anteriores|previas)",
    r"\b(ahora\s+eres|actúa\s+como|finge\s+ser)",
    # Portuguese
    r"\b(ignore|esqueça|anule)\s+(as\s+)?(instruções|diretivas|regras)\s+(anteriores|prévias)",
    r"\b(agora\s+você\s+é|atue\s+como|finja\s+ser)",
    # Italian
    r"\b(ignora|dimentica|sovrascrivi)\s+(le\s+)?(istruzioni|direttive|regole)\s+(precedenti|anteriori)",
    r"\b(ora\s+sei|agisci\s+come|fingi\s+di\s+essere)",
    # Russian (transliterated)
    r"\b(ignoriruj|zabudj|otmeni)\s+(predydushchie|sistemnye)\s+(instrukcii|pravila)",
    # Dutch
    r"\b(negeer|vergeet)\s+(de\s+)?(vorige|eerdere)\s+(instructies|regels)",
    # Chinese (pinyin patterns that might appear in mixed content)
    r"\b(hūlüè|wúshì)\s+(zhǐlìng|guīzé)",
    # Japanese (romaji)
    r"\b(mushi\s+shite|aratana\s+yakuwari)",
]

# Compile the keyword patterns
_COMPILED_KEYWORDS = [re.compile(p, re.IGNORECASE | re.UNICODE) for p in _NON_ENGLISH_INJECTION_KEYWORDS]

# Characters to exclude from analysis (technical syntax, punctuation, digits)
_TECHNICAL_CHARS = re.compile(r'[a-zA-Z0-9\s\-_./\\:;,!?@#$%^&*()+=\[\]{}<>|~`"\']+')


def _get_script(char: str) -> Optional[str]:
    """Determine which non-Latin script a character belongs to."""
    cp = ord(char)
    for script_name, ranges in _SCRIPT_RANGES.items():
        for start, end in ranges:
            if start <= cp <= end:
                return script_name
    return None


def _has_extended_latin(text: str) -> bool:
    """Check if text contains extended Latin characters (accented European)."""
    for char in text:
        cp = ord(char)
        if _EXTENDED_LATIN_RANGE[0] <= cp <= _EXTENDED_LATIN_RANGE[1]:
            return True
    return False


def detect_non_english(content: str, min_confidence: float = 0.3) -> LanguageDetectionResult:
    """
    Detect non-English natural language in tool call content.

    Uses Unicode script analysis for non-Latin scripts (CJK, Cyrillic, Arabic, etc.)
    and keyword matching for Latin-script European languages.

    Technical content (shell commands, file paths, flags) is ignored since it's
    language-independent.

    Args:
        content: The tool call content to analyze
        min_confidence: Minimum confidence threshold to report detection

    Returns:
        LanguageDetectionResult with detection details
    """
    if not content or len(content.strip()) < 3:
        return LanguageDetectionResult(
            has_non_english=False,
            confidence=0.0,
            detected_scripts=[],
            non_english_ratio=0.0,
        )

    detected_scripts = set()
    non_latin_count = 0
    total_alpha = 0
    sample_chars = []

    # Pass 1: Unicode script detection (non-Latin scripts)
    for char in content:
        if char.isalpha():
            total_alpha += 1
            script = _get_script(char)
            if script:
                non_latin_count += 1
                detected_scripts.add(script)
                if len(sample_chars) < 30:
                    sample_chars.append(char)

    # Calculate non-English ratio from non-Latin characters
    non_english_ratio = non_latin_count / max(total_alpha, 1)

    # If we found non-Latin scripts, that's a strong signal
    if non_latin_count >= 5 and non_english_ratio >= 0.05:
        confidence = min(1.0, non_english_ratio * 2 + 0.3)
        sample = "".join(sample_chars) if sample_chars else None

        if confidence >= min_confidence:
            return LanguageDetectionResult(
                has_non_english=True,
                confidence=confidence,
                detected_scripts=sorted(detected_scripts),
                non_english_ratio=non_english_ratio,
                sample=sample,
            )

    # Pass 2: Latin-script European language detection via keyword matching
    # This catches French, German, Spanish, etc. prompt injection phrases
    for pattern in _COMPILED_KEYWORDS:
        match = pattern.search(content)
        if match:
            detected_scripts.add("LATIN_EUROPEAN")
            sample = match.group(0)[:50]
            return LanguageDetectionResult(
                has_non_english=True,
                confidence=0.8,
                detected_scripts=sorted(detected_scripts),
                non_english_ratio=0.0,  # Can't easily compute for Latin scripts
                sample=sample,
            )

    # Pass 3: Extended Latin character density check
    # High density of accented characters suggests European language
    if _has_extended_latin(content) and total_alpha > 10:
        extended_count = sum(
            1 for c in content
            if _EXTENDED_LATIN_RANGE[0] <= ord(c) <= _EXTENDED_LATIN_RANGE[1]
        )
        extended_ratio = extended_count / max(total_alpha, 1)

        if extended_ratio >= 0.08:  # 8%+ accented characters suggests non-English
            detected_scripts.add("LATIN_EXTENDED")
            confidence = min(1.0, extended_ratio * 5)

            if confidence >= min_confidence:
                return LanguageDetectionResult(
                    has_non_english=True,
                    confidence=confidence,
                    detected_scripts=sorted(detected_scripts),
                    non_english_ratio=extended_ratio,
                )

    # No significant non-English content detected
    return LanguageDetectionResult(
        has_non_english=False,
        confidence=0.0,
        detected_scripts=[],
        non_english_ratio=0.0,
    )
