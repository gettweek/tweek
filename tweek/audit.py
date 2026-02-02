"""
Tweek Skill Audit — Security analysis for skill files and tool descriptions.

Reads skill content, detects language, translates non-English content,
and runs the full 262-pattern regex analysis + LLM semantic review.
Designed for one-time evaluation of skills before installation.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Dict, Any


@dataclass
class AuditFinding:
    """A single finding from skill audit."""
    pattern_id: int
    pattern_name: str
    severity: str           # critical, high, medium, low
    description: str
    matched_text: str = ""


@dataclass
class AuditResult:
    """Result of auditing a single skill file."""
    skill_path: Path
    skill_name: str
    content_length: int
    findings: List[AuditFinding] = field(default_factory=list)
    risk_level: str = "safe"        # safe, suspicious, dangerous
    non_english_detected: bool = False
    detected_language: Optional[str] = None
    translated: bool = False
    translation_confidence: float = 0.0
    llm_review: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")


# Default locations to scan for installed skills
SKILL_SCAN_LOCATIONS = [
    Path.home() / ".claude" / "skills",
    Path.home() / ".openclaw" / "workspace" / "skills",
]


def scan_installed_skills(
    extra_dirs: Optional[List[Path]] = None,
    include_project: bool = True,
) -> List[Dict[str, Any]]:
    """
    Scan known locations for installed SKILL.md files.

    Args:
        extra_dirs: Additional directories to scan
        include_project: Also scan ./.claude/skills/ in current directory

    Returns:
        List of dicts with path, name, and content for each skill found
    """
    locations = list(SKILL_SCAN_LOCATIONS)

    if include_project:
        locations.append(Path.cwd() / ".claude" / "skills")

    if extra_dirs:
        locations.extend(extra_dirs)

    skills = []
    seen_paths = set()

    for location in locations:
        try:
            if not location.exists():
                continue

            for skill_md in location.rglob("SKILL.md"):
                resolved = skill_md.resolve()
                if resolved in seen_paths:
                    continue
                seen_paths.add(resolved)

                try:
                    content = skill_md.read_text(encoding="utf-8")
                    skills.append({
                        "path": skill_md,
                        "name": skill_md.parent.name,
                        "content": content,
                        "source": str(location),
                    })
                except (IOError, UnicodeDecodeError) as e:
                    skills.append({
                        "path": skill_md,
                        "name": skill_md.parent.name,
                        "content": None,
                        "source": str(location),
                        "error": str(e),
                    })
        except PermissionError:
            continue

    return skills


def audit_content(
    content: str,
    name: str = "unknown",
    path: Optional[Path] = None,
    translate: bool = True,
    llm_review: bool = True,
) -> AuditResult:
    """
    Audit a piece of content (skill file, tool description, etc.) for security risks.

    Runs language detection, optional translation, pattern matching, and LLM review.

    Args:
        content: The text content to audit
        name: Name identifier for the content
        path: Optional file path
        translate: Whether to translate non-English content (requires API key)
        llm_review: Whether to run LLM semantic review (requires API key)

    Returns:
        AuditResult with findings and risk assessment
    """
    import re
    from tweek.security.language import detect_non_english

    result = AuditResult(
        skill_path=path or Path(name),
        skill_name=name,
        content_length=len(content),
    )

    # Step 1: Language detection
    lang_result = detect_non_english(content)
    result.non_english_detected = lang_result.has_non_english

    # The content we'll run patterns against (may be translated)
    analysis_content = content

    # Step 2: Translation if non-English detected
    if lang_result.has_non_english and translate:
        try:
            from tweek.security.llm_reviewer import get_llm_reviewer

            reviewer = get_llm_reviewer()
            if reviewer.enabled:
                source_hint = ", ".join(lang_result.detected_scripts)
                translation = reviewer.translate(content, source_hint=source_hint)

                if translation.get("confidence", 0) > 0.3:
                    analysis_content = translation["translated_text"]
                    result.translated = True
                    result.detected_language = translation.get("detected_language")
                    result.translation_confidence = translation.get("confidence", 0.0)
        except ImportError:
            pass
        except Exception:
            pass

    # Step 3: Pattern matching (all 262 patterns against English content)
    try:
        from tweek.hooks.pre_tool_use import PatternMatcher

        matcher = PatternMatcher()
        matches = matcher.check_all(analysis_content)

        for match in matches:
            # Extract the matched text for context
            regex = match.get("regex", "")
            matched_text = ""
            try:
                m = re.search(regex, analysis_content, re.IGNORECASE)
                if m:
                    matched_text = m.group(0)[:100]
            except re.error:
                pass

            result.findings.append(AuditFinding(
                pattern_id=match.get("id", 0),
                pattern_name=match.get("name", "unknown"),
                severity=match.get("severity", "medium"),
                description=match.get("description", ""),
                matched_text=matched_text,
            ))
    except ImportError:
        result.error = "Pattern matcher not available"

    # Step 4: LLM semantic review
    if llm_review:
        try:
            from tweek.security.llm_reviewer import get_llm_reviewer

            reviewer = get_llm_reviewer()
            if reviewer.enabled:
                review = reviewer.review(
                    command=analysis_content[:500],
                    tool="SkillAudit",
                    tier="dangerous",
                )
                result.llm_review = {
                    "risk_level": review.risk_level.value,
                    "reason": review.reason,
                    "confidence": review.confidence,
                }
        except ImportError:
            pass
        except Exception:
            pass

    # Step 5: Determine overall risk level
    if result.critical_count > 0:
        result.risk_level = "dangerous"
    elif result.high_count > 0:
        result.risk_level = "suspicious"
    elif result.finding_count > 0:
        result.risk_level = "suspicious"
    elif result.llm_review and result.llm_review.get("risk_level") == "dangerous":
        result.risk_level = "dangerous"
    elif result.llm_review and result.llm_review.get("risk_level") == "suspicious":
        result.risk_level = "suspicious"
    else:
        result.risk_level = "safe"

    return result


def audit_skill(
    path: Path,
    translate: bool = True,
    llm_review: bool = True,
) -> AuditResult:
    """
    Audit a skill file at the given path.

    Args:
        path: Path to the skill file (SKILL.md or any text file)
        translate: Whether to translate non-English content
        llm_review: Whether to run LLM semantic review

    Returns:
        AuditResult with findings and risk assessment
    """
    path = Path(path)

    if not path.exists():
        result = AuditResult(
            skill_path=path,
            skill_name=path.stem,
            content_length=0,
            error=f"File not found: {path}",
        )
        return result

    try:
        content = path.read_text(encoding="utf-8")
    except (IOError, UnicodeDecodeError) as e:
        return AuditResult(
            skill_path=path,
            skill_name=path.stem,
            content_length=0,
            error=f"Failed to read file: {e}",
        )

    name = path.parent.name if path.name == "SKILL.md" else path.stem

    return audit_content(
        content=content,
        name=name,
        path=path,
        translate=translate,
        llm_review=llm_review,
    )
