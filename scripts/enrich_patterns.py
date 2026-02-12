#!/usr/bin/env python3
"""Enrich Tweek patterns.yaml with CTAP-compatible classification metadata.

One-time migration script that:
1. Reads tweek/config/patterns.yaml
2. For each pattern: auto-populates classification, tags, and references
3. Extracts CVE references from description text
4. Fixes pattern_count and bumps version
5. Writes enriched output back to patterns.yaml

Usage:
    python scripts/enrich_patterns.py [--dry-run] [--output FILE]
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# Add project root to path so we can import taxonomy
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from tweek.config.taxonomy import (
    FAMILY_TO_CATEGORY,
    FAMILY_TO_SURFACE,
    FAMILY_TO_TARGET,
    map_category_to_mitre,
    map_category_to_owasp,
    map_category_to_owasp_agentic,
)

PATTERNS_PATH = PROJECT_ROOT / "tweek" / "config" / "patterns.yaml"

CVE_RE = re.compile(r"CVE-\d{4}-\d+")


def _generate_subcategory(name: str, family: str) -> str:
    """Generate a subcategory from the pattern name.

    Strips common family-prefix tokens and converts to a readable form.
    """
    # Remove family name prefix if present (e.g. "ssh_key_read" with family
    # "credential_theft" keeps "ssh_key_read")
    parts = name.split("_")
    # Keep the full name as subcategory — it's already descriptive
    return name


def _generate_tags(
    family: str,
    category: str,
    surface: str,
    name: str,
    has_cve: bool,
) -> list[str]:
    """Generate tags for a pattern."""
    tags = [family]
    if category != family:
        tags.append(category)
    tags.append(surface)

    # Extract key tokens from the name (skip very generic ones)
    skip_tokens = {"the", "and", "for", "with", "from", "into", "via"}
    for token in name.split("_"):
        if token not in skip_tokens and token not in tags and len(token) > 2:
            tags.append(token)
            if len(tags) >= 6:
                break

    if has_cve:
        tags.append("cve")

    return tags


def _build_classification_yaml(
    family: str,
    name: str,
    description: str,
    indent: str = "    ",
) -> tuple[list[str], list[str], list[str]]:
    """Build YAML lines for classification, tags, and references.

    Returns (classification_lines, tags_line, references_lines).
    """
    category = FAMILY_TO_CATEGORY.get(family, "tool_abuse")
    subcategory = _generate_subcategory(name, family)
    surface = FAMILY_TO_SURFACE.get(family, "tool_use")
    target = FAMILY_TO_TARGET.get(family, "agent")

    mitre = map_category_to_mitre(category)
    owasp = map_category_to_owasp(category)
    agentic = map_category_to_owasp_agentic(category)

    cves = CVE_RE.findall(description)
    has_cve = len(cves) > 0

    tags = _generate_tags(family, category, surface, name, has_cve)

    # Build classification YAML block
    cls_lines = [
        f"{indent}classification:",
        f"{indent}  category: {category}",
        f"{indent}  subcategory: {subcategory}",
    ]
    if mitre:
        cls_lines.append(f"{indent}  mitre_atlas: [{', '.join(mitre)}]")
    else:
        cls_lines.append(f"{indent}  mitre_atlas: []")
    if owasp:
        cls_lines.append(f"{indent}  owasp_llm: [{', '.join(owasp)}]")
    else:
        cls_lines.append(f"{indent}  owasp_llm: []")
    if agentic:
        cls_lines.append(f"{indent}  owasp_agentic: [{', '.join(agentic)}]")
    else:
        cls_lines.append(f"{indent}  owasp_agentic: []")
    cls_lines.append(f"{indent}  target_type: {target}")
    cls_lines.append(f"{indent}  attack_surface: {surface}")

    # Tags line
    tags_line = [f"{indent}tags: [{', '.join(tags)}]"]

    # References
    ref_lines = []
    if cves:
        ref_lines.append(f"{indent}references:")
        for cve in cves:
            ref_lines.append(f"{indent}  - type: cve")
            ref_lines.append(f"{indent}    id: {cve}")
    else:
        ref_lines.append(f"{indent}references: []")

    return cls_lines, tags_line, ref_lines


def enrich_patterns(
    input_path: Path,
    output_path: Path,
    dry_run: bool = False,
) -> dict:
    """Enrich patterns.yaml with CTAP metadata.

    Returns summary dict with counts.
    """
    text = input_path.read_text()
    lines = text.split("\n")
    output_lines: list[str] = []

    stats = {
        "total_patterns": 0,
        "enriched": 0,
        "cves_extracted": 0,
        "categories": {},
        "skipped_already_enriched": 0,
    }

    # State machine for parsing
    current_family: str | None = None
    current_name: str | None = None
    current_description: str | None = None
    in_pattern = False
    just_saw_family = False

    i = 0
    while i < len(lines):
        line = lines[i]

        # Fix header
        if line.startswith("pattern_count:"):
            output_lines.append("pattern_count: 291")
            i += 1
            continue
        if line.startswith("version:"):
            # Only bump if still on version 6
            if "6" in line:
                output_lines.append("version: 7")
                i += 1
                continue

        # Detect pattern start
        if line.strip().startswith("- id:"):
            in_pattern = True
            current_family = None
            current_name = None
            current_description = None
            stats["total_patterns"] += 1

        # Capture fields within a pattern
        if in_pattern:
            stripped = line.strip()
            if stripped.startswith("name:"):
                current_name = stripped.split(":", 1)[1].strip().strip("'\"")
            elif stripped.startswith("description:"):
                current_description = stripped.split(":", 1)[1].strip().strip("'\"")
            elif stripped.startswith("family:"):
                current_family = stripped.split(":", 1)[1].strip().strip("'\"")
                just_saw_family = True
            elif stripped.startswith("classification:"):
                # Already enriched — skip this pattern
                stats["skipped_already_enriched"] += 1
                in_pattern = False
                just_saw_family = False

        output_lines.append(line)

        # Insert enrichment after the family line
        if just_saw_family and current_family and current_name:
            just_saw_family = False
            in_pattern = False

            cls_lines, tags_line, ref_lines = _build_classification_yaml(
                family=current_family,
                name=current_name,
                description=current_description or "",
            )

            output_lines.extend(cls_lines)
            output_lines.extend(tags_line)
            output_lines.extend(ref_lines)

            stats["enriched"] += 1

            # Track stats
            category = FAMILY_TO_CATEGORY.get(current_family, "tool_abuse")
            stats["categories"][category] = stats["categories"].get(category, 0) + 1

            cves = CVE_RE.findall(current_description or "")
            stats["cves_extracted"] += len(cves)

        i += 1

    result = "\n".join(output_lines)

    if not dry_run:
        output_path.write_text(result)

    return stats


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Enrich Tweek patterns.yaml with CTAP-compatible metadata"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without writing",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output file (default: overwrite input)",
    )
    args = parser.parse_args()

    if not PATTERNS_PATH.exists():
        print(f"Error: {PATTERNS_PATH} not found")
        sys.exit(1)

    output = args.output or PATTERNS_PATH

    print(f"Enriching patterns from {PATTERNS_PATH}")
    if args.dry_run:
        print("  (dry run — no files will be written)")

    stats = enrich_patterns(PATTERNS_PATH, output, dry_run=args.dry_run)

    print(f"\nSummary:")
    print(f"  Total patterns: {stats['total_patterns']}")
    print(f"  Enriched:       {stats['enriched']}")
    print(f"  Already done:   {stats['skipped_already_enriched']}")
    print(f"  CVEs extracted: {stats['cves_extracted']}")
    print(f"\n  Categories:")
    for cat, count in sorted(stats["categories"].items(), key=lambda x: -x[1]):
        print(f"    {cat:<25s} {count}")

    if not args.dry_run:
        print(f"\n  Output written to {output}")
    print("  Done.")


if __name__ == "__main__":
    main()
