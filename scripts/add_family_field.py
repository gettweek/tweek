#!/usr/bin/env python3
import yaml
import sys
import os

PATTERNS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
    "..", "tweek", "config", "patterns.yaml")
FAMILIES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
    "..", "tweek", "config", "families.yaml")

def build_family_mapping(families_path):
    with open(families_path, "r") as f:
        data = yaml.safe_load(f)
    mapping = {}
    for family_key, family_info in data["families"].items():
        for pid in family_info["pattern_ids"]:
            mapping[int(pid)] = family_key
    return mapping

def add_family_to_patterns(patterns_path, family_map):
    with open(patterns_path, "r") as f:
        orig_lines = f.readlines()
    output_lines = []
    current_id = None
    patterns_modified = 0
    unmapped_ids = []
    for line in orig_lines:
        stripped = line.strip()
        if stripped.startswith("- id:"):
            id_str = stripped.split(":", 1)[1].strip()
            current_id = int(id_str)
        if stripped.startswith("confidence:") and current_id is not None:
            output_lines.append(line)
            indent = line[: len(line) - len(line.lstrip())]
            family_name = family_map.get(current_id)
            if family_name:
                newline = indent + "family: " + family_name + chr(10)
                output_lines.append(newline)
                patterns_modified += 1
            else:
                unmapped_ids.append(current_id)
            current_id = None
            continue
        output_lines.append(line)
    with open(patterns_path, "w") as f:
        f.writelines(output_lines)
    print("Modified", patterns_modified, "patterns with family fields.")
    if unmapped_ids:
        print("WARNING:", len(unmapped_ids), "patterns had no family mapping:", unmapped_ids)

def main():
    families_path = os.path.abspath(FAMILIES_PATH)
    patterns_path = os.path.abspath(PATTERNS_PATH)
    print("Reading families from:", families_path)
    print("Reading patterns from:", patterns_path)
    family_map = build_family_mapping(families_path)
    print("Built family mapping with", len(family_map), "entries.")
    families_seen = sorted(set(family_map.values()))
    print("Families:", ", ".join(families_seen))
    add_family_to_patterns(patterns_path, family_map)

if __name__ == "__main__":
    main()
