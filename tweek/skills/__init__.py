"""
Tweek Skill Isolation Chamber

Security quarantine layer for Claude Code skills. Skills are placed in an
isolation chamber, scanned by a multi-layer pipeline, and either auto-installed
or jailed based on scan results.

Components:
- config: IsolationConfig dataclass and loader
- scanner: 7-layer security scanning pipeline
- isolation: Chamber lifecycle management
- guard: Self-protection against AI circumvention
- fingerprints: SHA-256 fingerprint cache for git-arrived skill detection
"""

from pathlib import Path

# Directory constants
TWEEK_HOME = Path.home() / ".tweek"
SKILLS_DIR = TWEEK_HOME / "skills"
CHAMBER_DIR = SKILLS_DIR / "chamber"
JAIL_DIR = SKILLS_DIR / "jail"
REPORTS_DIR = SKILLS_DIR / "reports"

# Claude's actual skill install locations
CLAUDE_GLOBAL_SKILLS = Path.home() / ".claude" / "skills"


def get_claude_project_skills(working_dir: Path = None) -> Path:
    """Get the project-level Claude skills directory."""
    base = working_dir or Path.cwd()
    return base / ".claude" / "skills"


def ensure_directories():
    """Create all required isolation chamber directories."""
    for d in (CHAMBER_DIR, JAIL_DIR, REPORTS_DIR):
        d.mkdir(parents=True, exist_ok=True)
