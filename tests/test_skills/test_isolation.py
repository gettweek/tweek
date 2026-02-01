"""
Tests for tweek.skills.isolation — SkillIsolationChamber lifecycle.

Covers: accept, scan, accept_and_scan, approve, jail, release, list, report, purge.
All directory constants are monkeypatched to tmp_path sub-directories so that
tests never touch the real ~/.tweek or ~/.claude directories.
"""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from tweek.skills.config import IsolationConfig
from tweek.skills.isolation import SkillIsolationChamber
from tweek.skills.scanner import SkillScanReport


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_skill_dir(base: Path, name: str = "my-skill") -> Path:
    """Create a minimal valid skill directory under *base*."""
    skill_dir = base / name
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "SKILL.md").write_text("# My Skill\nA test skill.\n")
    return skill_dir


def _make_report(
    skill_name: str = "my-skill",
    verdict: str = "pass",
    risk_level: str = "safe",
    critical: int = 0,
    high: int = 0,
    medium: int = 0,
    low: int = 0,
    scan_duration_ms: int = 42,
) -> SkillScanReport:
    """Build a controlled SkillScanReport for mocking."""
    return SkillScanReport(
        skill_name=skill_name,
        verdict=verdict,
        risk_level=risk_level,
        critical_count=critical,
        high_count=high,
        medium_count=medium,
        low_count=low,
        scan_duration_ms=scan_duration_ms,
    )


@pytest.fixture()
def dirs(tmp_path):
    """
    Create isolated temp directories and monkeypatch the module-level
    constants so SkillIsolationChamber uses them instead of real paths.
    """
    chamber = tmp_path / "chamber"
    jail = tmp_path / "jail"
    reports = tmp_path / "reports"
    global_skills = tmp_path / "global_skills"
    project_skills = tmp_path / "project_skills"

    for d in (chamber, jail, reports, global_skills, project_skills):
        d.mkdir(parents=True, exist_ok=True)

    patches = [
        patch("tweek.skills.CHAMBER_DIR", chamber),
        patch("tweek.skills.JAIL_DIR", jail),
        patch("tweek.skills.REPORTS_DIR", reports),
        patch("tweek.skills.CLAUDE_GLOBAL_SKILLS", global_skills),
        # The isolation module imports these names directly, so patch there too
        patch("tweek.skills.isolation.CHAMBER_DIR", chamber),
        patch("tweek.skills.isolation.JAIL_DIR", jail),
        patch("tweek.skills.isolation.REPORTS_DIR", reports),
        patch("tweek.skills.isolation.CLAUDE_GLOBAL_SKILLS", global_skills),
        patch(
            "tweek.skills.isolation.get_claude_project_skills",
            return_value=project_skills,
        ),
        # ensure_directories is a no-op since we already created them
        patch("tweek.skills.isolation.ensure_directories"),
    ]

    for p in patches:
        p.start()

    class Dirs:
        pass

    d = Dirs()
    d.tmp = tmp_path
    d.chamber = chamber
    d.jail = jail
    d.reports = reports
    d.global_skills = global_skills
    d.project_skills = project_skills
    d._patches = patches

    yield d

    for p in patches:
        p.stop()


@pytest.fixture()
def chamber(dirs):
    """Return a SkillIsolationChamber wired to the temp directories."""
    config = IsolationConfig(mode="auto", notify_on_jail=False)
    return SkillIsolationChamber(config=config)


# =========================================================================
# 1. accept_skill
# =========================================================================


class TestAcceptSkill:
    """Tests for SkillIsolationChamber.accept_skill."""

    def test_accept_skill_directory(self, dirs, chamber):
        """Accept a valid skill directory."""
        src = _make_skill_dir(dirs.tmp / "src", "good-skill")
        ok, msg = chamber.accept_skill(src)

        assert ok is True
        assert "good-skill" in msg
        assert (dirs.chamber / "good-skill" / "SKILL.md").exists()

    def test_accept_skill_md_file(self, dirs, chamber):
        """Accept by pointing at the SKILL.md file directly."""
        src = _make_skill_dir(dirs.tmp / "src2", "md-skill")
        skill_md = src / "SKILL.md"
        ok, msg = chamber.accept_skill(skill_md)

        assert ok is True
        assert "md-skill" in msg
        assert (dirs.chamber / "md-skill" / "SKILL.md").exists()

    def test_reject_missing_source(self, dirs, chamber):
        """Reject a source path that does not exist."""
        ok, msg = chamber.accept_skill(dirs.tmp / "nonexistent")

        assert ok is False
        assert "does not exist" in msg

    def test_reject_missing_skill_md(self, dirs, chamber):
        """Reject a directory that has no SKILL.md."""
        src = dirs.tmp / "no_skill_md"
        src.mkdir()
        (src / "README.md").write_text("Not a skill.\n")
        ok, msg = chamber.accept_skill(src)

        assert ok is False
        assert "No SKILL.md" in msg

    def test_reject_duplicate(self, dirs, chamber):
        """Reject accepting the same skill name twice."""
        src = _make_skill_dir(dirs.tmp / "srcdup", "dup-skill")
        ok1, _ = chamber.accept_skill(src)
        assert ok1 is True

        ok2, msg = chamber.accept_skill(src)
        assert ok2 is False
        assert "already in chamber" in msg

    def test_accept_with_custom_name(self, dirs, chamber):
        """Accept with an overridden skill name."""
        src = _make_skill_dir(dirs.tmp / "srcname", "original")
        ok, msg = chamber.accept_skill(src, skill_name="renamed")

        assert ok is True
        assert "renamed" in msg
        assert (dirs.chamber / "renamed" / "SKILL.md").exists()
        assert not (dirs.chamber / "original").exists()


# =========================================================================
# 2. scan_skill
# =========================================================================


class TestScanSkill:
    """Tests for SkillIsolationChamber.scan_skill."""

    def test_scan_existing_skill(self, dirs, chamber):
        """Scan a skill that exists in the chamber (mock scanner)."""
        _make_skill_dir(dirs.chamber, "scanme")

        mock_report = _make_report("scanme", verdict="pass")
        with patch.object(
            chamber.scanner, "scan", return_value=mock_report
        ):
            report, msg = chamber.scan_skill("scanme")

        assert report.verdict == "pass"
        assert report.skill_name == "scanme"
        assert "scanme" in msg

    def test_scan_missing_skill(self, dirs, chamber):
        """Scanning a non-existent skill returns a fail report."""
        report, msg = chamber.scan_skill("ghost")

        assert report.verdict == "fail"
        assert "not found" in msg

    def test_scan_saves_report_file(self, dirs, chamber):
        """Scan saves a JSON report to the reports directory."""
        _make_skill_dir(dirs.chamber, "reported")

        mock_report = _make_report("reported", verdict="pass")
        with patch.object(
            chamber.scanner, "scan", return_value=mock_report
        ):
            chamber.scan_skill("reported")

        report_files = list(dirs.reports.glob("reported-*.json"))
        assert len(report_files) == 1

        data = json.loads(report_files[0].read_text())
        assert data["verdict"] == "pass"
        assert data["skill_name"] == "reported"


# =========================================================================
# 3. accept_and_scan
# =========================================================================


class TestAcceptAndScan:
    """Tests for the combined accept_and_scan flow."""

    def test_pass_auto_installs(self, dirs, chamber):
        """When verdict is pass and mode is auto, skill is auto-installed."""
        src = _make_skill_dir(dirs.tmp / "src_pass", "auto-install")

        mock_report = _make_report("auto-install", verdict="pass")
        with patch.object(
            chamber.scanner, "scan", return_value=mock_report
        ):
            report, msg = chamber.accept_and_scan(src)

        assert report.verdict == "pass"
        # Skill should have been moved out of chamber to global_skills
        assert (dirs.global_skills / "auto-install" / "SKILL.md").exists()
        assert not (dirs.chamber / "auto-install").exists()

    def test_fail_jails_skill(self, dirs, chamber):
        """When verdict is fail, skill is moved to jail."""
        src = _make_skill_dir(dirs.tmp / "src_fail", "bad-skill")

        mock_report = _make_report(
            "bad-skill", verdict="fail", risk_level="dangerous", critical=2
        )
        with patch.object(
            chamber.scanner, "scan", return_value=mock_report
        ):
            report, msg = chamber.accept_and_scan(src)

        assert report.verdict == "fail"
        assert "Quarantined" in msg or "jail" in msg.lower()
        assert (dirs.jail / "bad-skill").exists()
        assert not (dirs.chamber / "bad-skill").exists()

    def test_manual_review_stays_in_chamber(self, dirs, chamber):
        """When verdict is manual_review, skill stays in chamber."""
        src = _make_skill_dir(dirs.tmp / "src_review", "review-me")

        mock_report = _make_report(
            "review-me", verdict="manual_review", risk_level="suspicious", high=1
        )
        with patch.object(
            chamber.scanner, "scan", return_value=mock_report
        ):
            report, msg = chamber.accept_and_scan(src)

        assert report.verdict == "manual_review"
        # Should still be in chamber
        assert (dirs.chamber / "review-me" / "SKILL.md").exists()
        # Should NOT be in jail or global
        assert not (dirs.jail / "review-me").exists()
        assert not (dirs.global_skills / "review-me").exists()

    def test_accept_and_scan_to_project(self, dirs, chamber):
        """Auto-install targets the project skills directory."""
        src = _make_skill_dir(dirs.tmp / "src_proj", "proj-skill")

        mock_report = _make_report("proj-skill", verdict="pass")
        with patch.object(
            chamber.scanner, "scan", return_value=mock_report
        ):
            report, msg = chamber.accept_and_scan(src, target="project")

        assert report.verdict == "pass"
        assert (dirs.project_skills / "proj-skill" / "SKILL.md").exists()

    def test_accept_failure_returns_fail_report(self, dirs, chamber):
        """If accept itself fails, return a fail report immediately."""
        missing = dirs.tmp / "does_not_exist"
        report, msg = chamber.accept_and_scan(missing)

        assert report.verdict == "fail"
        assert "does not exist" in msg or "No SKILL.md" in msg


# =========================================================================
# 4. approve_skill
# =========================================================================


class TestApproveSkill:
    """Tests for SkillIsolationChamber.approve_skill."""

    def test_approve_to_global(self, dirs, chamber):
        """Approve moves the skill from chamber to global skills."""
        _make_skill_dir(dirs.chamber, "approved")

        ok, msg = chamber.approve_skill("approved", target="global")

        assert ok is True
        assert (dirs.global_skills / "approved" / "SKILL.md").exists()
        assert not (dirs.chamber / "approved").exists()

    def test_approve_to_project(self, dirs, chamber):
        """Approve to project installs into the project skills directory."""
        _make_skill_dir(dirs.chamber, "proj-approved")

        ok, msg = chamber.approve_skill("proj-approved", target="project")

        assert ok is True
        assert (dirs.project_skills / "proj-approved" / "SKILL.md").exists()
        assert not (dirs.chamber / "proj-approved").exists()

    def test_approve_missing_skill(self, dirs, chamber):
        """Approving a skill that is not in the chamber fails."""
        ok, msg = chamber.approve_skill("phantom")

        assert ok is False
        assert "not found" in msg

    def test_approve_overwrites_existing_install(self, dirs, chamber):
        """Re-approving overwrites an existing installation."""
        # Pre-existing install
        existing = dirs.global_skills / "overwrite-me"
        existing.mkdir(parents=True)
        (existing / "SKILL.md").write_text("old version")

        # New version in chamber
        new = _make_skill_dir(dirs.chamber, "overwrite-me")
        (new / "SKILL.md").write_text("new version")

        ok, msg = chamber.approve_skill("overwrite-me")

        assert ok is True
        content = (dirs.global_skills / "overwrite-me" / "SKILL.md").read_text()
        assert "new version" in content


# =========================================================================
# 5. jail_skill
# =========================================================================


class TestJailSkill:
    """Tests for SkillIsolationChamber.jail_skill."""

    def test_jail_with_report(self, dirs, chamber):
        """Jail a skill and embed a scan report."""
        _make_skill_dir(dirs.chamber, "jailable")

        report = _make_report(
            "jailable", verdict="fail", risk_level="dangerous", critical=1
        )
        ok, msg = chamber.jail_skill("jailable", report)

        assert ok is True
        assert "quarantined" in msg.lower()
        assert (dirs.jail / "jailable" / "SKILL.md").exists()
        assert not (dirs.chamber / "jailable").exists()

        # Embedded report
        report_path = dirs.jail / "jailable" / "scan-report.json"
        assert report_path.exists()
        data = json.loads(report_path.read_text())
        assert data["verdict"] == "fail"
        assert data["summary"]["critical"] == 1

    def test_jail_without_report(self, dirs, chamber):
        """Jail without a report still moves the skill."""
        _make_skill_dir(dirs.chamber, "no-report")

        ok, msg = chamber.jail_skill("no-report", report=None)

        assert ok is True
        assert (dirs.jail / "no-report" / "SKILL.md").exists()
        # No scan-report.json since report was None
        assert not (dirs.jail / "no-report" / "scan-report.json").exists()

    def test_jail_missing_skill(self, dirs, chamber):
        """Jailing a skill not in the chamber fails."""
        ok, msg = chamber.jail_skill("nonexistent")

        assert ok is False
        assert "not found" in msg

    def test_jail_overwrites_existing_jailed(self, dirs, chamber):
        """Re-jailing overwrites the existing jail entry."""
        # First jail entry
        old_jail = dirs.jail / "repeat-offender"
        old_jail.mkdir(parents=True)
        (old_jail / "SKILL.md").write_text("old version")

        # New version in chamber
        _make_skill_dir(dirs.chamber, "repeat-offender")

        ok, msg = chamber.jail_skill("repeat-offender")

        assert ok is True
        content = (dirs.jail / "repeat-offender" / "SKILL.md").read_text()
        assert content != "old version"


# =========================================================================
# 6. release_from_jail
# =========================================================================


class TestReleaseFromJail:
    """Tests for SkillIsolationChamber.release_from_jail."""

    def test_rescan_pass_releases(self, dirs, chamber):
        """Re-scan passes -- skill released from jail to chamber."""
        jailed = _make_skill_dir(dirs.jail, "reformed")

        mock_report = _make_report("reformed", verdict="pass")
        with patch.object(
            chamber.scanner, "scan", return_value=mock_report
        ):
            ok, msg = chamber.release_from_jail("reformed")

        assert ok is True
        assert "passes" in msg.lower() or "pass" in msg.lower()
        # Jail entry removed
        assert not (dirs.jail / "reformed").exists()
        # Skill is in chamber (released, awaiting approval)
        assert (dirs.chamber / "reformed" / "SKILL.md").exists()

    def test_force_release(self, dirs, chamber):
        """Force-release moves skill from jail to chamber without scanning."""
        _make_skill_dir(dirs.jail, "forced")

        ok, msg = chamber.release_from_jail("forced", force=True)

        assert ok is True
        assert "force-released" in msg.lower()
        assert not (dirs.jail / "forced").exists()
        assert (dirs.chamber / "forced" / "SKILL.md").exists()

    def test_still_fails_stays_in_jail(self, dirs, chamber):
        """Re-scan still fails -- skill stays in jail."""
        _make_skill_dir(dirs.jail, "recidivist")

        mock_report = _make_report(
            "recidivist", verdict="fail", risk_level="dangerous", critical=3
        )
        with patch.object(
            chamber.scanner, "scan", return_value=mock_report
        ):
            ok, msg = chamber.release_from_jail("recidivist")

        assert ok is False
        assert "still fails" in msg.lower()
        # Stays in jail
        assert (dirs.jail / "recidivist" / "SKILL.md").exists()
        # NOT left in chamber
        assert not (dirs.chamber / "recidivist").exists()

    def test_manual_review_releases_from_jail(self, dirs, chamber):
        """Re-scan yields manual_review -- released from jail to chamber."""
        _make_skill_dir(dirs.jail, "needs-review")

        mock_report = _make_report(
            "needs-review", verdict="manual_review", risk_level="suspicious"
        )
        with patch.object(
            chamber.scanner, "scan", return_value=mock_report
        ):
            ok, msg = chamber.release_from_jail("needs-review")

        assert ok is True
        assert "manual review" in msg.lower()
        assert not (dirs.jail / "needs-review").exists()
        assert (dirs.chamber / "needs-review" / "SKILL.md").exists()

    def test_release_missing_jail_entry(self, dirs, chamber):
        """Releasing a skill that is not in jail fails."""
        ok, msg = chamber.release_from_jail("not-jailed")

        assert ok is False
        assert "not found" in msg


# =========================================================================
# 7. list_chamber / list_jail
# =========================================================================


class TestListChamberAndJail:
    """Tests for list_chamber and list_jail."""

    def test_list_chamber_empty(self, dirs, chamber):
        """Empty chamber returns an empty list."""
        result = chamber.list_chamber()
        assert result == []

    def test_list_chamber_populated(self, dirs, chamber):
        """Populated chamber returns entries with expected keys."""
        _make_skill_dir(dirs.chamber, "alpha")
        _make_skill_dir(dirs.chamber, "beta")

        result = chamber.list_chamber()

        assert len(result) == 2
        names = {r["name"] for r in result}
        assert names == {"alpha", "beta"}

        for entry in result:
            assert "name" in entry
            assert "path" in entry
            assert "has_skill_md" in entry
            assert entry["has_skill_md"] is True

    def test_list_chamber_without_skill_md(self, dirs, chamber):
        """Entries without SKILL.md report has_skill_md=False."""
        no_md = dirs.chamber / "no-md"
        no_md.mkdir()
        (no_md / "README.md").write_text("not a skill")

        result = chamber.list_chamber()
        assert len(result) == 1
        assert result[0]["has_skill_md"] is False

    def test_list_jail_empty(self, dirs, chamber):
        """Empty jail returns an empty list."""
        result = chamber.list_jail()
        assert result == []

    def test_list_jail_populated(self, dirs, chamber):
        """Populated jail returns entries; those with reports include verdict info."""
        # Jail entry with report
        jailed_with_report = dirs.jail / "bad-actor"
        jailed_with_report.mkdir(parents=True)
        (jailed_with_report / "SKILL.md").write_text("evil stuff")
        report = _make_report(
            "bad-actor", verdict="fail", risk_level="dangerous", critical=2, high=1
        )
        (jailed_with_report / "scan-report.json").write_text(report.to_json())

        # Jail entry without report
        jailed_no_report = dirs.jail / "mystery"
        jailed_no_report.mkdir(parents=True)
        (jailed_no_report / "SKILL.md").write_text("unknown")

        result = chamber.list_jail()

        assert len(result) == 2
        by_name = {r["name"]: r for r in result}

        # Entry with report should have verdict and risk info
        assert by_name["bad-actor"]["verdict"] == "fail"
        assert by_name["bad-actor"]["risk_level"] == "dangerous"
        assert by_name["bad-actor"]["critical"] == 2
        assert by_name["bad-actor"]["high"] == 1

        # Entry without report should just have name and path
        assert "verdict" not in by_name["mystery"]


# =========================================================================
# 8. get_report
# =========================================================================


class TestGetReport:
    """Tests for SkillIsolationChamber.get_report."""

    def test_get_report_from_jail(self, dirs, chamber):
        """Retrieve a report embedded in a jailed skill."""
        jailed = dirs.jail / "reported-skill"
        jailed.mkdir(parents=True)
        report = _make_report("reported-skill", verdict="fail", critical=1)
        (jailed / "scan-report.json").write_text(report.to_json())

        result = chamber.get_report("reported-skill")

        assert result is not None
        assert result["verdict"] == "fail"
        assert result["summary"]["critical"] == 1

    def test_get_report_from_reports_dir(self, dirs, chamber):
        """Retrieve a report from the reports directory."""
        report = _make_report("saved-skill", verdict="pass")
        report_file = dirs.reports / "saved-skill-20250101-120000.json"
        report_file.write_text(report.to_json())

        result = chamber.get_report("saved-skill")

        assert result is not None
        assert result["verdict"] == "pass"

    def test_get_report_latest_from_reports_dir(self, dirs, chamber):
        """When multiple reports exist, get the latest (sorted reverse)."""
        old_report = _make_report("multi", verdict="fail")
        new_report = _make_report("multi", verdict="pass")

        (dirs.reports / "multi-20250101-100000.json").write_text(old_report.to_json())
        (dirs.reports / "multi-20250102-100000.json").write_text(new_report.to_json())

        result = chamber.get_report("multi")

        assert result is not None
        assert result["verdict"] == "pass"  # the later one

    def test_get_report_jail_takes_priority(self, dirs, chamber):
        """Jail report is returned over reports directory."""
        jail_dir = dirs.jail / "priority-skill"
        jail_dir.mkdir(parents=True)
        jail_report = _make_report("priority-skill", verdict="fail")
        (jail_dir / "scan-report.json").write_text(jail_report.to_json())

        report_file = dirs.reports / "priority-skill-20250101-120000.json"
        reports_report = _make_report("priority-skill", verdict="pass")
        report_file.write_text(reports_report.to_json())

        result = chamber.get_report("priority-skill")

        assert result is not None
        assert result["verdict"] == "fail"  # jail takes priority

    def test_get_report_not_found(self, dirs, chamber):
        """No report found returns None."""
        result = chamber.get_report("never-scanned")
        assert result is None

    def test_get_report_malformed_json(self, dirs, chamber):
        """Malformed JSON in jail report falls through gracefully."""
        jailed = dirs.jail / "malformed"
        jailed.mkdir(parents=True)
        (jailed / "scan-report.json").write_text("{not valid json!!!")

        # Should fall through and also check reports dir, finding nothing
        result = chamber.get_report("malformed")
        assert result is None


# =========================================================================
# 9. purge_jail
# =========================================================================


class TestPurgeJail:
    """Tests for SkillIsolationChamber.purge_jail."""

    def test_purge_empty_jail(self, dirs, chamber):
        """Purging an empty jail returns 0."""
        count, msg = chamber.purge_jail()

        assert count == 0
        assert "0" in msg or "empty" in msg.lower()

    def test_purge_populated_jail(self, dirs, chamber):
        """Purging removes all jailed skills and returns the count."""
        for name in ("bad1", "bad2", "bad3"):
            d = dirs.jail / name
            d.mkdir(parents=True)
            (d / "SKILL.md").write_text(f"# {name}")

        count, msg = chamber.purge_jail()

        assert count == 3
        assert "3" in msg
        # Jail should now be empty of directories
        remaining = [d for d in dirs.jail.iterdir() if d.is_dir()]
        assert remaining == []

    def test_purge_ignores_files(self, dirs, chamber):
        """Purge only removes directories, not loose files."""
        # A directory entry
        d = dirs.jail / "skill-dir"
        d.mkdir()
        (d / "SKILL.md").write_text("skill")

        # A loose file (not a skill directory)
        (dirs.jail / "stray-file.txt").write_text("oops")

        count, msg = chamber.purge_jail()

        assert count == 1
        # The loose file should still be there
        assert (dirs.jail / "stray-file.txt").exists()


# =========================================================================
# Edge cases and integration-style tests
# =========================================================================


class TestEdgeCases:
    """Additional edge cases and integration flows."""

    def test_full_lifecycle_pass(self, dirs, chamber):
        """Full lifecycle: accept -> scan (pass) -> approve -> installed."""
        src = _make_skill_dir(dirs.tmp / "lifecycle", "lifecycle-skill")

        # Accept
        ok, msg = chamber.accept_skill(src, "lifecycle-skill")
        assert ok is True

        # Scan (mocked pass)
        mock_report = _make_report("lifecycle-skill", verdict="pass")
        with patch.object(
            chamber.scanner, "scan", return_value=mock_report
        ):
            report, msg = chamber.scan_skill("lifecycle-skill")
        assert report.verdict == "pass"

        # Approve
        ok, msg = chamber.approve_skill("lifecycle-skill")
        assert ok is True
        assert (dirs.global_skills / "lifecycle-skill" / "SKILL.md").exists()

    def test_full_lifecycle_fail_jail_release(self, dirs, chamber):
        """Full lifecycle: accept -> scan (fail) -> jail -> release (pass)."""
        src = _make_skill_dir(dirs.tmp / "lifecycle2", "jailbird")

        # Accept
        ok, _ = chamber.accept_skill(src, "jailbird")
        assert ok is True

        # Scan (mocked fail)
        fail_report = _make_report(
            "jailbird", verdict="fail", risk_level="dangerous", critical=1
        )
        with patch.object(
            chamber.scanner, "scan", return_value=fail_report
        ):
            report, _ = chamber.scan_skill("jailbird")
        assert report.verdict == "fail"

        # Jail
        ok, _ = chamber.jail_skill("jailbird", report)
        assert ok is True
        assert (dirs.jail / "jailbird").exists()

        # Release (now passes)
        pass_report = _make_report("jailbird", verdict="pass")
        with patch.object(
            chamber.scanner, "scan", return_value=pass_report
        ):
            ok, msg = chamber.release_from_jail("jailbird")
        assert ok is True
        assert not (dirs.jail / "jailbird").exists()
        assert (dirs.chamber / "jailbird" / "SKILL.md").exists()

    def test_manual_mode_returns_manual_review(self, dirs):
        """In manual mode, accept_and_scan with a passing scan still returns manual_review if the scanner says so."""
        config = IsolationConfig(mode="manual", notify_on_jail=False)
        manual_chamber = SkillIsolationChamber(config=config)

        src = _make_skill_dir(dirs.tmp / "manual_src", "manual-skill")

        # Scanner returns manual_review (as manual mode typically does)
        mock_report = _make_report(
            "manual-skill", verdict="manual_review", risk_level="safe"
        )
        with patch.object(
            manual_chamber.scanner, "scan", return_value=mock_report
        ):
            report, msg = manual_chamber.accept_and_scan(src)

        assert report.verdict == "manual_review"
        # Should NOT be auto-installed
        assert not (dirs.global_skills / "manual-skill").exists()
        # Should be in chamber
        assert (dirs.chamber / "manual-skill" / "SKILL.md").exists()

    def test_accept_skill_preserves_nested_files(self, dirs, chamber):
        """Accept preserves the full directory tree inside the skill."""
        src = dirs.tmp / "nested_src" / "deep-skill"
        src.mkdir(parents=True)
        (src / "SKILL.md").write_text("# Deep Skill")
        sub = src / "scripts"
        sub.mkdir()
        (sub / "helper.py").write_text("print('hello')")

        ok, _ = chamber.accept_skill(src)
        assert ok is True
        assert (dirs.chamber / "deep-skill" / "scripts" / "helper.py").exists()

    def test_accept_and_scan_via_skill_md_path(self, dirs, chamber):
        """accept_and_scan resolves a SKILL.md file to its parent directory."""
        src = _make_skill_dir(dirs.tmp / "md_src", "via-md")
        skill_md_path = src / "SKILL.md"

        mock_report = _make_report("via-md", verdict="pass")
        with patch.object(
            chamber.scanner, "scan", return_value=mock_report
        ):
            report, msg = chamber.accept_and_scan(skill_md_path)

        assert report.verdict == "pass"
        assert (dirs.global_skills / "via-md" / "SKILL.md").exists()
