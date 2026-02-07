#!/usr/bin/env python3
"""
Tweek CLI - GAH! Security for your AI agents.

Usage:
    tweek install [--scope global|project]
    tweek uninstall [--scope global|project]
    tweek doctor
    tweek config [--skill NAME] [--preset paranoid|cautious|trusted]
    tweek vault store SKILL KEY VALUE
    tweek vault get SKILL KEY
    tweek vault migrate-env [--dry-run]
    tweek logs [--limit N] [--type TYPE]
    tweek logs stats [--days N]
    tweek logs export [--days N] [--output FILE]
    tweek skills chamber list|import|scan|approve|reject
    tweek skills jail list|rescan|release|purge
    tweek skills report NAME
    tweek skills status
    tweek skills config [--mode auto|manual]
"""
from __future__ import annotations

import click

from tweek import __version__
from tweek.cli_helpers import TieredGroup


# =============================================================================
# MAIN CLI GROUP
# =============================================================================

@click.group(cls=TieredGroup)
@click.version_option(version=__version__, prog_name="tweek")
def main():
    """Tweek - Security for AI agents.

    GAH! TOO MUCH PRESSURE on your credentials!
    """
    pass


# =============================================================================
# REGISTER ALL COMMAND MODULES
# =============================================================================

# Install / Uninstall (Tweek package lifecycle)
from tweek.cli_install import install
from tweek.cli_uninstall import uninstall

# Protect / Unprotect (per-tool protection lifecycle)
from tweek.cli_protect import protect, unprotect

# Core commands (status, trust, untrust, doctor, update/upgrade, audit)
from tweek.cli_core import status, trust, untrust, doctor, update, upgrade, audit

# Configuration
from tweek.cli_config import config
from tweek.cli_configure import configure

# Vault & License
from tweek.cli_vault import vault, license_group

# Logs
from tweek.cli_logs import logs

# Proxy
from tweek.cli_proxy import proxy

# Plugins
from tweek.cli_plugins import plugins

# MCP
from tweek.cli_mcp import mcp

# Skills
from tweek.cli_skills import skills

# Dry-run (renamed from sandbox)
from tweek.cli_dry_run import dry_run

# Scan (static file/URL security scanner)
from tweek.cli_scan import scan

# Security (override, feedback)
from tweek.cli_security import override_group, feedback_group

# Memory
from tweek.cli_memory import memory_group


# Register all commands
for cmd in [
    install,
    uninstall,
    protect,
    unprotect,
    status,
    trust,
    untrust,
    doctor,
    update,
    upgrade,
    audit,
    config,
    configure,
    vault,
    license_group,
    logs,
    proxy,
    plugins,
    mcp,
    skills,
    scan,
    dry_run,
    override_group,
    feedback_group,
    memory_group,
]:
    main.add_command(cmd)

# Model management (optional dependency)
try:
    from tweek.cli_model import model as model_group
    main.add_command(model_group)
except ImportError:
    pass


if __name__ == "__main__":
    main()
