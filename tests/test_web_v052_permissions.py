from __future__ import annotations

import os
from pathlib import Path
import stat
import subprocess

ROOT = Path(__file__).parents[1]
NORMALIZER = ROOT / "deploy" / "normalize-release-permissions.sh"


def test_release_permission_normalizer_fixes_restrictive_tree_in_test_mode(tmp_path):
    release = tmp_path / "release"
    (release / "frontend/assets").mkdir(parents=True)
    (release / "migrations/versions").mkdir(parents=True)
    (release / "deploy").mkdir(parents=True)
    (release / "frontend/index.html").write_text("ok\n", encoding="utf-8")
    (release / "migrations/env.py").write_text("# env\n", encoding="utf-8")
    (release / "migrations/versions/0001.py").write_text("# rev\n", encoding="utf-8")
    (release / "deploy/helper.sh").write_text("#!/bin/sh\n", encoding="utf-8")

    for directory in [release, release / "frontend", release / "frontend/assets", release / "migrations", release / "migrations/versions", release / "deploy"]:
        directory.chmod(0o700)
    for file in [release / "frontend/index.html", release / "migrations/env.py", release / "migrations/versions/0001.py", release / "deploy/helper.sh"]:
        file.chmod(0o600)

    env = os.environ.copy()
    env["WBCZ_RELEASE_NORMALIZE_TEST_MODE"] = "1"
    result = subprocess.run(
        ["sh", str(NORMALIZER), str(release)],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "RELEASE_PERMISSIONS_NORMALIZED=YES" in result.stdout

    assert stat.S_IMODE(release.stat().st_mode) == 0o755
    assert stat.S_IMODE((release / "frontend").stat().st_mode) == 0o755
    assert stat.S_IMODE((release / "migrations/versions").stat().st_mode) == 0o755
    assert stat.S_IMODE((release / "frontend/index.html").stat().st_mode) == 0o644
    assert stat.S_IMODE((release / "migrations/env.py").stat().st_mode) == 0o644
    assert stat.S_IMODE((release / "migrations/versions/0001.py").stat().st_mode) == 0o644
    assert stat.S_IMODE((release / "deploy/helper.sh").stat().st_mode) == 0o755


def test_release_permission_normalizer_rejects_arbitrary_production_target(tmp_path):
    release = tmp_path / "release"
    release.mkdir()
    env = os.environ.copy()
    env.pop("WBCZ_RELEASE_NORMALIZE_TEST_MODE", None)
    result = subprocess.run(
        ["sh", str(NORMALIZER), str(release)],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode != 0
    assert "refusing to normalize unexpected path" in result.stderr
