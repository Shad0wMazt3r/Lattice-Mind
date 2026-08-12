"""Smoke tests for the installable wheel contents."""

import os
import subprocess
import sys
import zipfile
from pathlib import Path


def test_built_wheel_contains_runtime_modules_and_assets(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    wheel_dir = tmp_path / "wheel"
    wheel_dir.mkdir()
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"

    build = subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--no-build-isolation",
            "--wheel-dir",
            str(wheel_dir),
            str(repo_root),
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert build.returncode == 0, build.stderr

    wheels = list(wheel_dir.glob("lattice_mind-*.whl"))
    assert len(wheels) == 1
    with zipfile.ZipFile(wheels[0]) as wheel:
        members = set(wheel.namelist())
        metadata_name = next(name for name in members if name.endswith(".dist-info/METADATA"))
        metadata = wheel.read(metadata_name).decode("utf-8")
        wheel.extractall(tmp_path / "installed")

    source_yaml = {
        path.relative_to(repo_root).as_posix()
        for path in (repo_root / "lattice_mind" / "trees" / "yaml").rglob("*")
        if path.suffix in {".yaml", ".yml"}
    }
    wheel_yaml = {
        name for name in members if name.endswith((".yaml", ".yml"))
    }

    assert "Requires-Dist: PyYAML>=6.0" in metadata
    assert "Requires-Dist: httpx2>=2.0.0; extra == \"dev\"" in metadata
    assert "Requires-Dist: setuptools>=69; extra == \"dev\"" in metadata
    assert "lattice_mind/core/tree_loader.py" in members
    assert "lattice_mind/engines/detection.py" in members
    assert "lattice_mind/frontend/index.html" in members
    assert "lattice_mind/frontend/script.js" in members
    assert "lattice_mind/frontend/style.css" in members
    assert wheel_yaml == source_yaml

    smoke_env = env.copy()
    smoke_env["PYTHONPATH"] = str(tmp_path / "installed")
    smoke_env["LATTICE_MIND_DB"] = str(tmp_path / "wheel-smoke.db")
    smoke = subprocess.run(
        [
            sys.executable,
            "-c",
            "from pathlib import Path; "
            "import lattice_mind; "
            "from lattice_mind.core.tree_loader import TreeRegistry; "
            "root = Path(lattice_mind.__file__).parent; "
            "registry = TreeRegistry(); "
            "registry.load_from_directory(str(root / 'trees' / 'yaml')); "
            "assert len(registry.list_trees()) == 46; "
            "assert not registry.validation_errors; "
            "assert (root / 'frontend' / 'index.html').is_file(); "
            "from lattice_mind.api import server; "
            "assert server.app.title == 'Lattice Mind API'; "
            "assert server.FRONTEND_DIR == root / 'frontend'",
        ],
        cwd=tmp_path,
        env=smoke_env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert smoke.returncode == 0, smoke.stderr
