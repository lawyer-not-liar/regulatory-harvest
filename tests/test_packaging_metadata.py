import importlib.resources
import subprocess
import tarfile
import tomllib
from pathlib import Path

from regulatory_harvest import __version__

ROOT = Path(__file__).parents[1]


def test_public_package_metadata_supports_declared_install_surfaces() -> None:
    """Incomplete distribution metadata would make the first public package ambiguous."""
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))[
        "project"
    ]

    assert project["name"] == "regulatory-harvest"
    assert project["version"] == "0.1.0"
    assert __version__ == project["version"]
    assert project["requires-python"] == ">=3.11"
    assert project["license"] == "Apache-2.0"
    assert project["scripts"] == {"harvest": "regulatory_harvest.cli:main"}
    assert {
        "beautifulsoup4>=4.12",
        "httpx>=0.27",
        "pydantic>=2.8",
        "pypdf>=6.15.0",
    } == set(project["dependencies"])
    assert set(project["optional-dependencies"]) == {"dev", "openai"}
    assert project["urls"] == {
        "Changelog": "https://github.com/lawyer-not-liar/regulatory-harvest/blob/main/CHANGELOG.md",
        "Homepage": "https://github.com/lawyer-not-liar/regulatory-harvest",
        "Repository": "https://github.com/lawyer-not-liar/regulatory-harvest.git",
    }
    assert project["authors"] == [{"name": "Regulatory Harvest maintainers"}]
    assert project["maintainers"] == [{"name": "Regulatory Harvest maintainers"}]
    assert "Intended Audience :: Legal Industry" in project["classifiers"]


def test_experimental_beta_release_surfaces_are_coherent() -> None:
    """The prerelease surfaces must describe the bounded readiness companion."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    roadmap = (ROOT / "docs" / "roadmap.md").read_text(encoding="utf-8")
    beta9_heading = "## [0.1.0-beta.9] - 2026-08-26"
    beta8_heading = "## [0.1.0-beta.8] - 2026-08-24"
    _, found_beta9_heading, beta9_and_history = changelog.partition(beta9_heading)
    beta9_section, found_beta8_heading, _ = beta9_and_history.partition(beta8_heading)
    readme_words = " ".join(readme.split())
    beta9_changelog_words = " ".join(beta9_section.split())
    roadmap_words = " ".join(roadmap.split())
    release_surfaces = (
        readme_words.replace("> ", "").casefold(),
        beta9_changelog_words.casefold(),
    )

    assert "v0.1.0-beta.9" in readme
    assert "TO_BE_BOUND" not in readme
    assert "packages project version `0.1.0`" in readme_words
    assert "Protocol 2.1 remains the new-run default" in readme_words
    assert found_beta9_heading == beta9_heading
    assert found_beta8_heading == beta8_heading
    for release_surface in release_surfaces:
        assert "protocol 2.2 remains opt-in and experimental" in release_surface
        assert "stable evaluation baseline" in release_surface
        assert "delivery-readiness companion" in release_surface
        assert "report-blind" in release_surface
        assert "high_assurance" in release_surface
        assert "review_ready_with_gaps" in release_surface
        assert "not_deliverable" in release_surface
        assert "public synthetic validation" in release_surface
        assert "no private matter rollout validation was performed" in release_surface
        assert (
            "no performance, benchmark, legal-correctness, or report-quality claim is made"
            in release_surface
        )
        assert "no pypi distribution is published" in release_surface
    assert "LLM supplies substantive judgments" in roadmap_words
    assert "deterministic code constructs canonical artifacts" in roadmap_words


def test_installed_package_exposes_type_marker_and_prompt_resources() -> None:
    """Dropping package data would break typed consumers and model-backed runs after install."""
    package = importlib.resources.files("regulatory_harvest")
    prompts = package.joinpath("analysis", "prompts")

    assert package.joinpath("py.typed").is_file()
    assert prompts.joinpath("map-v1.md").read_text(encoding="utf-8")
    assert prompts.joinpath("build-v1.md").read_text(encoding="utf-8")


def test_source_distribution_excludes_generated_development_state(
    tmp_path: Path,
) -> None:
    """A missing build exclusion must not leak local test caches into the sdist."""
    result = subprocess.run(
        ["uv", "build", "--sdist", "--out-dir", str(tmp_path)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr

    (archive,) = tmp_path.glob("*.tar.gz")
    with tarfile.open(archive, "r:gz") as source_distribution:
        paths = [Path(name).parts[1:] for name in source_distribution.getnames()]

    prohibited_roots = {".hypothesis", ".mypy_cache", ".pytest_cache", ".venv", "build", "dist"}
    assert not {
        parts[0]
        for parts in paths
        if parts and parts[0] in prohibited_roots
    }
