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
    """The current prerelease must describe bounded V3 attorney review without erasing beta.9."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    roadmap = (ROOT / "docs" / "roadmap.md").read_text(encoding="utf-8")
    beta10_heading = "## [0.1.0-beta.10] - 2026-09-14"
    beta9_heading = "## [0.1.0-beta.9] - 2026-08-26"
    _, found_beta10_heading, beta10_and_history = changelog.partition(beta10_heading)
    beta10_section, found_beta9_heading, _ = beta10_and_history.partition(beta9_heading)
    readme_words = " ".join(readme.replace("> ", "").split())
    beta10_changelog_words = " ".join(beta10_section.split())
    roadmap_words = " ".join(roadmap.split())
    release_surfaces = (
        readme_words.casefold(),
        beta10_changelog_words.casefold(),
    )

    assert readme.splitlines()[2].startswith(
        "> **Experimental beta (`v0.1.0-beta.10`).**"
    )
    assert "TO_BE_BOUND" not in readme
    assert "packages project version `0.1.0`" in readme_words
    assert "Protocol 2.1 remains the new-run default" in readme_words
    assert "Protocol 2.2 remains opt-in and experimental" in readme_words
    assert "No PyPI distribution is published" in readme_words
    assert (
        "No performance, benchmark, legal-correctness, or report-quality claim is made"
        in readme_words
    )
    assert (
        "Subsequent successful verification is not evidence that the underlying issue "
        "has been repaired"
        in readme_words
    )
    assert found_beta10_heading == beta10_heading
    assert found_beta9_heading == beta9_heading
    for release_surface in release_surfaces:
        assert "delivery-readiness" in release_surface
        assert "ordinary omissions" in release_surface
        assert "integrity" in release_surface
        assert "beta.9 tag or artifact" in release_surface
        assert "saved-run verification refusal remains" in release_surface
        assert "attorney" in release_surface
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
