"""Tests for scripts.frida_github."""
import pytest

from scripts.frida_github import FridaGithub

DEFAULT = "https://api.github.com/repos/frida/frida"


@pytest.mark.parametrize(
    "reference",
    [
        "myuser/my-frida-fork",
        "github.com/myuser/my-frida-fork",
        "https://github.com/myuser/my-frida-fork",
        "http://github.com/myuser/my-frida-fork",
        "https://www.github.com/myuser/my-frida-fork",
        "https://github.com/myuser/my-frida-fork/",
        "https://github.com/myuser/my-frida-fork.git",
        "  myuser/my-frida-fork  ",
    ],
)
def test_accepted_repository_references(reference):
    """Every way of naming a github.com repository resolves the same."""
    expected = "https://api.github.com/repos/myuser/my-frida-fork"
    assert FridaGithub.parse_repo(reference) == expected


@pytest.mark.parametrize(
    "reference",
    [
        "https://evil.com/frida/frida",
        "evil.com/frida/frida",
        "http://gitlab.com/a/b",
        "justrepo",
        "owner/repo/extra",
        "https://github.com/onlyowner",
        "/leading/slash",
    ],
)
def test_rejected_repository_references(reference):
    """Anything that is not a github.com owner/repo is refused."""
    with pytest.raises(ValueError):
        FridaGithub.parse_repo(reference)


def test_default_repository():
    """Without --github-repo the upstream frida releases are used."""
    assert FridaGithub.parse_repo("") == DEFAULT
    assert FridaGithub().github_api_base == DEFAULT


def test_release_endpoints_follow_the_repository():
    """Both endpoints are derived from the selected repository."""
    github = FridaGithub("17.0.0", "myuser/fork")

    assert github.latest_release_url.endswith("/myuser/fork/releases/latest")
    assert github.tagged_release_url.format(tag="17.0.0").endswith(
        "/myuser/fork/releases/tags/17.0.0"
    )


def test_gadget_version_is_kept():
    """The version selects which release the assets come from."""
    assert FridaGithub("17.0.0").gadget_version == "17.0.0"
