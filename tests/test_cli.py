"""Tests for scripts.cli."""
import json
from pathlib import Path

import pytest

from scripts import cli


# --- architecture --------------------------------------------------------


@pytest.mark.parametrize(
    "given, expected",
    [
        ("arm64-v8a", "arm64"),
        ("armeabi-v7a", "arm"),
        ("multi-arch", "multi-arch"),
        ("MULTI-ARCH", "multi-arch"),
        ("x86_64", "x86_64"),
    ],
)
def test_arch_aliases(given, expected):
    """Device ABI names are accepted alongside the short names."""
    assert cli.normalize_arch(given, False) == expected


def test_unsupported_arch_is_rejected():
    """An architecture we cannot download a gadget for stops the run."""
    with pytest.raises(SystemExit):
        cli.validate_arch("mips")


def test_multi_arch_skips_validation():
    """'multi-arch' is resolved from the APK later on."""
    assert cli.validate_arch("multi-arch") == "multi-arch"


# --- gadget naming -------------------------------------------------------


def test_custom_gadget_name_wins():
    """--custom-gadget-name decides the library name."""
    assert cli.resolve_gadget_name("/x/frida.so", "mygadget", "arm64") == "mygadget.so"


def test_custom_gadget_name_applies_to_multi_arch():
    """One name resolves in every lib/<abi>, so it works for multi-arch too."""
    assert cli.resolve_gadget_name("/x/frida.so", "mygadget", "multi-arch") == "mygadget.so"


def test_multi_arch_uses_an_architecture_free_name():
    """The downloaded name carries the ABI, which loadLibrary cannot use."""
    name = cli.resolve_gadget_name("/x/frida-gadget-17-android-arm64.so", None, "multi-arch")
    assert name == "libfrida-gadget.so"


def test_downloaded_gadget_keeps_its_name():
    """Without overrides the downloaded file name is used as-is."""
    assert cli.resolve_gadget_name("/x/frida-gadget.so", None, "arm64") == "frida-gadget.so"


def test_unknown_architecture_has_no_abi_directory(tmp_path):
    """An ABI directory we do not know about is refused."""
    with pytest.raises(NotImplementedError):
        cli.prepare_lib_dir(tmp_path, "mips")


def test_lib_directory_is_created(tmp_path):
    """lib/<abi> is created even when the APK ships no native libraries."""
    lib_dir = cli.prepare_lib_dir(tmp_path, "arm64")
    assert lib_dir == tmp_path / "lib" / "arm64-v8a"
    assert lib_dir.is_dir()


# --- gadget config -------------------------------------------------------


def test_config_is_generated_for_a_script(tmp_path):
    """--js alone produces a config pointing at the uploaded script."""
    upload_files = {"config": None, "script": "s.js"}
    cli.write_gadget_config(None, "s.js", tmp_path, "libfoo", upload_files)

    written = json.loads((tmp_path / "libfoo.config.so").read_text(encoding="utf-8"))
    assert written == {"interaction": {"type": "script", "path": "libfoo.script.so"}}
    assert "config" not in upload_files


def test_supplied_config_gets_the_script_path_rewritten(tmp_path):
    """The path in the user's config is replaced by the uploaded name."""
    config = tmp_path / "gadget.json"
    config.write_text(
        json.dumps({"interaction": {"type": "script", "path": "/data/local/tmp/a.js"}}),
        encoding="utf-8",
    )
    upload_files = {"config": str(config), "script": "s.js"}

    cli.write_gadget_config(str(config), "s.js", tmp_path, "libfoo", upload_files)

    written = json.loads((tmp_path / "libfoo.config.so").read_text(encoding="utf-8"))
    assert written["interaction"]["path"] == "libfoo.script.so"
    assert "config" not in upload_files


def test_config_without_script_is_uploaded_untouched(tmp_path):
    """Without --js the config is left for the upload step to copy."""
    config = tmp_path / "gadget.json"
    config.write_text(
        json.dumps({"interaction": {"type": "listen", "address": "127.0.0.1"}}),
        encoding="utf-8",
    )
    upload_files = {"config": str(config), "script": None}

    cli.write_gadget_config(str(config), None, tmp_path, "libfoo", upload_files)

    assert not (tmp_path / "libfoo.config.so").exists()
    assert upload_files["config"] == str(config)


def test_config_must_declare_an_interaction(tmp_path):
    """A config frida cannot act on stops the run."""
    config = tmp_path / "gadget.json"
    config.write_text(json.dumps({}), encoding="utf-8")

    with pytest.raises(SystemExit):
        cli.load_config_data(str(config))


def test_script_config_must_declare_a_path(tmp_path):
    """'type: script' without a path would leave the gadget idle."""
    config = tmp_path / "gadget.json"
    config.write_text(json.dumps({"interaction": {"type": "script"}}), encoding="utf-8")

    with pytest.raises(SystemExit):
        cli.warn_config_without_script(str(config))


# --- delayed javascript --------------------------------------------------


def test_delayed_script_is_written_outside_the_source_directory(tmp_path):
    """The user's own files must not be overwritten or required to be writable."""
    source = tmp_path / "hook.js"
    source.write_text("console.log('x');", encoding="utf-8")
    bystander = tmp_path / "hook_wrapped.js"
    bystander.write_text("keep me", encoding="utf-8")

    wrapped = cli.wrap_js_file(str(source), 3)

    assert Path(wrapped).parent != tmp_path
    assert bystander.read_text(encoding="utf-8") == "keep me"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["hook.js", "hook_wrapped.js"]

    contents = Path(wrapped).read_text(encoding="utf-8")
    assert "console.log('x');" in contents
    assert "}, 3000);" in contents


def test_delay_requires_a_script():
    """--js-delay on its own has nothing to wrap."""
    with pytest.raises(SystemExit):
        cli.wrap_js_file(None, 3)


def test_negative_delay_is_rejected():
    """A negative timeout would run the script immediately."""
    with pytest.raises(SystemExit):
        cli.wrap_js_file("hook.js", -1)


def test_missing_script_is_reported(tmp_path):
    """A path that does not exist stops the run."""
    with pytest.raises(SystemExit):
        cli.wrap_js_file(str(tmp_path / "absent.js"), 1)


# --- frida version detection ---------------------------------------------


def recording_github(asked):
    """Build a FridaGithub stand-in that records the version it was given."""

    class RecordingGithub:  # pylint: disable=too-few-public-methods
        """Reports a release whose assets never match."""

        def __init__(self, version, github_repo=""):
            asked["version"] = version
            asked["repo"] = github_repo

        @staticmethod
        def get_assets():
            """Report a release with no matching asset."""
            return []

    return RecordingGithub


def test_gadget_version_falls_back_to_the_installed_frida(monkeypatch, tmp_path):
    """Without --frida-version the version frida reports is used."""
    monkeypatch.setattr(cli, "INSTALLED_FRIDA_VERSION", "17.0.0")
    monkeypatch.setattr(cli, "FILE_DIR", tmp_path)
    asked = {}

    monkeypatch.setattr(cli, "FridaGithub", recording_github(asked))
    with pytest.raises(FileNotFoundError):
        cli.download_gadget("arm64")

    assert asked["version"] == "17.0.0"


def test_missing_frida_asks_for_an_explicit_version(monkeypatch):
    """Without frida installed the version has to be named on the command line."""
    monkeypatch.setattr(cli, "INSTALLED_FRIDA_VERSION", None)

    with pytest.raises(SystemExit):
        cli.download_gadget("arm64")


def test_explicit_version_works_without_frida(monkeypatch, tmp_path):
    """--frida-version makes the frida package unnecessary."""
    monkeypatch.setattr(cli, "INSTALLED_FRIDA_VERSION", None)
    monkeypatch.setattr(cli, "FILE_DIR", tmp_path)
    asked = {}

    monkeypatch.setattr(cli, "FridaGithub", recording_github(asked))
    with pytest.raises(FileNotFoundError):
        cli.download_gadget("arm64", frida_version="16.1.3")

    assert asked["version"] == "16.1.3"
