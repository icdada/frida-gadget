"""Tests for scripts.cli."""
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
