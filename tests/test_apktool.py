"""Tests for scripts.apktool."""
import tempfile
import zipfile

import pytest

from scripts import apktool


# --- decompile directory -------------------------------------------------


@pytest.mark.parametrize(
    "name, expected",
    [
        ("documents.apk", "documents"),
        ("my.app.v1.2.apk", "my.app.v1.2"),
        # Without an extension there is nothing to strip, and truncating the
        # name used to point at the directory holding the APK
        ("app", "app_decompiled"),
        ("base", "base_decompiled"),
        (".apk", ".apk_decompiled"),
    ],
)
def test_decompile_target_stays_next_to_the_apk(tmp_path, name, expected):
    """The decompile directory is a sibling of the APK, never its parent."""
    apk = tmp_path / name
    apk.write_bytes(b"PK\x03\x04")

    decompiled = apktool.get_decompiled_path(apk)

    assert decompiled.name == expected
    assert decompiled.parent == tmp_path.resolve()
    assert decompiled != tmp_path.resolve()


def test_empty_directory_is_reusable(tmp_path):
    """Nothing can be lost by removing an empty directory."""
    assert apktool.is_reusable_decompile_dir(tmp_path) is True


@pytest.mark.parametrize("marker", ["apktool.yml", "AndroidManifest.xml", "smali"])
def test_apktool_output_is_reusable(tmp_path, marker):
    """A previous decompile, complete or interrupted, may be replaced."""
    (tmp_path / marker).write_text("x", encoding="utf-8")
    assert apktool.is_reusable_decompile_dir(tmp_path) is True


def test_unrelated_directory_is_not_reusable(tmp_path):
    """A directory that merely shares the APK name must survive."""
    (tmp_path / "holiday.jpg").write_text("x", encoding="utf-8")
    assert apktool.is_reusable_decompile_dir(tmp_path) is False


def test_regular_file_is_not_reusable(tmp_path):
    """A file cannot be handed to rmtree."""
    target = tmp_path / "plain"
    target.write_text("x", encoding="utf-8")
    assert apktool.is_reusable_decompile_dir(target) is False


# --- apktool -------------------------------------------------------------


def test_decompile_options_carry_the_flags(tmp_path):
    """The apktool command line reflects the CLI flags."""
    options, no_res = apktool.build_decompile_options(tmp_path, True, True, None)

    assert options[:2] == ["d", "-o"]
    assert "--force" in options
    assert "--force-manifest" in options
    assert "--no-res" in options
    assert no_res is True


def test_no_res_is_not_passed_twice(tmp_path):
    """--no-res given both ways still reaches apktool once."""
    options, no_res = apktool.build_decompile_options(tmp_path, False, True, "--no-res")

    assert options.count("--no-res") == 1
    assert no_res is True


def test_no_res_in_decompile_opts_updates_the_flag(tmp_path):
    """--decompile-opts can turn on no_res for the injection step."""
    options, no_res = apktool.build_decompile_options(tmp_path, False, False, "--no-res")

    assert options.count("--no-res") == 1
    assert no_res is True


def test_apktool_falls_back_to_the_one_on_path(monkeypatch):
    """Without --apktool-path the command found on PATH is used."""
    monkeypatch.setattr(apktool, "APKTOOL", "/usr/local/bin/apktool")
    assert apktool.resolve_apktool(None) == "/usr/local/bin/apktool"


def test_missing_apktool_is_reported(monkeypatch):
    """Without apktool anywhere the run cannot start."""
    monkeypatch.setattr(apktool, "APKTOOL", None)
    with pytest.raises(FileNotFoundError):
        apktool.resolve_apktool(None)


def test_apktool_path_must_exist():
    """A missing --apktool-path is reported instead of failing later."""
    with pytest.raises(SystemExit):
        apktool.resolve_apktool("/nonexistent/apktool")


# --- restoring the original dex files ------------------------------------


def build_apk(path, entries):
    """Write a zip holding the given name to bytes mapping."""
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return path


def read_apk(path):
    """Read a zip back into a name to bytes mapping."""
    with zipfile.ZipFile(path) as archive:
        return {i.filename: archive.read(i.filename) for i in archive.infolist()}


def test_only_the_patched_dex_comes_from_the_rebuild(tmp_path):
    """Every other dex is taken from the original APK, resources from the rebuild."""
    original = build_apk(
        tmp_path / "app.apk",
        {
            "classes.dex": b"orig-1",
            "classes2.dex": b"orig-2",
            "classes3.dex": b"orig-3",
            "res/layout.xml": b"orig-res",
        },
    )
    recompiled = build_apk(
        tmp_path / "rebuilt.apk",
        {
            "classes.dex": b"rebuilt-1",
            "classes2.dex": b"rebuilt-2",
            "classes3.dex": b"rebuilt-3",
            "res/layout.xml": b"rebuilt-res",
        },
    )

    apktool.restore_original_dex(original, recompiled, 2)

    result = read_apk(recompiled)
    assert result["classes2.dex"] == b"rebuilt-2", "the patched dex must survive"
    assert result["classes.dex"] == b"orig-1"
    assert result["classes3.dex"] == b"orig-3"
    assert result["res/layout.xml"] == b"rebuilt-res"


@pytest.mark.parametrize("number", [None, 1])
def test_the_primary_dex_is_the_default_target(tmp_path, number):
    """smali/ and smali_classes1/ both map to classes.dex."""
    original = build_apk(tmp_path / "app.apk", {"classes.dex": b"orig", "classes2.dex": b"orig-2"})
    recompiled = build_apk(
        tmp_path / f"rebuilt{number}.apk", {"classes.dex": b"new", "classes2.dex": b"new-2"}
    )

    apktool.restore_original_dex(original, recompiled, number)

    result = read_apk(recompiled)
    assert result["classes.dex"] == b"new"
    assert result["classes2.dex"] == b"orig-2"


def test_a_failure_leaves_the_rebuilt_apk_alone(tmp_path):
    """Restoring is best effort, so a broken original must not lose the rebuild."""
    broken = tmp_path / "app.apk"
    broken.write_bytes(b"not a zip at all")
    recompiled = build_apk(tmp_path / "rebuilt.apk", {"classes.dex": b"new"})

    apktool.restore_original_dex(broken, recompiled, None)

    assert read_apk(recompiled) == {"classes.dex": b"new"}


def test_no_temporary_file_is_left_behind(tmp_path, monkeypatch):
    """A failure part way through must not strand a staged APK in the temp dir."""
    staging = tmp_path / "staging"
    staging.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(staging))

    original = build_apk(tmp_path / "app.apk", {"classes.dex": b"orig"})
    recompiled = build_apk(tmp_path / "rebuilt.apk", {"classes.dex": b"new", "classes9.dex": b"x"})

    # classes9.dex is missing from the original, so the copy raises part way
    apktool.restore_original_dex(original, recompiled, None)

    assert not list(staging.iterdir())
