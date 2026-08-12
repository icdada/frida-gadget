"""Tests for scripts.cli."""
import io
import json
import subprocess
import tempfile
import zipfile

import pytest

from scripts import cli


class FakeStdin:  # pylint: disable=too-few-public-methods
    """Stand-in for sys.stdin with a controllable isatty()."""
    def __init__(self, tty):
        """Record whether this stream should look like a terminal."""
        self.tty = tty

    def isatty(self):
        """Report whether this stream is a terminal."""
        return self.tty


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

    decompiled = cli.get_decompiled_path(apk)

    assert decompiled.name == expected
    assert decompiled.parent == tmp_path.resolve()
    assert decompiled != tmp_path.resolve()


def test_empty_directory_is_reusable(tmp_path):
    """Nothing can be lost by removing an empty directory."""
    assert cli.is_reusable_decompile_dir(tmp_path) is True


@pytest.mark.parametrize("marker", ["apktool.yml", "AndroidManifest.xml", "smali"])
def test_apktool_output_is_reusable(tmp_path, marker):
    """A previous decompile, complete or interrupted, may be replaced."""
    (tmp_path / marker).write_text("x", encoding="utf-8")
    assert cli.is_reusable_decompile_dir(tmp_path) is True


def test_unrelated_directory_is_not_reusable(tmp_path):
    """A directory that merely shares the APK name must survive."""
    (tmp_path / "holiday.jpg").write_text("x", encoding="utf-8")
    assert cli.is_reusable_decompile_dir(tmp_path) is False


def test_regular_file_is_not_reusable(tmp_path):
    """A file cannot be handed to rmtree."""
    target = tmp_path / "plain"
    target.write_text("x", encoding="utf-8")
    assert cli.is_reusable_decompile_dir(target) is False


# --- apktool -------------------------------------------------------------


def test_decompile_options_carry_the_flags(tmp_path):
    """The apktool command line reflects the CLI flags."""
    options, no_res = cli.build_decompile_options(tmp_path, True, True, None)

    assert options[:2] == ["d", "-o"]
    assert "--force" in options
    assert "--force-manifest" in options
    assert "--no-res" in options
    assert no_res is True


def test_no_res_is_not_passed_twice(tmp_path):
    """--no-res given both ways still reaches apktool once."""
    options, no_res = cli.build_decompile_options(tmp_path, False, True, "--no-res")

    assert options.count("--no-res") == 1
    assert no_res is True


def test_no_res_in_decompile_opts_updates_the_flag(tmp_path):
    """--decompile-opts can turn on no_res for the injection step."""
    options, no_res = cli.build_decompile_options(tmp_path, False, False, "--no-res")

    assert options.count("--no-res") == 1
    assert no_res is True


def test_apktool_falls_back_to_the_one_on_path(monkeypatch):
    """Without --apktool-path the command found on PATH is used."""
    monkeypatch.setattr(cli, "APKTOOL", "/usr/local/bin/apktool")
    assert cli.resolve_apktool(None) == "/usr/local/bin/apktool"


def test_missing_apktool_is_reported(monkeypatch):
    """Without apktool anywhere the run cannot start."""
    monkeypatch.setattr(cli, "APKTOOL", None)
    with pytest.raises(FileNotFoundError):
        cli.resolve_apktool(None)


def test_apktool_path_must_exist():
    """A missing --apktool-path is reported instead of failing later."""
    with pytest.raises(SystemExit):
        cli.resolve_apktool("/nonexistent/apktool")


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


# --- smali patching ------------------------------------------------------


ONCREATE_SMALI = [
    ".class public Lcom/e/Main;",
    ".method protected onCreate(Landroid/os/Bundle;)V",
    "    .locals 2",
    "    return-void",
    ".end method",
]


def test_load_library_call_is_inserted_into_oncreate():
    """The call lands right after the .locals declaration."""
    text = list(ONCREATE_SMALI)

    assert cli.insert_load_library_call(text, "libfrida-gadget") is True
    assert text[3] == '    const-string v0, "frida-gadget"'
    assert "System;->loadLibrary" in text[4]


def test_locals_zero_is_raised_to_one():
    """A method with no registers gets one for the library name."""
    text = [
        ".method protected onCreate(Landroid/os/Bundle;)V",
        "    .locals 0",
        "    return-void",
    ]

    assert cli.insert_load_library_call(text, "libfoo") is True
    assert text[1].strip() == ".locals 1"


def test_method_without_locals_is_skipped():
    """Without a .locals declaration there is no register to use."""
    text = [
        ".method protected onCreate(Landroid/os/Bundle;)V",
        "    return-void",
        ".end method",
        ".method public constructor <init>()V",
        "    .locals 1",
        "    return-void",
    ]

    assert cli.insert_load_library_call(text, "libfoo") is True
    assert 'const-string v0, "foo"' in text[5]


def test_no_entrypoint_reports_failure():
    """A class without onCreate or <init> cannot be patched."""
    assert cli.insert_load_library_call([".class public Lcom/e/Main;"], "libfoo") is False


def test_trailing_method_declaration_does_not_crash():
    """A truncated smali file must not raise IndexError."""
    assert cli.insert_load_library_call(
        [".method protected onCreate(Landroid/os/Bundle;)V"], "libfoo"
    ) is False


def test_activity_smali_is_found_in_a_split_dex(tmp_path):
    """Classes live in smali_classes<N> once the APK is multidex."""
    target = tmp_path / "smali_classes3" / "com" / "e" / "Main.smali"
    target.parent.mkdir(parents=True)
    target.write_text(".class public Lcom/e/Main;", encoding="utf-8")

    found, number = cli.find_activity_smali(tmp_path, "com.e.Main")

    assert found == target
    assert number == 3


def test_activity_smali_in_the_primary_dex_has_no_number(tmp_path):
    """The plain 'smali' directory maps to classes.dex."""
    target = tmp_path / "smali" / "com" / "e" / "Main.smali"
    target.parent.mkdir(parents=True)
    target.write_text(".class public Lcom/e/Main;", encoding="utf-8")

    assert cli.find_activity_smali(tmp_path, "com.e.Main") == (target, None)


def test_missing_activity_smali_is_reported(tmp_path):
    """A class apktool never produced stops the run."""
    (tmp_path / "smali").mkdir()
    with pytest.raises(FileNotFoundError):
        cli.find_activity_smali(tmp_path, "com.e.Missing")


# --- signing -------------------------------------------------------------


def test_passwords_are_redacted():
    """A failing signer must not print the keystore passwords."""
    cmd = ["java", "--ks", "/k.jks", "--ksKeyPass", "hunter2", "--ksPass", "s3cr3t"]

    redacted = cli.redact_passwords(cmd)

    assert "hunter2" not in redacted
    assert "s3cr3t" not in redacted
    assert redacted.count("***") == 2
    assert cmd[-1] == "s3cr3t", "the original command must not be modified"


def test_redaction_survives_a_trailing_flag():
    """A flag without its value must not walk off the end of the list."""
    assert cli.redact_passwords(["java", "--ksPass"]) == ["java", "--ksPass"]


def test_stdin_without_a_terminal(monkeypatch):
    """A pipe cannot answer a password prompt."""
    monkeypatch.setattr("sys.stdin", io.StringIO())
    assert cli.stdin_is_interactive() is False


def test_stdin_that_was_closed(monkeypatch):
    """A closed stream raises rather than answering isatty()."""
    class Closed:  # pylint: disable=too-few-public-methods
        """Raises the way a closed file object does."""
        def isatty(self):
            """Fail the way a closed stream does."""
            raise ValueError("I/O operation on closed file")

    monkeypatch.setattr("sys.stdin", Closed())
    assert cli.stdin_is_interactive() is False


def test_missing_stdin(monkeypatch):
    """Windowed interpreters can leave sys.stdin unset."""
    monkeypatch.setattr("sys.stdin", None)
    assert cli.stdin_is_interactive() is False


def test_signer_keeps_the_pipe_without_a_terminal(monkeypatch):
    """Handing over a stdin nobody can type into would hang the run."""
    captured = {}
    monkeypatch.setattr(cli, "download_signer", lambda: "/signer.jar")
    monkeypatch.setattr("sys.stdin", FakeStdin(tty=False))
    monkeypatch.setattr(cli.subprocess, "Popen", _popen_recorder(captured))

    cli.sign_apk("/out/app.apk", ks="/k.jks")

    assert captured["stdout"] is subprocess.PIPE
    assert captured["input"] == b"\n"


def test_signer_gets_the_terminal_when_there_is_one(monkeypatch):
    """uber-apk-signer prompts for the passwords it was not given."""
    captured = {}
    monkeypatch.setattr(cli, "download_signer", lambda: "/signer.jar")
    monkeypatch.setattr("sys.stdin", FakeStdin(tty=True))
    monkeypatch.setattr(cli.subprocess, "Popen", _popen_recorder(captured))

    cli.sign_apk("/out/app.apk", ks="/k.jks")

    assert captured["stdout"] is None
    assert captured["input"] is None


def test_signer_keeps_the_pipe_when_both_passwords_are_given(monkeypatch):
    """With nothing left to prompt for there is no reason to give up stdout."""
    captured = {}
    monkeypatch.setattr(cli, "download_signer", lambda: "/signer.jar")
    monkeypatch.setattr("sys.stdin", FakeStdin(tty=True))
    monkeypatch.setattr(cli.subprocess, "Popen", _popen_recorder(captured))

    cli.sign_apk("/out/app.apk", ks="/k.jks", ks_pass="a", ks_key_pass="b")

    assert captured["stdout"] is subprocess.PIPE


def _popen_recorder(captured):
    """Build a Popen stand-in recording how the signer was wired up."""
    class FakeProcess:
        """Reports a successful, silent run."""
        returncode = 0

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def communicate(self, data=None):
            """Record what was written to the signer."""
            captured["input"] = data
            return (b"", None)

    def popen(cmd, stdin=None, stdout=None, stderr=None):
        """Record the streams the signer was given."""
        captured.update(cmd=cmd, stdin=stdin, stdout=stdout, stderr=stderr)
        return FakeProcess()

    return popen


# --- delayed javascript --------------------------------------------------


def test_delayed_script_is_written_outside_the_source_directory(tmp_path):
    """The user's own files must not be overwritten or required to be writable."""
    source = tmp_path / "hook.js"
    source.write_text("console.log('x');", encoding="utf-8")
    bystander = tmp_path / "hook_wrapped.js"
    bystander.write_text("keep me", encoding="utf-8")

    wrapped = cli.wrap_js_file(str(source), 3)

    assert cli.Path(wrapped).parent != tmp_path
    assert bystander.read_text(encoding="utf-8") == "keep me"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["hook.js", "hook_wrapped.js"]

    contents = cli.Path(wrapped).read_text(encoding="utf-8")
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

    cli.restore_original_dex(original, recompiled, 2)

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

    cli.restore_original_dex(original, recompiled, number)

    result = read_apk(recompiled)
    assert result["classes.dex"] == b"new"
    assert result["classes2.dex"] == b"orig-2"


def test_a_failure_leaves_the_rebuilt_apk_alone(tmp_path):
    """Restoring is best effort, so a broken original must not lose the rebuild."""
    broken = tmp_path / "app.apk"
    broken.write_bytes(b"not a zip at all")
    recompiled = build_apk(tmp_path / "rebuilt.apk", {"classes.dex": b"new"})

    cli.restore_original_dex(broken, recompiled, None)

    assert read_apk(recompiled) == {"classes.dex": b"new"}


def test_no_temporary_file_is_left_behind(tmp_path, monkeypatch):
    """A failure part way through must not strand a staged APK in the temp dir."""
    staging = tmp_path / "staging"
    staging.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(staging))

    original = build_apk(tmp_path / "app.apk", {"classes.dex": b"orig"})
    recompiled = build_apk(tmp_path / "rebuilt.apk", {"classes.dex": b"new", "classes9.dex": b"x"})

    # classes9.dex is missing from the original, so the copy raises part way
    cli.restore_original_dex(original, recompiled, None)

    assert not list(staging.iterdir())


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
