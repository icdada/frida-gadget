"""Tests for scripts.smali."""
import pytest

from scripts import smali


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

    assert smali.insert_load_library_call(text, "libfrida-gadget") is True
    assert text[3] == '    const-string v0, "frida-gadget"'
    assert "System;->loadLibrary" in text[4]


def test_locals_zero_is_raised_to_one():
    """A method with no registers gets one for the library name."""
    text = [
        ".method protected onCreate(Landroid/os/Bundle;)V",
        "    .locals 0",
        "    return-void",
    ]

    assert smali.insert_load_library_call(text, "libfoo") is True
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

    assert smali.insert_load_library_call(text, "libfoo") is True
    assert 'const-string v0, "foo"' in text[5]


def test_no_entrypoint_reports_failure():
    """A class without onCreate or <init> cannot be patched."""
    assert smali.insert_load_library_call([".class public Lcom/e/Main;"], "libfoo") is False


def test_trailing_method_declaration_does_not_crash():
    """A truncated smali file must not raise IndexError."""
    assert smali.insert_load_library_call(
        [".method protected onCreate(Landroid/os/Bundle;)V"], "libfoo"
    ) is False


def test_activity_smali_is_found_in_a_split_dex(tmp_path):
    """Classes live in smali_classes<N> once the APK is multidex."""
    target = tmp_path / "smali_classes3" / "com" / "e" / "Main.smali"
    target.parent.mkdir(parents=True)
    target.write_text(".class public Lcom/e/Main;", encoding="utf-8")

    found, number = smali.find_activity_smali(tmp_path, "com.e.Main")

    assert found == target
    assert number == 3


def test_activity_smali_in_the_primary_dex_has_no_number(tmp_path):
    """The plain 'smali' directory maps to classes.dex."""
    target = tmp_path / "smali" / "com" / "e" / "Main.smali"
    target.parent.mkdir(parents=True)
    target.write_text(".class public Lcom/e/Main;", encoding="utf-8")

    assert smali.find_activity_smali(tmp_path, "com.e.Main") == (target, None)


def test_missing_activity_smali_is_reported(tmp_path):
    """A class apktool never produced stops the run."""
    (tmp_path / "smali").mkdir()
    with pytest.raises(FileNotFoundError):
        smali.find_activity_smali(tmp_path, "com.e.Missing")
