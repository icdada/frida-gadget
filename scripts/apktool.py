"""Driving apktool, and the directory it decompiles an APK into."""
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from shutil import which

from .logger import logger

APKTOOL = which("apktool")


def get_decompiled_path(apk_path: Path) -> Path:
    """
    Build the path apktool decompiles the APK into.

    Parameters
    ----------
    apk_path : Path
        path of apk file

    Returns
    -------
    Path
        the decompile directory, next to the APK file

    """
    resolved = apk_path.resolve()
    decompiled_path = resolved.with_suffix("")
    if decompiled_path == resolved:
        # The APK has no extension to strip, so keep the directory separate
        decompiled_path = resolved.with_name(resolved.name + "_decompiled")
    return decompiled_path


def is_reusable_decompile_dir(path: Path) -> bool:
    """
    Check whether a decompile directory can be safely removed.

    Only empty directories and previous apktool outputs are reusable, so an
    unrelated directory that happens to share the APK name is never deleted.

    Parameters
    ----------
    path : Path
        path of the decompile directory

    Returns
    -------
    bool
        True if the directory can be removed

    """
    if not path.is_dir():
        return False

    entries = list(path.iterdir())
    if not entries:
        return True

    # 'apktool.yml' is only written once decoding finishes, so the artifacts
    # of an interrupted or failed decompile are accepted as well.
    return any(
        entry.name in ("apktool.yml", "AndroidManifest.xml", "original", "unknown")
        or entry.name.startswith("smali")
        for entry in entries
    )


def resolve_apktool(apktool_path: str = None) -> str:
    """
    Work out the apktool command to run.

    Parameters
    ----------
    apktool_path : str
        path or command given with --apktool-path

    Returns
    -------
    str
        the command to invoke apktool with

    Raises
    ------
    FileNotFoundError
        apktool is neither given nor on PATH

    """
    if not apktool_path:
        if not APKTOOL:
            raise FileNotFoundError(
                "apktool not found. Please install apktool and add it to your PATH environment.\n"
                "For macOS: brew install apktool\n"
                "For Windows: Download from https://ibotpeaches.github.io/Apktool/install/\n"
                "For Linux: sudo apt-get install apktool\n"
                "After installation, you may need to restart your terminal."
            )
        return APKTOOL

    apktool_parts = apktool_path.split()
    apktool_binary = apktool_parts[-1]
    if not Path(apktool_binary).exists():
        logger.error("The specified apktool path does not exist: %s", apktool_binary)
        sys.exit(-1)

    if len(apktool_parts) > 1:
        logger.info("Using custom apktool command: '%s'", apktool_path)
    else:
        logger.info("Using custom apktool path: '%s'", apktool_path)

    return apktool_path


def run_apktool(option: list, apk_path: str, apktool: str = None):
    """
    Run apktool with option.

    Parameters
    ----------
    option : list|str
        option of apktool
    apk_path : str
        path of apk file
    apktool : str
        command to invoke apktool with, defaults to the one on PATH

    """
    pipe = subprocess.PIPE
    cmd = (apktool or APKTOOL).split() + option + [apk_path]
    with subprocess.Popen(
        cmd, stdin=pipe, stdout=sys.stdout, stderr=sys.stderr
    ) as process:
        process.communicate(b"\n")
        if process.returncode != 0:
            # Suggest only the options that are not in use yet. Removing from the
            # list while iterating over it used to skip the second entry.
            recommend_options = [
                opt for opt in ("--no-res", "--use-aapt2") if opt not in option
            ]

            logger.error(
                "It looks like you're having trouble with apktool.\n"
                "Consider trying the '%s' options, or if you'd prefer more control,\n"
                "you can manually specify apktool settings using "
                "['--decompile-opts', '--recompile-opts', '--apktool-path'].",
                recommend_options,
            )

            raise subprocess.CalledProcessError(
                process.returncode, cmd, sys.stdout, sys.stderr
            )
        return True


def restore_original_dex(apk_path, recompiled_apk_path, modified_dex_number):
    """
    Put the original dex files back into the recompiled APK.

    apktool reassembles every dex file, which can change classes it was never
    asked to touch. Only the dex holding the patched main activity has to come
    from the rebuild; the rest are copied over from the original APK.

    Parameters
    ----------
    apk_path : Path
        path of the original apk file
    recompiled_apk_path : Path
        path of the apk apktool produced
    modified_dex_number : int
        smali_classes<N> the main activity lives in

    """
    logger.debug(
        "Copying original dex files (except modified one %s) to the recompiled APK",
        modified_dex_number,
    )

    modified_dex_filename = (
        f"classes{modified_dex_number}.dex"
        if modified_dex_number and modified_dex_number > 1
        else "classes.dex"
    )

    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir_path = Path(temp_dir)
            with zipfile.ZipFile(apk_path, "r") as original_apk:
                original_apk.extractall(temp_dir_path)

            # Built inside the temporary directory so a failure cannot leave a
            # stray file behind the way the old NamedTemporaryFile did
            staged_apk_path = temp_dir_path.joinpath("repacked.apk")
            with zipfile.ZipFile(recompiled_apk_path, "r") as recompiled_apk, zipfile.ZipFile(
                staged_apk_path, "w"
            ) as new_apk:
                for item in recompiled_apk.infolist():
                    is_dex = item.filename.startswith("classes") and item.filename.endswith(
                        ".dex"
                    )
                    if is_dex and item.filename != modified_dex_filename:
                        dex_file = temp_dir_path.joinpath(item.filename)
                        new_apk.write(str(dex_file), dex_file.name)
                        continue

                    if item.filename == modified_dex_filename:
                        logger.debug("Copying %s from recompiled APK", item.filename)
                    new_apk.writestr(item, recompiled_apk.read(item.filename))

            shutil.move(str(staged_apk_path), str(recompiled_apk_path))
            logger.info("Successfully replaced dex files in the recompiled APK")
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile, RuntimeError, KeyError) as e:
        # Restoring the dex files is best effort: apktool has already produced a
        # working APK, so a failure here is reported and the run carries on.
        # RuntimeError covers the NotImplementedError zipfile raises for
        # compression methods it cannot read, which must not take the run down.
        logger.error("Failed to copy original dex files: %s", str(e))


def prepare_decompile_dir(decompiled_path: Path):
    """
    Make sure the decompile target is an empty directory we may write to.

    Parameters
    ----------
    decompiled_path : Path
        the decompile directory

    """
    if decompiled_path.exists():
        if not is_reusable_decompile_dir(decompiled_path):
            logger.error(
                "The decompile target '%s' already exists and does not look like "
                "an apktool output.\n"
                "Remove or rename it, or use the --skip-decompile option "
                "if it already contains the decompiled APK.",
                decompiled_path,
            )
            sys.exit(-1)
        shutil.rmtree(decompiled_path)

    decompiled_path.mkdir(parents=True)


def build_decompile_options(
    decompiled_path: Path, force_manifest: bool, no_res: bool, decompile_opts: str
):
    """
    Assemble the apktool decode command line.

    Parameters
    ----------
    decompiled_path : Path
        where apktool should write the decompiled APK
    force_manifest : bool
        whether --force-manifest was given
    no_res : bool
        whether --no-res was given
    decompile_opts : str
        extra options given with --decompile-opts

    Returns
    -------
    tuple
        the option list, and no_res updated from --decompile-opts

    """
    options = ["d", "-o", str(decompiled_path.resolve()), "--force"]
    if force_manifest:
        options += ["--force-manifest"]
    if no_res:
        options += ["--no-res"]

    if decompile_opts:
        if "--no-res" in decompile_opts:
            if no_res:
                # remove no-res option if it's already in the list
                options.remove("--no-res")
            no_res = True
        options += decompile_opts.split()

    return options, no_res
