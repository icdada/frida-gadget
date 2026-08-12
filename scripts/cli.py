"""Frida Gadget Injector for Android APK.

This script allows you to inject the Frida gadget library into an Android APK.
It provides various functionalities including:
- Decompiling the APK using apktool
- Downloading the appropriate Frida gadget library based on the device architecture
- Injecting the Frida gadget library into the APK
- Modifying the AndroidManifest.xml to add necessary permissions
- Recompiling the APK
- Optionally signing the APK using uber-apk-signer
"""
import os
import sys
import atexit
import shutil
import subprocess
import json
import tempfile
import zipfile
from shutil import which
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import click
from androguard.core.apk import APK
from .apk_utils import get_main_activity
from .logger import logger
from .__version__ import __version__
from .frida_github import FridaGithub
from .uber_apk_signer_github import UberApkSignerGithub
from . import INSTALLED_FRIDA_VERSION


p = Path(__file__)
ROOT_DIR = p.parent.resolve()
FILE_DIR = ROOT_DIR.joinpath("files")

APKTOOL = which("apktool")


def get_decompiled_path(apk_path: Path) -> Path:
    """Build the path apktool decompiles the APK into.

    Args:
        apk_path (Path): path of apk file

    Returns:
        Path: the decompile directory, next to the APK file
    """
    resolved = apk_path.resolve()
    decompiled_path = resolved.with_suffix("")
    if decompiled_path == resolved:
        # The APK has no extension to strip, so keep the directory separate
        decompiled_path = resolved.with_name(resolved.name + "_decompiled")
    return decompiled_path


def is_reusable_decompile_dir(path: Path) -> bool:
    """Check whether a decompile directory can be safely removed.

    Only empty directories and previous apktool outputs are reusable, so an
    unrelated directory that happens to share the APK name is never deleted.

    Args:
        path (Path): path of the decompile directory

    Returns:
        bool: True if the directory can be removed
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
    """Work out the apktool command to run.

    Args:
        apktool_path (str): path or command given with --apktool-path

    Returns:
        str: the command to invoke apktool with

    Raises:
        FileNotFoundError: apktool is neither given nor on PATH
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
    """Run apktool with option.

    Args:
        option (list|str): option of apktool
        apk_path (str): path of apk file
        apktool (str): command to invoke apktool with, defaults to the one on PATH
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


def download_gadget(
    arch: str,
    frida_version: str = None,
    custom_gadget_path: str = None,
    github_repo: str = None,
):
    """Download the frida gadget library or use a custom file.

    Args:
        arch (str): architecture of the device
        frida_version (str): specific frida version to use
        custom_gadget_path (str): path to custom frida gadget file
        github_repo (str): custom GitHub repository for the frida gadget
    """
    # A custom gadget is used as-is, so the frida version is irrelevant here
    if custom_gadget_path:
        logger.info("Using custom Frida gadget file: %s", custom_gadget_path)

        source = Path(custom_gadget_path)
        if source.suffix != ".so":
            raise ValueError(
                f"The custom gadget must be an uncompressed '.so' file, got '{source.name}'.\n"
                "Frida publishes the gadget as '.so.xz', so decompress it first."
            )

        # FILE_DIR is normally created while downloading, which we skip here
        FILE_DIR.mkdir(parents=True, exist_ok=True)
        so_gadget_path = str(FILE_DIR.joinpath(f"frida-gadget-custom-{arch}.so"))
        shutil.copy2(source, so_gadget_path)
        return so_gadget_path

    if frida_version:
        logger.info("Using specified frida version: %s", frida_version)
        version = frida_version
    else:
        logger.info("Auto-detected your frida version: %s", INSTALLED_FRIDA_VERSION)
        version = INSTALLED_FRIDA_VERSION

    if github_repo:
        logger.info("Using custom GitHub repository: %s", github_repo)

    frida_github = FridaGithub(version, github_repo)
    assets = frida_github.get_assets()
    file = f"frida-gadget-{version}-android-{arch}.so.xz"
    for asset in assets:
        if asset["name"] == file:
            logger.debug(
                "Downloading the frida gadget library(%s) for %s", version, arch
            )
            so_gadget_path = str(FILE_DIR.joinpath(file[:-3]))
            return frida_github.download_gadget_so(
                asset["browser_download_url"], so_gadget_path
            )

    raise FileNotFoundError(f"'{file}' not found in the github releases")


def download_signer():
    """Download the Uber Apk Signer."""
    signer_github = UberApkSignerGithub()
    assets = signer_github.get_assets()
    file = f"uber-apk-signer-{signer_github.signer_version}.jar"
    signer_path = str(FILE_DIR.joinpath(file))
    if os.path.exists(signer_path):
        return signer_path

    logger.debug("Downloading the %s file for signing", file)
    return signer_github.download_signer_jar(assets, signer_path)


def find_activity_smali(decompiled_path, main_activity):
    """Locate the smali file of an activity across the smali_classes* trees.

    Args:
        decompiled_path (Path): decompiled path of apk file
        main_activity (str): activity class name

    Returns:
        tuple: the smali file path, and the smali_classes<N> number it sits in
               (None for the plain 'smali' directory)

    Raises:
        FileNotFoundError: the activity has no smali file
    """
    target_relative_path = main_activity.replace(".", os.sep) + ".smali"

    for directory in sorted(decompiled_path.iterdir()):
        if not directory.is_dir() or not directory.name.startswith("smali"):
            continue

        target_smali = directory.joinpath(target_relative_path)
        if not target_smali.exists():
            continue

        class_number = None
        if directory.name.startswith("smali_classes"):
            class_number = int(directory.name.split("smali_classes")[1])
        return target_smali, class_number

    raise FileNotFoundError(
        f"The smali file for '{main_activity}' was not found under {decompiled_path}."
    )


def insert_load_library_call(text: list, load_library_name: str) -> bool:
    """Insert the loadLibrary call into the first usable entrypoint.

    Args:
        text (list): lines of the smali file, modified in place
        load_library_name (str): name passed to System.loadLibrary

    Returns:
        bool: True when the call was inserted
    """
    if load_library_name.startswith("lib"):
        load_library_name = load_library_name[3:]

    for entrypoint in (" onCreate(", "<init>"):
        for idx, line in enumerate(text):
            if not line.strip().startswith(".method") or entrypoint not in line:
                continue

            # The call needs a register, which only a method declaring .locals has
            if idx + 1 >= len(text):
                continue

            declaration = text[idx + 1]
            if ".locals" not in declaration:
                continue

            # Increase the number of locals 0 to 1
            text[idx + 1] = declaration.replace(".locals 0", ".locals 1")
            text.insert(
                idx + 2,
                "    invoke-static {v0}, "
                "Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V",
            )
            text.insert(idx + 2, f'    const-string v0, "{load_library_name}"')
            return True

    return False


def insert_loadlibary(decompiled_path, main_activity, load_library_name):
    """Inject loadlibary code to main activity.

    Args:
        decompiled_path (str): decomplied path of apk file
        main_activity (str): main activity of apk file
        load_library_name (str): name of load library

    Returns:
        int: the smali_classes<N> number the patched activity sits in
    """
    logger.debug("Searching for the main activity in the smali files")
    target_smali, target_smali_class_number = find_activity_smali(
        decompiled_path, main_activity
    )

    logger.debug("Found the main activity at '%s'", str(target_smali))
    text = target_smali.read_text(encoding="utf-8")
    text = text.replace("invoke-virtual {v0, v1}, Ljava/lang/Runtime;->exit(I)V", "")
    text = text.split("\n")

    logger.debug("Locating the entrypoint method and injecting the loadLibrary code")
    if not insert_load_library_call(text, load_library_name):
        logger.error("Cannot find the appropriate position in the main activity.")
        logger.error(
            "Please report the issue at %s with the following information:",
            "https://github.com/ksg97031/frida-gadget/issues",
        )
        logger.error("APK Name: <Your APK Name>")
        logger.error("APK Version: <Your APK Version>")
        logger.error("APKTOOL Version: <Your APKTOOL Version>")
        sys.exit(-1)

    # Replace the smali file with the new one
    target_smali.write_text("\n".join(text), encoding="utf-8")
    return target_smali_class_number

def modify_manifest(decompiled_path):
    """Modify manifest permissions.

    Args:
        decompiled_path (str): decomplied path of apk file
    """
    # Add internet permission
    logger.debug("Checking internet permission and extractNativeLibs settings")
    android_manifest = decompiled_path.joinpath("AndroidManifest.xml")
    txt = android_manifest.read_text(encoding="utf-8")
    pos = txt.index("</manifest>")
    permission = "android.permission.INTERNET"

    if permission not in txt:
        logger.debug(
            "Adding 'android.permission.INTERNET' permission to AndroidManifest.xml"
        )
        permissions_txt = f"<uses-permission android:name='{permission}'/>"
        txt = txt[:pos] + permissions_txt + txt[pos:]

    # Set extractNativeLibs to true
    if ':extractNativeLibs="false"' in txt:
        logger.debug('Editing the extractNativeLibs="true"')
        txt = txt.replace(':extractNativeLibs="false"', ':extractNativeLibs="true"')
    android_manifest.write_text(txt, encoding="utf-8")


def detect_apk_architectures(decompiled_path):
    """Detect architectures from the APK's lib directory.

    Args:
        decompiled_path (str): decompiled path of apk file

    Returns:
        list: List of detected architectures
    """
    lib_dir = decompiled_path.joinpath("lib")
    if not lib_dir.exists():
        logger.warning(
            "No lib directory found in the APK. Returning default architecture (arm64)."
        )
        return ["arm64"]

    arch_mapping = {
        "arm64-v8a": "arm64",
        "armeabi-v7a": "arm",
        "x86": "x86",
        "x86_64": "x86_64",
    }

    detected_archs = []
    for arch_dir in lib_dir.iterdir():
        if arch_dir.is_dir() and arch_dir.name in arch_mapping:
            detected_archs.append(arch_mapping[arch_dir.name])

    if not detected_archs:
        logger.warning(
            "No supported architectures found in the APK. Returning default architecture (arm64)."
        )
        return ["arm64"]

    logger.info("Detected architectures in APK: %s", ", ".join(detected_archs))
    return detected_archs


ARCH_DIRNAMES = {
    "arm": "armeabi-v7a",
    "x86": "x86",
    "arm64": "arm64-v8a",
    "x86_64": "x86_64",
}


def resolve_main_activity(apk: APK, main_activity: str = None) -> str:
    """Work out which activity the loadLibrary call goes into.

    Args:
        apk (APK): parsed apk file
        main_activity (str): activity given with --main-activity

    Returns:
        str: the activity class name
    """
    if main_activity:
        return main_activity

    main_activity = get_main_activity(apk)
    if main_activity == -1:  # multiple main activities
        sys.exit(-1)
    if main_activity:
        return main_activity

    activities = apk.get_activities()
    if len(activities) == 1:
        logger.warning(
            "The main activity was not found.\n"
            "Using the first activity from the manifest file."
        )
        return activities[0]

    logger.error(
        "The main activity was not found.\n"
        "Please specify the main activity using the --main-activity option.\n"
        "Select the activity from %s",
        activities,
    )
    sys.exit(-1)


def resolve_gadget_name(gadget_path: str, custom_gadget_name: str, arch: str) -> str:
    """Decide the file name the gadget is stored under inside the APK.

    Args:
        gadget_path (str): path of the downloaded or supplied gadget
        custom_gadget_name (str): name given with --custom-gadget-name
        arch (str): the requested architecture, or 'multi-arch'

    Returns:
        str: the file name to use in lib/<abi>
    """
    if custom_gadget_name:
        gadget_name = custom_gadget_name + ".so"
        logger.info("Using custom gadget name: %s", gadget_name)
        return gadget_name

    if arch == "multi-arch":
        # The downloaded file name carries the architecture, but a single
        # loadLibrary call has to resolve inside every lib/<abi> directory
        gadget_name = "libfrida-gadget.so"
        logger.info("Using multi-arch gadget name: %s", gadget_name)
        return gadget_name

    return Path(gadget_path).name


def prepare_lib_dir(decompiled_path: Path, current_arch: str) -> Path:
    """Create the lib/<abi> directory the gadget is copied into.

    Args:
        decompiled_path (Path): decompiled path of apk file
        current_arch (str): architecture being injected

    Returns:
        Path: the lib/<abi> directory

    Raises:
        NotImplementedError: the architecture has no known ABI directory
    """
    if current_arch not in ARCH_DIRNAMES:
        raise NotImplementedError(f"The architecture '{current_arch}' is not supported.")

    lib_arch_dir = decompiled_path.joinpath("lib", ARCH_DIRNAMES[current_arch])
    lib_arch_dir.mkdir(parents=True, exist_ok=True)
    return lib_arch_dir


def load_config_data(config: str) -> dict:
    """Read a gadget config file and check it declares an interaction.

    Args:
        config (str): path of the config file

    Returns:
        dict: the parsed config
    """
    with open(config, "r", encoding="utf-8") as f:
        config_data = json.load(f)

    if "interaction" not in config_data:
        logger.error("The config file must contain an 'interaction' key.")
        sys.exit(-1)

    if "type" not in config_data["interaction"]:
        logger.error("The config file must contain an 'interaction.type' key.")
        sys.exit(-1)

    return config_data


def warn_config_without_script(config: str):
    """Explain what a config without --js means for the resulting APK.

    Args:
        config (str): path of the config file
    """
    logger.warning(
        "The '%s' config file was provided without the script file.", config
    )
    logger.warning(
        "To upload the script file to the APK, please provide the --js option."
    )

    config_data = load_config_data(config)
    if config_data["interaction"]["type"] not in ("script", "script-directory"):
        # 'listen' and 'connect' wait for a client instead of loading a script
        return

    if "path" not in config_data["interaction"]:
        logger.error(
            "The config file must contain a 'interaction.path' key with "
            "'type: script' or 'type: script-directory'"
        )
        sys.exit(-1)

    logger.warning(
        "The script file must be located at '%s' on your Android device",
        config_data["interaction"]["path"],
    )


def write_gadget_config(
    config: str, js: str, lib_arch_dir: Path, load_library_name: str, upload_files: dict
):
    """Write the gadget's config file next to the library.

    Args:
        config (str): path given with --config
        js (str): path given with --js
        lib_arch_dir (Path): the lib/<abi> directory
        load_library_name (str): name passed to System.loadLibrary
        upload_files (dict): files still to copy, the config is removed from it
                             once it has been written here
    """
    script_path = f"{load_library_name}.script.so"

    if js and config:
        config_data = load_config_data(config)
        if "path" in config_data["interaction"]:
            logger.debug(
                "Updating the script path in '%s' from '%s' to '%s'",
                config,
                config_data["interaction"]["path"],
                script_path,
            )
        config_data["interaction"]["path"] = script_path
    elif js:
        config_data = {"interaction": {"type": "script", "path": script_path}}
    else:
        if config:
            warn_config_without_script(config)
        return

    config_name = f"{load_library_name}.config.so"
    contents = json.dumps(config_data, indent=4)
    with open(lib_arch_dir.joinpath(config_name), "w", encoding="utf-8") as f:
        f.write(contents)

    logger.debug("Created the config file: %s", config_name)
    logger.debug(contents)
    del upload_files["config"]


def upload_gadget_files(upload_files: dict, lib_arch_dir: Path, load_library_name: str):
    """Copy the config and script files into the APK's lib directory.

    Args:
        upload_files (dict): file type to source path
        lib_arch_dir (Path): the lib/<abi> directory
        load_library_name (str): name passed to System.loadLibrary
    """
    for file_type, file_path in upload_files.items():
        if not file_path:
            continue

        file_path = Path(file_path)
        if not file_path.exists():
            logger.error("Frida %s file not found: %s", file_type, file_path)
            sys.exit(-1)

        target_name = f"{load_library_name}.{file_type}.so"
        if file_path.name == target_name:
            logger.debug("Uploading Frida %s file: %s", file_type, file_path.name)
        else:
            logger.debug(
                "Renaming and uploading Frida %s file: %s -> %s",
                file_type,
                file_path.name,
                target_name,
            )

        shutil.copy(file_path, lib_arch_dir.joinpath(target_name))


@dataclass
class GadgetSource:
    """Where the gadget library comes from and what it is called.

    Attributes:
        custom_gadget_name (str): name given with --custom-gadget-name
        custom_gadget_path (str): path given with --custom-gadget-path
        frida_version (str): version given with --frida-version
        github_repo (str): repository given with --github-repo
    """

    custom_gadget_name: Optional[str] = None
    custom_gadget_path: Optional[str] = None
    frida_version: Optional[str] = None
    github_repo: Optional[str] = None


# The parameters mirror the CLI flags that reach the injection step
# pylint: disable=too-many-arguments,too-many-positional-arguments,too-many-locals
def inject_gadget_into_apk(
    apk_path: str,
    arch: str,
    decompiled_path: Path,
    no_res: bool,
    force_manifest: bool,
    main_activity: str = None,
    config: str = None,
    js: str = None,
    gadget_source: "GadgetSource" = None,
) -> int:
    """Inject frida gadget into an APK.

    Args:
        apk (APK): path of apk file
        arch (str): architecture of the device
        decompiled_path (str): decomplied path of apk file

    Raises:
        FileNotFoundError: file not found
        NotImplementedError: not implemented
    """
    apk = APK(apk_path)
    gadget_source = gadget_source or GadgetSource()

    # Handle 'multi-arch' option
    if arch == "multi-arch":
        archs = detect_apk_architectures(decompiled_path)
        logger.info(
            "Using multiple architectures detected from APK: %s", ", ".join(archs)
        )
    else:
        archs = [arch]

    main_activity = resolve_main_activity(apk, main_activity)

    # Apply permission to android manifest
    if not no_res or force_manifest:
        modify_manifest(decompiled_path)

    for current_arch in archs:
        gadget_path = download_gadget(
            current_arch,
            gadget_source.frida_version,
            gadget_source.custom_gadget_path,
            gadget_source.github_repo,
        )
        gadget_name = resolve_gadget_name(
            gadget_path, gadget_source.custom_gadget_name, arch
        )
        lib_arch_dir = prepare_lib_dir(decompiled_path, current_arch)

        lib_library_name = gadget_name
        if not lib_library_name.startswith("lib"):
            lib_library_name = "lib" + gadget_name
        shutil.copy(gadget_path, lib_arch_dir.joinpath(lib_library_name))

        # Upload gadget config and js files for each architecture
        upload_files = {"config": config, "script": js}
        load_library_name = lib_library_name[:-3]

        write_gadget_config(config, js, lib_arch_dir, load_library_name, upload_files)
        upload_gadget_files(upload_files, lib_arch_dir, load_library_name)

    return insert_loadlibary(decompiled_path, main_activity, load_library_name)


def stdin_is_interactive():
    """Check whether a child process could prompt on this stdin.

    Returns:
        bool: True if stdin is attached to a terminal
    """
    try:
        return sys.stdin is not None and sys.stdin.isatty()
    except ValueError:  # stdin was already closed
        return False


def redact_passwords(cmd: list):
    """Hide keystore passwords in a command line before it is reported.

    Args:
        cmd (list): command line of the signer

    Returns:
        list: copy of the command line without password values
    """
    redacted = list(cmd)
    for idx, arg in enumerate(redacted[:-1]):
        if arg in ("--ksPass", "--ksKeyPass"):
            redacted[idx + 1] = "***"

    return redacted


def sign_apk(
    apk_path: str,
    ks: str = None,
    ks_alias: str = None,
    ks_key_pass: str = None,
    ks_pass: str = None,
):
    """Run uber apk signer with option.

    Args:
        apk_path (str): path of apk file
        ks (str): keystore file path
        ks_alias (str): keystore alias
        ks_key_pass (str): key password
        ks_pass (str): keystore password
    """
    signer_path = download_signer()  # Download apk signer

    cmd = ["java", "-jar", signer_path, "--apks", apk_path]

    if ks:
        cmd.append("--ks")
        cmd.append(ks)
    if ks_alias:
        cmd.append("--ksAlias")
        cmd.append(ks_alias)
    if ks_key_pass:
        cmd.append("--ksKeyPass")
        cmd.append(ks_key_pass)
    if ks_pass:
        cmd.append("--ksPass")
        cmd.append(ks_pass)

    if ks_key_pass or ks_pass:
        logger.warning(
            "Keystore passwords given on the command line are readable by every "
            "other user on this machine through the process list.\n"
            "Omit the --ks-pass and --ks-key-pass options to let uber-apk-signer "
            "prompt for them instead."
        )

    # uber-apk-signer prompts for the passwords that were not provided,
    # which only works while it owns the terminal.
    needs_prompt = bool(ks) and not (ks_pass and ks_key_pass)
    interactive = needs_prompt and stdin_is_interactive()
    if needs_prompt and not interactive:
        logger.warning(
            "There is no terminal attached, so uber-apk-signer cannot prompt for "
            "the missing keystore password.\n"
            "Run this from a terminal, or pass --ks-pass and --ks-key-pass."
        )

    stdio = None if interactive else subprocess.PIPE

    with subprocess.Popen(
        cmd, stdin=stdio, stdout=stdio, stderr=sys.stderr
    ) as process:
        stdout, _ = process.communicate(None if interactive else b"\n")
        if process.returncode != 0:
            logger.error("The APK signing process failed.")
            raise subprocess.CalledProcessError(
                process.returncode, redact_passwords(cmd), sys.stdout, sys.stderr
            )

        if stdout is None:  # the signer wrote directly to the terminal
            return

        output = stdout.decode()
        print(output)
        if "VERIFY" in output:
            verify_message = output.split("VERIFY")[1]
            if "file:" in verify_message:
                apk_path = verify_message.split("file:")[1].split("\n")[0].strip()
                logger.info("APK signing finished: %s", apk_path)


def restore_original_dex(apk_path, recompiled_apk_path, modified_dex_number):
    """Put the original dex files back into the recompiled APK.

    apktool reassembles every dex file, which can change classes it was never
    asked to touch. Only the dex holding the patched main activity has to come
    from the rebuild; the rest are copied over from the original APK.

    Args:
        apk_path (Path): path of the original apk file
        recompiled_apk_path (Path): path of the apk apktool produced
        modified_dex_number (int): smali_classes<N> the main activity lives in
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


def detect_adb_arch():
    """Detect the architecture of the currently connected device via ADB.

    This function communicates with a connected Android device over ADB
    to determine its CPU architecture (e.g., arm64-v8a, armeabi-v7a, x86).

    Returns:
        str: The detected architecture of the connected device.
              Defaults to 'arm64' if detection fails.
    """
    pipe = subprocess.PIPE
    cmd = ["adb", "shell", "getprop", "ro.product.cpu.abi"]
    default_arch = "arm64"

    try:
        with subprocess.Popen(
            cmd, stdin=pipe, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        ) as process:
            stdout, stderr = process.communicate()
            if process.returncode != 0:
                logger.warning(
                    "Failed to execute ADB command. Error: %s", stderr.decode().strip()
                )
                logger.warning("Falling back to default architecture: %s", default_arch)
                return default_arch

            arch = stdout.decode().strip()
            if not arch:
                logger.warning(
                    "Architecture detection failed: no output received. "
                    "Falling back to default: %s",
                    default_arch,
                )
                return default_arch

            if arch == "arm64-v8a":
                arch = "arm64"
            elif arch == "armeabi-v7a":
                arch = "arm"

            logger.info("Auto-detected architecture via ADB: %s", arch)
            return arch

    except FileNotFoundError:
        logger.warning(
            "ADB is not installed or not found in the system PATH. Falling back to default: %s",
            default_arch,
        )
        return default_arch
    except (OSError, ValueError, subprocess.SubprocessError) as e:
        logger.warning(
            "An unexpected error occurred during architecture detection: %s. "
            "Falling back to default: %s",
            str(e),
            default_arch,
        )
        return default_arch


def print_version(ctx, _, value):
    """Print version and exit."""
    if not value or ctx.resilient_parsing:
        return
    print(f"frida-gadget version {__version__}")
    ctx.exit()


SUPPORTED_ARCHS = ["arm", "arm64", "x86", "x86_64"]


def log_target_arch(arch: str):
    """Report the architecture the gadget will be built for.

    Args:
        arch (str): normalized architecture name
    """
    if arch == "multi-arch":
        logger.info(
            "Gadget Architecture(--arch): %s (will inject for all architectures found in APK)",
            arch,
        )
        return

    logger.info(
        "Gadget Architecture(--arch): %s%s",
        arch,
        "(default)" if arch == "arm64" else "",
    )


def validate_arch(arch: str) -> str:
    """Check the architecture is one we can download a gadget for.

    Args:
        arch (str): normalized architecture name

    Returns:
        str: the architecture, lowercased
    """
    if arch == "multi-arch":
        return arch

    arch = arch.lower()
    if arch not in SUPPORTED_ARCHS:
        logger.error(
            "The --arch option only supports the following architectures: %s, multi-arch",
            ", ".join(SUPPORTED_ARCHS),
        )
        sys.exit(-1)

    return arch


def validate_input_files(js: str, config: str):
    """Check the files given with --js and --config are usable.

    Args:
        js (str): path given with --js
        config (str): path given with --config
    """
    if js and not Path(js).exists():
        logger.error("The specified JavaScript file does not exist: %s", js)
        sys.exit(-1)

    if not config:
        return

    if not Path(config).exists():
        logger.error("The specified configuration file does not exist: %s", config)
        sys.exit(-1)

    try:
        with open(config, "r", encoding="utf-8") as f:
            json.load(f)
    except json.JSONDecodeError:
        logger.error("The specified configuration file is not a valid JSON: %s", config)
        sys.exit(-1)


def prepare_decompile_dir(decompiled_path: Path):
    """Make sure the decompile target is an empty directory we may write to.

    Args:
        decompiled_path (Path): the decompile directory
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
    """Assemble the apktool decode command line.

    Args:
        decompiled_path (Path): where apktool should write the decompiled APK
        force_manifest (bool): whether --force-manifest was given
        no_res (bool): whether --no-res was given
        decompile_opts (str): extra options given with --decompile-opts

    Returns:
        tuple: the option list, and no_res updated from --decompile-opts
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


def normalize_arch(arch: str, skip_decompile: bool) -> str:
    """Turn the --arch value into one of the names used internally.

    Args:
        arch (str): value given with --arch, None to auto-detect over ADB
        skip_decompile (bool): whether --skip-decompile was given

    Returns:
        str: 'multi-arch' or one of the supported architecture names
    """
    if arch is None:
        return detect_adb_arch()

    if arch.lower() == "multi-arch":
        if skip_decompile:
            logger.warning(
                "The 'multi-arch' option requires decompiling the APK first to detect architectures"
            )
        return "multi-arch"

    aliases = {"arm64-v8a": "arm64", "armeabi-v7a": "arm"}
    return aliases.get(arch, arch)


def wrap_js_file(js: str, js_delay: int) -> str:
    """Write a delayed copy of the script and return its path.

    Args:
        js (str): path given with --js
        js_delay (int): seconds to wait before the script runs

    Returns:
        str: path of the wrapped copy
    """
    if js is None:
        logger.error("The --js-delay option requires --js option to be specified.")
        sys.exit(-1)

    if js_delay < 0:
        logger.error("Delay value must be a positive number.")
        sys.exit(-1)

    logger.info("JavaScript execution will be delayed by %d seconds", js_delay)

    js_path = Path(js)
    if not js_path.exists():
        logger.error("The specified JavaScript file does not exist: %s", js)
        sys.exit(-1)

    try:
        wrapped_content = wrap_js_with_timeout(
            js_path.read_text(encoding="utf-8"), js_delay
        )

        # Keep the wrapped copy in a private temporary directory. Writing it
        # next to the original silently overwrote any existing file of that
        # name and failed outright when the directory was read-only.
        temp_dir = tempfile.mkdtemp(prefix="frida-gadget-")
        atexit.register(shutil.rmtree, temp_dir, True)
        temp_js = Path(temp_dir).joinpath("wrapped.js")
        with open(temp_js, "w", encoding="utf-8") as wrapped_file:
            wrapped_file.write(wrapped_content)
    except (OSError, UnicodeDecodeError) as e:
        logger.error("Failed to process JavaScript file: %s", str(e))
        sys.exit(-1)

    logger.debug("Created wrapped JavaScript file: %s", temp_js)
    return str(temp_js)


def wrap_js_with_timeout(js_content: str, delay: int) -> str:
    """Wrap JavaScript content with setTimeout.

    Args:
        js_content (str): Original JavaScript content
        delay (int): Seconds to wait before executing

    Returns:
        str: Wrapped JavaScript content
    """
    return f"""setTimeout(function() {{
{js_content}
}}, {delay * 1000});"""


# The signature is dictated by the click options below, one parameter per flag.
# pylint: disable=too-many-arguments,too-many-positional-arguments,too-many-locals
@click.command()
@click.option(
    "--arch",
    default=None,
    help="Specify the target architecture of the device. "
    "(options: arm64, x86_64, arm, x86, multi-arch)",
)
@click.option("--config", help="Specify the Frida configuration file.")
@click.option("--js", default=None, help="Specify the Frida gadget JavaScript file.")
@click.option(
    "--js-delay",
    type=int,
    help="Specify seconds to wait before executing the JavaScript file.",
)
@click.option(
    "--force-manifest",
    is_flag=True,
    help="Force modify AndroidManifest.xml even if it already has required permissions.",
)
@click.option(
    "--custom-gadget-name",
    default=None,
    help="Specify a custom name for the Frida gadget.",
)
@click.option(
    "--custom-gadget-path",
    default=None,
    type=click.Path(exists=True),
    help="Use a custom Frida gadget library file instead of downloading from GitHub.",
)
@click.option(
    "--github-repo",
    default=None,
    help="Specify a custom GitHub repository for downloading Frida gadget "
    "(e.g., username/repo-name or full URL).",
)
@click.option("--no-res", is_flag=True, help="Skip decoding resources.")
@click.option(
    "--main-activity", default=None, help="Specify the main activity if known."
)
@click.option(
    "--sign", is_flag=True, help="Automatically sign the APK using uber-apk-signer."
)
@click.option("--skip-decompile", is_flag=True, help="Skip the decompilation step.")
@click.option("--skip-recompile", is_flag=True, help="Skip the recompilation step.")
@click.option(
    "--use-aapt2",
    is_flag=True,
    help="Use aapt2 instead of aapt for resource processing.",
)
@click.option(
    "--decompile-opts",
    default=None,
    help="Specify additional options for apktool decompile.",
)
@click.option(
    "--recompile-opts",
    default=None,
    help="Specify additional options for apktool recompile.",
)
@click.option(
    "--apktool-path", default=None, help="Specify the path or command to run apktool."
)
@click.option("--frida-version", default=None, help="Specify the Frida version to use.")
@click.option(
    "--ks",
    default=None,
    help="The keystore file. If not provided, will use debug keystore.",
)
@click.option("--ks-alias", default=None, help="The alias of the used key in the keystore.")
@click.option(
    "--ks-key-pass",
    default=None,
    help="The password for the key. Prompted for if omitted.",
)
@click.option(
    "--ks-pass",
    default=None,
    help="The password for the keystore. Prompted for if omitted.",
)
@click.option(
    "--version",
    is_flag=True,
    callback=print_version,
    expose_value=False,
    is_eager=True,
    help="Show the version and exit.",
)
@click.argument("apk_path", type=click.Path(exists=True), required=True)
# One parameter per CLI flag, so the count is dictated by the options above
def run(  # NOSONAR
    apk_path: str,
    arch: str,
    config: str,
    no_res: bool,
    main_activity: str,
    sign: bool,
    custom_gadget_name: str,
    custom_gadget_path: str,
    js: str,
    js_delay: int,
    force_manifest: bool,
    skip_decompile: bool,
    skip_recompile: bool,
    use_aapt2: bool,
    decompile_opts: str,
    recompile_opts: str,
    apktool_path: str,
    frida_version: str,
    ks: str,
    ks_alias: str,
    ks_key_pass: str,
    ks_pass: str,
    github_repo: str,
):
    """Patch an APK with the Frida gadget library."""
    apk_path = Path(apk_path)

    logger.info("APK: '%s'", apk_path)
    arch = normalize_arch(arch, skip_decompile)

    # A single library file only matches one ABI, so it cannot serve every
    # architecture found in the APK
    if custom_gadget_path and arch == "multi-arch":
        logger.error(
            "The --custom-gadget-path option cannot be combined with '--arch multi-arch'.\n"
            "Run the command once per architecture instead."
        )
        sys.exit(-1)

    if js_delay is not None:
        js = wrap_js_file(js, js_delay)

    apktool = resolve_apktool(apktool_path)
    log_target_arch(arch)
    validate_input_files(js, config)
    arch = validate_arch(arch)

    # Make directory for decompile
    decompiled_path = get_decompiled_path(apk_path)
    if not skip_decompile:
        logger.debug('Decompiling the target APK using apktool\n"%s"', decompiled_path)
        prepare_decompile_dir(decompiled_path)
        decompile_option, no_res = build_decompile_options(
            decompiled_path, force_manifest, no_res, decompile_opts
        )
        run_apktool(decompile_option, str(apk_path.resolve()), apktool)
    elif not decompiled_path.exists():
        logger.error("Decompiled directory not found: %s", decompiled_path)
        sys.exit(-1)

    # Process if decompile is success
    modified_dex_number = inject_gadget_into_apk(
        apk_path,
        arch,
        decompiled_path,
        no_res,
        force_manifest,
        main_activity,
        config,
        js,
        GadgetSource(custom_gadget_name, custom_gadget_path, frida_version, github_repo),
    )

    # Rebuild with apktool, print apk_path if process is success
    if not skip_recompile:
        logger.debug('Recompiling the new APK using apktool "%s"', decompiled_path)

        recompile_option = ["b"]
        if use_aapt2:
            recompile_option += ["--use-aapt2"]
        if recompile_opts:
            recompile_option += recompile_opts.split()

        run_apktool(recompile_option, str(decompiled_path.resolve()), apktool)
        recompiled_apk_path = decompiled_path.joinpath("dist", apk_path.name)
        if not recompiled_apk_path.exists():
            # Carrying on would repack and sign an APK that is not there
            logger.error("APK not found: %s", recompiled_apk_path)
            sys.exit(-1)

        logger.info("Frida gadget injected into APK: %s", recompiled_apk_path)

        # The wrapped JavaScript file is removed by the atexit hook that created it,
        # so it no longer leaks when --skip-recompile is used or the run fails.

        restore_original_dex(apk_path, recompiled_apk_path, modified_dex_number)

        if sign:
            logger.debug("Starting APK signing using uber-apk-signer")
            sign_apk(str(recompiled_apk_path), ks, ks_alias, ks_key_pass, ks_pass)
            return
    else:
        logger.info(apk_path)
    logger.warning(
        "The APK is not signed. Use the --sign option to sign it automatically, "
        "or sign the APK manually before installing it."
    )


if __name__ == "__main__":
    # pylint: disable=no-value-for-parameter
    run()
