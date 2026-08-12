"""Choosing the gadget library and putting it inside the decompiled APK."""
import json
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from androguard.core.apk import APK

from . import INSTALLED_FRIDA_VERSION
from .apk_utils import get_main_activity
from .frida_github import FridaGithub
from .logger import logger
from .paths import FILE_DIR
from .smali import insert_loadlibary, modify_manifest


def download_gadget(
    arch: str,
    frida_version: str = None,
    custom_gadget_path: str = None,
    github_repo: str = None,
):
    """
    Download the frida gadget library or use a custom file.

    Parameters
    ----------
    arch : str
        architecture of the device
    frida_version : str
        specific frida version to use
    custom_gadget_path : str
        path to custom frida gadget file
    github_repo : str
        custom GitHub repository for the frida gadget

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
    elif INSTALLED_FRIDA_VERSION:
        logger.info("Auto-detected your frida version: %s", INSTALLED_FRIDA_VERSION)
        version = INSTALLED_FRIDA_VERSION
    else:
        logger.error(
            "frida is not installed, so the gadget version cannot be detected.\n"
            "Install it with 'pip install frida', or name the release yourself "
            "with the --frida-version option."
        )
        sys.exit(-1)

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


def detect_apk_architectures(decompiled_path):
    """
    Detect architectures from the APK's lib directory.

    Parameters
    ----------
    decompiled_path : str
        decompiled path of apk file

    Returns
    -------
    list
        List of detected architectures

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
    """
    Work out which activity the loadLibrary call goes into.

    Parameters
    ----------
    apk : APK
        parsed apk file
    main_activity : str
        activity given with --main-activity

    Returns
    -------
    str
        the activity class name

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
    """
    Decide the file name the gadget is stored under inside the APK.

    Parameters
    ----------
    gadget_path : str
        path of the downloaded or supplied gadget
    custom_gadget_name : str
        name given with --custom-gadget-name
    arch : str
        the requested architecture, or 'multi-arch'

    Returns
    -------
    str
        the file name to use in lib/<abi>

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
    """
    Create the lib/<abi> directory the gadget is copied into.

    Parameters
    ----------
    decompiled_path : Path
        decompiled path of apk file
    current_arch : str
        architecture being injected

    Returns
    -------
    Path
        the lib/<abi> directory

    Raises
    ------
    NotImplementedError
        the architecture has no known ABI directory

    """
    if current_arch not in ARCH_DIRNAMES:
        raise NotImplementedError(f"The architecture '{current_arch}' is not supported.")

    lib_arch_dir = decompiled_path.joinpath("lib", ARCH_DIRNAMES[current_arch])
    lib_arch_dir.mkdir(parents=True, exist_ok=True)
    return lib_arch_dir


def load_config_data(config: str) -> dict:
    """
    Read a gadget config file and check it declares an interaction.

    Parameters
    ----------
    config : str
        path of the config file

    Returns
    -------
    dict
        the parsed config

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
    """
    Explain what a config without --js means for the resulting APK.

    Parameters
    ----------
    config : str
        path of the config file

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
    """
    Write the gadget's config file next to the library.

    Parameters
    ----------
    config : str
        path given with --config
    js : str
        path given with --js
    lib_arch_dir : Path
        the lib/<abi> directory
    load_library_name : str
        name passed to System.loadLibrary
    upload_files : dict
        files still to copy, the config is removed from it
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
    """
    Copy the config and script files into the APK's lib directory.

    Parameters
    ----------
    upload_files : dict
        file type to source path
    lib_arch_dir : Path
        the lib/<abi> directory
    load_library_name : str
        name passed to System.loadLibrary

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
    """
    Where the gadget library comes from and what it is called.

    Attributes
    ----------
    custom_gadget_name : str
        name given with --custom-gadget-name
    custom_gadget_path : str
        path given with --custom-gadget-path
    frida_version : str
        version given with --frida-version
    github_repo : str
        repository given with --github-repo

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
    """
    Inject frida gadget into an APK.

    Parameters
    ----------
    apk_path : str
        path of apk file
    arch : str
        architecture of the device, or 'multi-arch' to read them from the APK
    decompiled_path : Path
        decompiled path of apk file
    no_res : bool
        whether the APK was decompiled without decoding resources
    force_manifest : bool
        patch the manifest even when resources were skipped
    main_activity : str
        activity to inject into, resolved from the manifest when omitted
    config : str
        path of the gadget config file
    js : str
        path of the script to load on the device
    gadget_source : GadgetSource
        where the gadget comes from and what it is called

    Raises
    ------
    FileNotFoundError
        file not found
    NotImplementedError
        not implemented

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
