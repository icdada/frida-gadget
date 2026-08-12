"""
Command line entry point for injecting the Frida gadget into an APK.

The work is spread across the sibling modules:
- apktool: decompiling, recompiling, and restoring the original dex files
- gadget: choosing the gadget and putting it inside the decompiled APK
- smali: patching the main activity and the manifest
- signing: handing the rebuilt APK to uber-apk-signer

What is left here is validating the options and the click command tying it up.
"""

import atexit
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import click

from .__version__ import __version__
from .apktool import (
    build_decompile_options,
    get_decompiled_path,
    prepare_decompile_dir,
    resolve_apktool,
    restore_original_dex,
    run_apktool,
)
from .gadget import GadgetSource, inject_gadget_into_apk
from .logger import logger
from .signing import sign_apk


def detect_adb_arch():
    """
    Detect the architecture of the currently connected device via ADB.

    This function communicates with a connected Android device over ADB
    to determine its CPU architecture (e.g., arm64-v8a, armeabi-v7a, x86).

    Returns
    -------
    str
        The detected architecture of the connected device.
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
    """
    Report the architecture the gadget will be built for.

    Parameters
    ----------
    arch : str
        normalized architecture name

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
    """
    Check the architecture is one we can download a gadget for.

    Parameters
    ----------
    arch : str
        normalized architecture name

    Returns
    -------
    str
        the architecture, lowercased

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
    """
    Check the files given with --js and --config are usable.

    Parameters
    ----------
    js : str
        path given with --js
    config : str
        path given with --config

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


def normalize_arch(arch: str, skip_decompile: bool) -> str:
    """
    Turn the --arch value into one of the names used internally.

    Parameters
    ----------
    arch : str
        value given with --arch, None to auto-detect over ADB
    skip_decompile : bool
        whether --skip-decompile was given

    Returns
    -------
    str
        'multi-arch' or one of the supported architecture names

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
    """
    Write a delayed copy of the script and return its path.

    Parameters
    ----------
    js : str
        path given with --js
    js_delay : int
        seconds to wait before the script runs

    Returns
    -------
    str
        path of the wrapped copy

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
    """
    Wrap JavaScript content with setTimeout.

    Parameters
    ----------
    js_content : str
        Original JavaScript content
    delay : int
        Seconds to wait before executing

    Returns
    -------
    str
        Wrapped JavaScript content

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
def run(
    apk_path: str,  # NOSONAR
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
