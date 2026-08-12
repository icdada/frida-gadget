"""Signing the rebuilt APK with uber-apk-signer."""
import os
import subprocess
import sys

from .logger import logger
from .paths import FILE_DIR
from .uber_apk_signer_github import UberApkSignerGithub


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
