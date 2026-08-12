"""Reading and patching the smali apktool produces."""
import os
import sys

from .logger import logger


def find_activity_smali(decompiled_path, main_activity):
    """
    Locate the smali file of an activity across the smali_classes* trees.

    Parameters
    ----------
    decompiled_path : Path
        decompiled path of apk file
    main_activity : str
        activity class name

    Returns
    -------
    tuple
        the smali file path, and the smali_classes<N> number it sits in
        (None for the plain 'smali' directory)

    Raises
    ------
    FileNotFoundError
        the activity has no smali file

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
    """
    Insert the loadLibrary call into the first usable entrypoint.

    Parameters
    ----------
    text : list
        lines of the smali file, modified in place
    load_library_name : str
        name passed to System.loadLibrary

    Returns
    -------
    bool
        True when the call was inserted

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
    """
    Inject loadlibary code to main activity.

    Parameters
    ----------
    decompiled_path : str
        decomplied path of apk file
    main_activity : str
        main activity of apk file
    load_library_name : str
        name of load library

    Returns
    -------
    int
        the smali_classes<N> number the patched activity sits in

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
    """
    Modify manifest permissions.

    Parameters
    ----------
    decompiled_path : str
        decomplied path of apk file

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
