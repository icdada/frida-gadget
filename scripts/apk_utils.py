"""Helpers for reading activity information out of an APK manifest."""
from androguard.core.apk import APK

from .logger import logger

# Fixed by the Android manifest format, so reading attributes does not depend
# on androguard internals. tests/test_apk_utils.py checks it still agrees with
# androguard's own constant.
ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

MAIN_ACTION = "android.intent.action.MAIN"
LAUNCHER_CATEGORY = "android.intent.category.LAUNCHER"


def android_attr(element, name: str):
    """
    Read an 'android:' namespaced attribute off a manifest element.

    Parameters
    ----------
    element: manifest element
    name : str
        attribute name without the namespace

    Returns
    -------
    str
        the attribute value, or None when it is absent

    """
    return element.get(ANDROID_NS + name)


def iter_activities(apk: APK):
    """
    Yield every activity and activity-alias declared in the manifest.

    Parameters
    ----------
    apk : APK
        parsed apk file

    Yields
    ------
        the manifest elements, skipping the ones that are explicitly disabled

    """
    for manifest in apk.xml.values():
        if manifest is None:
            continue

        elements = manifest.findall(".//activity") + manifest.findall(".//activity-alias")
        for element in elements:
            # Some applications have more than one MAIN activity,
            # for example a paid and a free variant
            if android_attr(element, "enabled") == "false":
                continue

            yield element


def resolve_activity_name(element):
    """
    Resolve the class an activity entry points at.

    An activity-alias points at another activity through 'targetActivity',
    which is the class that actually has to be patched.

    Parameters
    ----------
    element: manifest element of an activity or activity-alias

    Returns
    -------
    str
        the class name, or None when the entry has neither attribute

    """
    activity = android_attr(element, "name")
    target_activity = android_attr(element, "targetActivity")
    if target_activity is not None:
        logger.debug("Target activity found: %s -> %s", activity, target_activity)
        return target_activity

    return activity


def declares(element, tag: str, value: str) -> bool:
    """
    Check whether an activity declares an intent filter entry.

    Parameters
    ----------
    element: manifest element of an activity or activity-alias
    tag : str
        child tag to look at, 'action' or 'category'
    value : str
        the android:name the child has to carry

    Returns
    -------
    bool
        True when at least one child matches

    """
    return any(
        android_attr(child, "name") == value for child in element.findall(f".//{tag}")
    )


def get_main_activity(apk: APK):
    """
    Find the activity the launcher starts.

    Parameters
    ----------
    apk : APK
        parsed apk file

    Returns
    -------
    str
        the main activity class name,
        None when the manifest declares none,
        -1 when it declares more than one

    """
    mains = set()
    launchers = set()

    for element in iter_activities(apk):
        is_main = declares(element, "action", MAIN_ACTION)
        is_launcher = declares(element, "category", LAUNCHER_CATEGORY)
        if not is_main and not is_launcher:
            continue

        name = resolve_activity_name(element)
        if name is None:
            logger.warning("Activity without name in the manifest")
            continue

        if is_main:
            mains.add(name)
        if is_launcher:
            launchers.add(name)

    activities = mains & launchers
    if not activities:
        return None

    if len(activities) > 1:
        logger.error("Multiple main activities found: %s", activities)
        logger.error("Please specify one using the --main-activity option.")
        return -1

    return activities.pop()
