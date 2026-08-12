"""Tests for scripts.apk_utils."""
import xml.etree.ElementTree as ET
from types import SimpleNamespace

from androguard.core.apk import APK

from scripts.apk_utils import ANDROID_NS, get_main_activity

LAUNCHER_FILTER = (
    "<intent-filter>"
    '<action android:name="android.intent.action.MAIN"/>'
    '<category android:name="android.intent.category.LAUNCHER"/>'
    "</intent-filter>"
)


def fake_apk(*bodies):
    """Build an object exposing the manifests the way androguard's APK does."""
    manifests = {}
    for idx, body in enumerate(bodies):
        xml = (
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
            f"<application>{body}</application></manifest>"
        )
        manifests[f"manifest{idx}.xml"] = ET.fromstring(xml)
    return SimpleNamespace(xml=manifests)


def test_android_namespace_matches_androguard():
    """The hardcoded namespace has to agree with the one androguard resolves."""
    # pylint: disable=protected-access
    assert ANDROID_NS + "name" == APK._ns("name")


def test_single_main_activity():
    """An activity with both MAIN and LAUNCHER is the entrypoint."""
    apk = fake_apk(f'<activity android:name="com.e.Main">{LAUNCHER_FILTER}</activity>')
    assert get_main_activity(apk) == "com.e.Main"


def test_activity_alias_resolves_to_target():
    """An alias points at the class that actually has to be patched."""
    apk = fake_apk(
        '<activity android:name="com.e.Real"/>'
        '<activity-alias android:name="com.e.Alias" '
        f'android:targetActivity="com.e.Real">{LAUNCHER_FILTER}</activity-alias>'
    )
    assert get_main_activity(apk) == "com.e.Real"


def test_disabled_activity_is_skipped():
    """android:enabled="false" rules an activity out."""
    apk = fake_apk(
        '<activity android:name="com.e.Off" android:enabled="false">'
        f"{LAUNCHER_FILTER}</activity>"
        f'<activity android:name="com.e.On">{LAUNCHER_FILTER}</activity>'
    )
    assert get_main_activity(apk) == "com.e.On"


def test_multiple_main_activities_report_minus_one():
    """The caller has to ask the user which one to patch."""
    apk = fake_apk(
        f'<activity android:name="com.e.A">{LAUNCHER_FILTER}</activity>'
        f'<activity android:name="com.e.B">{LAUNCHER_FILTER}</activity>'
    )
    assert get_main_activity(apk) == -1


def test_activities_are_collected_across_manifests():
    """Split manifests are searched too."""
    apk = fake_apk(
        f'<activity android:name="com.e.One">{LAUNCHER_FILTER}</activity>',
        f'<activity android:name="com.e.Two">{LAUNCHER_FILTER}</activity>',
    )
    assert get_main_activity(apk) == -1


def test_no_main_activity():
    """A plain activity is not an entrypoint."""
    assert get_main_activity(fake_apk('<activity android:name="com.e.Plain"/>')) is None


def test_main_without_launcher_category():
    """MAIN alone does not make an activity the launcher entry."""
    apk = fake_apk(
        '<activity android:name="com.e.M"><intent-filter>'
        '<action android:name="android.intent.action.MAIN"/>'
        "</intent-filter></activity>"
    )
    assert get_main_activity(apk) is None


def test_launcher_without_main_action():
    """LAUNCHER alone does not make an activity the launcher entry."""
    apk = fake_apk(
        '<activity android:name="com.e.L"><intent-filter>'
        '<category android:name="android.intent.category.LAUNCHER"/>'
        "</intent-filter></activity>"
    )
    assert get_main_activity(apk) is None


def test_activity_without_name_is_ignored():
    """An entry we cannot name cannot be patched."""
    assert get_main_activity(fake_apk(f"<activity>{LAUNCHER_FILTER}</activity>")) is None


def test_empty_manifest():
    """A manifest without activities yields nothing."""
    assert get_main_activity(fake_apk("")) is None


def test_none_manifest_entries_are_skipped():
    """androguard stores None for manifests it could not parse."""
    apk = fake_apk(f'<activity android:name="com.e.Main">{LAUNCHER_FILTER}</activity>')
    apk.xml["broken.xml"] = None
    assert get_main_activity(apk) == "com.e.Main"
