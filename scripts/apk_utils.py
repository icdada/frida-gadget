from androguard.core.apk import APK

from .logger import logger

def get_main_activity(apk:APK):
    x = set()
    y = set()

    for i in apk.xml:
        if apk.xml[i] is None:
            continue
        activities_and_aliases = apk.xml[i].findall(".//activity") + \
                                    apk.xml[i].findall(".//activity-alias")

        for item in activities_and_aliases:
            # Some applications have more than one MAIN activity.
            # For example: paid and free content
            activityEnabled = item.get(apk._ns("enabled"))
            if activityEnabled == "false":
                continue

            for sitem in item.findall(".//action"):
                val = sitem.get(apk._ns("name"))
                if val == "android.intent.action.MAIN":
                    activity = item.get(apk._ns("name"))
                    target_activty = item.get(apk._ns("targetActivity"))
                    if target_activty is not None:
                        logger.debug('Target activity found: %s -> %s', activity, target_activty)
                        activity = target_activty
                    if activity is not None:
                        x.add(activity)
                    else:
                        logger.warning('Main activity without name')

            for sitem in item.findall(".//category"):
                val = sitem.get(apk._ns("name"))
                if val == "android.intent.category.LAUNCHER":
                    activity = item.get(apk._ns("name"))
                    target_activty = item.get(apk._ns("targetActivity"))
                    if target_activty is not None:
                        activity = target_activty
                    if activity is not None:
                        y.add(activity)
                    else:
                        logger.warning('Launcher activity without name')

    activities = x.intersection(y)
    if len(activities) == 0:
        return None
    elif len(activities) > 1:
        logger.error("Multiple main activities found: %s", activities)
        logger.error('Please specify one using the --main-activity option.')
        return -1

    main_activity = activities.pop()
    return main_activity