from androguard.core.bytecodes.apk import APK
import json
import sys

def get_app_components(apk_path):
    apk = APK(apk_path)
    
    activities = apk.get_activities()
    services = apk.get_services()
    receivers = apk.get_receivers()
    providers = apk.get_providers()

    exported_activities = [activity for activity in activities if apk.get_intent_filters("activity", activity)]
    exported_services = [service for service in services if apk.get_intent_filters("service", service)]
    exported_receivers = [receiver for receiver in receivers if apk.get_intent_filters("receiver", receiver)]
    exported_providers = [provider for provider in providers if apk.get_intent_filters("provider", provider)]

    components_info = {
        "Activities": activities,
        "Exported Activities": exported_activities,
        "Services": services,
        "Exported Services": exported_services,
        "Receivers": receivers,
        "Exported Receivers": exported_receivers,
        "Providers": providers,
        "Exported Providers": exported_providers,
    }

    return components_info

def main():
    apk_path = sys.argv[1]  # Get the APK path from the command-line arguments
    components_info = get_app_components(apk_path)
    print(json.dumps(components_info))

if __name__ == "__main__":
    main()
