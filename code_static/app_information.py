from androguard.core.bytecodes.apk import APK
import json
import sys

def get_app_info(apk_path):
    apk = APK(apk_path)
    app_info = {
        "App Name": apk.get_app_name(),
        "Package Name": apk.get_package(),
        "Main Activity": apk.get_main_activity(),
        "Target SDK": apk.get_target_sdk_version(),
        "Min SDK": apk.get_min_sdk_version(),
        "Max SDK": "N/A",  # Androguard does not provide max SDK directly
        "Android Version Name": apk.get_androidversion_name(),
        "Android Version Code": apk.get_androidversion_code(),
    }
    return app_info

def main():
    apk_path = sys.argv[1]
    app_info = get_app_info(apk_path)
    print(json.dumps(app_info))

if __name__ == "__main__":
    main()
