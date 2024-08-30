from regipy.registry import RegistryHive
from regipy import convert_wintime
import pandas as pd
import re

GUID_REGEX = r"{[0-9A-Z]{8}-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{12}}"
USB_REGEX = r".*?VID_([0-9A-Z]{4})&PID_([0-9A-Z]{4})"

def get_control_set():
    print("Gathering Control Set")

    _key = "SYSTEM\\Select\\Current"

    reg = RegistryHive("hives/SYSTEM")
    cs = reg.get_control_sets(_key)

    out = ""

    if len(cs) > 0:
        out = cs[0].split('\\')[1]

    return out

def parse_hive(_key, control_set):
    _key = _key.replace("CurrentControlSet", control_set)
    
    reg = RegistryHive("hives/" + _key.split("\\")[0])
    key = reg.get_key(_key)
    return key

def get_operating_system():
    print("Gathering Operating System")

    _key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"

    reg = RegistryHive("hives/SOFTWARE")
    key = reg.get_key(_key)

    out = {"Key": [], "Value": []}
    keys = ["CurrentBuild", "CurrentVersion", "ProductName", "EditionID"]

    for val in key.iter_values():
        if val.name in keys:
           out["Key"].append(val.name)
           out["Value"].append(val.value)

    return out

def get_computer_name(control_set):
    print("Gathering Computer Name")

    key = parse_hive(
        "SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName",
        control_set
    )

    out = {"Key": [], "Value": []}
    keys = ["ComputerName"]

    for val in key.iter_values():
        if val.name in keys:
            out["Key"].append(val.name)
            out["Value"].append(val.value)

    return out

def get_time_zone(control_set):
    print("Gathering Time Zone")

    key = parse_hive(
        "SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation",
        control_set
    )

    out = {"Key": [], "Value": []}
    keys = ["TimeZoneKeyName", "DaylightBias"]

    for val in key.iter_values():
        if val.name in keys:
           out["Key"].append(val.name)
           out["Value"].append(val.value)

    return out

def get_network_interface_keys(key):
    interface_keys = []

    for interface in key.iter_subkeys():
        interface_keys.append(interface)

    return interface_keys

def get_network_interfaces(control_set):
    print("Gathering Network Information")
    
    key = parse_hive(
        "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces",
        control_set
    )

    out = {"GUID": [], "Key": [], "Value": []}
    keys = ["IPAddress", "SubnetMask", "EnableDHCP", "DhcpIPAddress", "DhcpDefaultGateway", "DhcpSubnetMaskOpt", "DhcpNameServer", "DhcpServer", "LeaseObtainedTime"]
    
    interface_keys = get_network_interface_keys(key)
    last_interface = ""

    for interface in interface_keys:
        for sk in interface.iter_values():
            if sk.name in keys:
                out["Key"].append(sk.name)
                out["Value"].append(sk.value)

                if last_interface is not interface.name:
                    out["GUID"].append(interface.name)
                else:
                    out["GUID"].append("")
                    
                last_interface = interface.name

    return out

def get_network_profile_keys(key):
    profile_keys = []

    for profile in key.iter_subkeys():
        profile_keys.append(profile)

    return profile_keys


def get_network_profiles():
    print("Gathering Network Profiles")

    _key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles"

    reg = RegistryHive("hives/SOFTWARE")
    key = reg.get_key(_key)

    out = {"GUID": [], "Value": []}
    
    profile_keys = get_network_profile_keys(key)

    for profile in profile_keys:
        for sk in profile.iter_values():
            if sk.name == "ProfileName":
                out["Value"].append(sk.value)
                out["GUID"].append(profile.name)

    return out

def get_utc_time(timestamp):
    t = convert_wintime(timestamp).utctimetuple()

    return f"{t.tm_mday}/{t.tm_mon}/{t.tm_year} at {t.tm_hour}:{t.tm_min}:{t.tm_sec} UTC"
    
def get_last_shutdown(control_set):
    print("Gathering Last Shutdown")

    _key = "SYSTEM\\CurrentControlSet\\Control\\Windows"
    _key = _key.replace("CurrentControlSet", control_set)
    
    reg = RegistryHive("hives/SYSTEM")
    key = reg.get_key(_key)

    last_modified = get_utc_time(key.header.last_modified)

    return {"Key": ["LastModified"], "Value": [last_modified]}

def get_windows_defender():
    print("Gathering Windows Defender")

    _key = "SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection"
    
    reg = RegistryHive("hives/" + _key.split("\\")[0])
    key = reg.get_key(_key)
    
    last_modified = get_utc_time(key.header.last_modified)

    out = {"Key": ["LastModified"], "Value": [last_modified]}
    keys = ["DpaDisabled", "DisableRealtimeMonitoring"]

    for val in key.iter_values():
        if val.name in keys:
            out["Key"].append(val.name)
            out["Value"].append(val.value)

    return out

def get_applications():
    print("Gathering Applications")

    _key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"

    reg = RegistryHive("hives/SOFTWARE")
    key = reg.get_key(_key)
    keys = ["InstallLocation", "InstallDate", "InstallSource", "Publisher", "DisplayVersion", "DisplayName", "URLInfoAbout"]
    out = {"GUID": [], "Key": [], "Value": []}
    last_guid = ""

    for guid in key.iter_subkeys():
        if re.match(GUID_REGEX, guid.name):
            last_modified = get_utc_time(guid.header.last_modified)

            for val in guid.iter_values():
                if val.name in keys:
                    out["Key"].append(val.name)
                    out["Value"].append(val.value)

                    if guid.name == last_guid:
                        out["GUID"].append("")
                    else:
                        out["GUID"].append(guid.name)

                    last_guid = guid.name

            out["Key"].append("LastModified")
            out["Value"].append(last_modified)
            out["GUID"].append("")

    return out

def get_local_users():
    print("Gathering Local Users")

    _key = "SAM\\SAM\\Domains\\Account\\Users"

    reg = RegistryHive("hives/SAM")
    key = reg.get_key(_key)

    # SID-RID
    # SAM\Domains\Account\V
    # Last 12 bytes groups of 4 bytes == Machine ID

    # 204 end of fixed header in V
    rid = []
    username = []
    logon_count = []
    last_modified = []
    
    for sk in key.iter_subkeys():
        if sk.name == "Names":
            for name in sk.iter_subkeys():
                username.append(name.name)
                lm = get_utc_time(name.header.last_modified)
                last_modified.append(lm)

                for rid_key in name.iter_values():
                    rid.append(rid_key.value_type)
        else:
            for val in sk.iter_values():
                if val.name == "F":
                    ba = bytearray.fromhex(val.value)[66:68]
                    lc = int.from_bytes(ba, 'little')

                    logon_count.append(lc)

    return {
        "RID": rid,
        "Usernames": username,
        "LogonCount": logon_count,
        "LastModified": last_modified
    }

def get_device_volumes():
    _key = "SOFTWARE\\Microsoft\\Windows Portable Devices\\Devices"

    reg = RegistryHive("hives/SOFTWARE")
    key = reg.get_key(_key)

    last_modified = []
    name = []
    
    for sk in key.iter_subkeys():
        lm = get_utc_time(sk.header.last_modified)
        last_modified.append(lm)

        for val in sk.iter_values():
            if val.name == "FriendlyName":
                ids = re.findall(USB_REGEX, sk.header)

                name.append(val.value)

def get_devices(control_set):
    print("Get Devices")

    key = parse_hive(
        "SYSTEM\\ControlSet001\\Enum\\USB",
        control_set
    )

    vendor_ids = []
    product_ids = []
    device_ids = []
    last_modified = []

    for dev in key.iter_subkeys():
        lm = get_utc_time(dev.header.last_modified)

        if not dev.name.startswith("ROOT_HUB"):
            ids = re.findall(USB_REGEX, dev.name)[0]

            vendor_ids.append(ids[0])
            product_ids.append(ids[1])
            last_modified.append(lm)

            for val in dev.iter_subkeys():
                device_ids.append(val.name)

    # get_device_volumes()

    return {
        "VendorID": vendor_ids,
        "ProductID": product_ids,
        "DeviceID": device_ids,
        "LastModified": last_modified
    }

def export(output):
    print("Exporting Data")

    frames = []
    keys = []

    for key in output:
        keys.append(key)
        frames.append(pd.DataFrame(output[key]))

    with pd.ExcelWriter("output.xlsx") as writer:
        for index, frame in enumerate(frames):
            frame.to_excel(writer, sheet_name=keys[index], index=False)    

if __name__ == "__main__":
    print('-------- PULLING REGISTRY INFORMATION --------\n')

    all_data = {}

    control_set = get_control_set()

    all_data["Operating System"] = get_operating_system()
    all_data["Computer Name"] = get_computer_name(control_set)
    all_data["Time Zone"] = get_time_zone(control_set)
    all_data["Network Interfaces"] = get_network_interfaces(control_set)
    all_data["Network Profile"] = get_network_profiles()
    all_data["Last Shutdown"] = get_last_shutdown(control_set)
    all_data["Windows Defender"] = get_windows_defender()
    all_data["Applications"] = get_applications()
    all_data["Local Users"] = get_local_users()
    # all_data["USB Devices"] = get_volume_names()
    all_data["Devices"] = get_devices(control_set)

    export(all_data)

    print('\n-------- EXPORTED REGISTRY INFORMATION --------')