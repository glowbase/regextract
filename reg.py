from regipy.registry import RegistryHive
from regipy import convert_wintime
import pandas as pd
import struct
import re

GUID_REGEX = r"{[0-9A-Z]{8}-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{12}}"

def get_control_set():
    print("Gathering Control Set")

    _key = "SYSTEM\\Select\\Current"

    reg = RegistryHive("hives/" + _key.split("\\")[0])
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

    reg = RegistryHive("hives/" + _key.split("\\")[0])
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
    keys = ["IPAddress", "SubnetMask", "EnableDHCP", "DhcpIPAddress", "DhcpDefaultGateway", "DhcpSubnetMaskOpt", "DhcpNameServer", "DhcpServer"]
    
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

    reg = RegistryHive("hives/" + _key.split("\\")[0])
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
    
    reg = RegistryHive("hives/" + _key.split("\\")[0])
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

    reg = RegistryHive("hives/" + _key.split("\\")[0])
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

    return out

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

    export(all_data)

    print('\n-------- EXPORTED REGISTRY INFORMATION --------')