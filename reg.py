from regipy.registry import RegistryHive
import pandas as pd

def get_control_set():
    print("Gathering Control Set")

    _key = "SYSTEM\Select\Current"

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

    _key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion"

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
        "SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName",
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
        "SYSTEM\CurrentControlSet\Control\TimeZoneInformation",
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

def get_network_information(control_set):
    print("Gathering Network Information")
    
    key = parse_hive(
        "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces",
        control_set
    )

    out = {"Interface": [], "Key": [], "Value": []}
    keys = ["IPAddress", "SubnetMask", "EnableDHCP", "DhcpIPAddress", "DhcpDefaultGateway", "DhcpSubnetMaskOpt", "DhcpNameServer", "DhcpServer"]
    
    interface_keys = get_network_interface_keys(key)
    last_interface = ""

    for interface in interface_keys:
        for sk in interface.iter_values():
            if sk.name in keys:
                out["Key"].append(sk.name)
                out["Value"].append(sk.value)

                if last_interface is not interface.name:
                    out["Interface"].append(interface.name)
                else:
                    out["Interface"].append("")
                    
                last_interface = interface.name

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

    all_data["OPERATING SYSTEM"] = get_operating_system()
    all_data["COMPUTER NAME"] = get_computer_name(control_set)
    all_data["TIME ZONE"] = get_time_zone(control_set)
    all_data["NETWORK"] = get_network_information(control_set)

    export(all_data)

    print('\n-------- EXPORTED REGISTRY INFORMATION --------')