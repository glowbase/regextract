# regextract
Extract key values from registry hives to base line machines during a static forensic investigation. 

Currently, the script pulls the following information.
- Operating System (Build, Version, Edition, etc.)
- Computer Name
- Time Zone (Bias, Time Zone, etc.)
- Network (Interfaces, IP Addresses, DHCP, etc.)

## Use
Ensure all registry hives are retrieved from the forensic image using a tool such as FTK Imager and placed into the *hives/* directory. The execute the script shown below:

```bash
python3 reg.py
```

Once executed, you should see an *output.xlsx* spreadsheet with the information pulled from the registry hives provided. Currently, information is separated into different sheets for ease of use.
