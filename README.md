# regextract
Extract key values from registry hives to base line machines during a static forensic investigation.


## Use
Ensure all registry hives are retrieved from the forensic image using a tool such as FTK Imager and placed into the *hives/* directory. The execute the script shown below:

```bash
python3 reg.py
```
