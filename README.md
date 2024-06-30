# Project: VULNER

This script uses various analyzing and carving tools to automate network scanning, aiming to swiftly and accurately identify vulnerabilities and risks and providing comprehensive reports.

## Video Demonstration

[![Video Demonstration](https://img.youtube.com/vi/PjDXN4xUNso/0.jpg)](https://youtu.be/PjDXN4xUNso)

Click the image above to watch the video demonstration.

## Requirements

A Linux system with internet connectivity (Kali Linux preferred).

The following tools will be installed if missing:

- nmap
- hydra
- medusa
- zip

## Script Workflow

### User Input:

- The script ensures it is run as root.
- The script prompts the user for:
  - A network to scan (in CIDR format).
  - A name for the output directory.
  - A scan type ('Basic' or 'Full').
  - If 'Full' is selected, additional options for nbstat and SMB Suite are provided.

### System Preparation:

- The script checks if it is run as root.
- The script updates the system and installs any missing dependencies (optional).

### Network Scan:

#### Basic Scan:

- **Options**: `-sS -sU -version-intensity 0 -v`
- **Description**: Performs a SYN scan and a UDP scan with low intensity and verbosity, saving results in a greppable format.

#### Full Scan:

- **Options**: `-sS -sU -version-intensity 0 -A -v --script vuln`
- **Description**: Performs a more comprehensive scan, including OS detection, version detection, script scanning, and vulnerability scanning.
- **Additional Scripts**: Optionally runs `nbstat`, SMB Suite (`smb-enum-users` and `smb-enum-shares`), and `ms-sql-info`.

### Weak Password Checks:

- Uses Hydra to check for weak passwords on discovered services.
- If no weak passwords are found, Medusa is used for a secondary check.

### Results Logging and Archiving:

- Results are saved in the specified output directory.
- A summary of findings is logged.
- The output directory is zipped for easy distribution.

### Output Files
A `.zip` archive will be created, containing the results of the scan, along with detailed logs and an overall summary of the findings.

- `nmap_scan.gnmap`: Results of the Nmap scan.
- `pslist.txt`: List of running processes.
- `netscan.txt`: Network connections.
- `hivelist.txt`: Registry information.
- `report.txt`: Summary report of the scan.
- `smb_suite_results.txt`: Results of the SMB Suite (if selected).
- `mssql_info_results.txt`: Results of the ms-sql-info scan (if selected).
- Various logs and results from Hydra and Medusa.

## Troubleshoot
- **Root Check:** Ensure the script is run as root.
- **File Check:** Verify the memory dump file path is correct.
- **Tool Installation:** Ensure internet connectivity for installing missing tools.
- **Time and Resources:** Large memory dumps may take time and resources to process; ensure your system is adequately equipped.

## Tool Sources
- **Volatility 3:** [Volatility](https://github.com/volatilityfoundation/volatility3)
- **Bulk Extractor:** [Bulk Extractor](https://github.com/simsong/bulk_extractor)
- **Foremost:** [Foremost](http://foremost.sourceforge.net/)
- **Binwalk:** [Binwalk](https://github.com/ReFirmLabs/binwalk)
- **Strings:** [Strings](https://linux.die.net/man/1/strings)
- **PV:** [PV](https://linux.die.net/man/1/pv)
- **Cabextract:** [Cabextract](https://www.cabextract.org.uk/)

## NSE Scripts and Usage
### Nmap Scan:
- **Basic Scan**: Performs a SYN scan and a UDP scan with low intensity and verbosity, saving results in a greppable format.
  - Options: `-sS -sU -version-intensity 0 -v`
- **Full Scan**: Performs a comprehensive scan including OS detection, version detection, script scanning, and vulnerability scanning.
  - Options: `-sS -sU -version-intensity 0 -A -v --script vuln`

### Additional Scripts:
- **nbstat**: Retrieves NetBIOS information, including the NetBIOS name table and MAC addresses.
  - Options: `--script nbstat`
- **SMB Suite**: Includes `smb-enum-users` and `smb-enum-shares` to enumerate SMB users and shares.
  - Options: `--script smb-enum-users,smb-enum-shares`
- **ms-sql-info**: Gathers information about Microsoft SQL servers.
  - Options: `--script ms-sql-info`
