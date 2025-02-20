# ActiveDirectory_PowerShell_Automation_Scripts


[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Project Overview

This repository contains a collection of PowerShell scripts designed to automate common Active Directory (AD) administration tasks. These scripts are built with production-readiness in mind, incorporating robust error handling, input validation, and logging to ensure reliability and security in real-world environments.  They are intended to streamline IT support and system administration workflows, saving time and reducing the potential for human error in routine AD management tasks.

## Features

This repository includes the following PowerShell automation scripts:

*   **`Scripts/UserManagement/New-ADUser-ProductionReady.ps1`**:
    *   **Description:** Automates the creation of new Active Directory user accounts. Takes user details as parameters and creates a new user account with enhanced error handling, input validation, and logging for production environments.
    *   **Example Usage:**
        ```powershell
        .\Scripts\UserManagement\New-ADUser-ProductionReady.ps1 -UserName "testuser1" -LastName "Test" -FirstName "User1" -UserOU "OU=TestUsers,DC=example,DC=com" -InitialPassword (Read-Host -AsSecureString -Prompt "Enter Initial Password")
        ```
    *   **Notes:** Requires Active Directory PowerShell module, administrative privileges, logs to `C:\Logs\ADUserScriptLogs`, includes input validation, securely prompts for initial password.

*   **`Scripts/UserManagement/Update-ADUser-ProductionReady.ps1`**:
    *   **Description:** Updates information for existing Active Directory user accounts, allowing modification of attributes like Department, Title, and Office Phone. Features robust error handling, input validation, and logging for production use.
    *   **Example Usage:**
        ```powershell
        .\Scripts\UserManagement\Update-ADUser-ProductionReady.ps1 -Identity "testuser1" -Department "New IT Department" -Title "Senior Test Engineer" -OfficePhone "02-1111-2222"
        ```
    *   **Notes:** Requires Active Directory PowerShell module, administrative privileges, logs to `C:\Logs\ADUserScriptLogs`, includes input validation, optional parameters for attributes.

*   **`Scripts/GroupManagement/Add-ADGroupMember-ProductionReady.ps1`**:
    *   **Description:** Automates adding user accounts to Active Directory groups. Takes the group name and user identity as parameters, providing enhanced error handling, input validation, and logging for production environments.
    *   **Example Usage:**
        ```powershell
        .\Scripts\GroupManagement\Add-ADGroupMember-ProductionReady.ps1 -GroupName "TestGroup" -UserIdentity "testuser1"
        ```
    *   **Notes:** Requires Active Directory PowerShell module, administrative privileges, logs to `C:\Logs\ADUserScriptLogs`, includes input validation.

*   **`Scripts/PermissionManagement/Set-FolderPermission-ProductionReady.ps1`**:
    *   **Description:** Automates setting folder or file share permissions for Active Directory groups. Takes the folder path, group name, and permission type as parameters, incorporating robust error handling, input validation, and logging for production scenarios.
    *   **Example Usage:**
        ```powershell
        .\Scripts\PermissionManagement\Set-FolderPermission-ProductionReady.ps1 -FolderPath "\\\\server\\share\\data" -GroupName "DataReadUsers" -Permissions "ReadAndExecute"
        ```
    *   **Notes:** Requires Active Directory PowerShell module, administrative privileges, logs to `C:\Logs\ADUserScriptLogs`, includes input validation, validates permission types against `ValidateSet`.

*   **`Scripts/UserManagement/Disable-ADUser-ProductionReady.ps1`**:
    *   **Description:** Automates disabling Active Directory user accounts, typically for leavers. Takes the user identity as a parameter and disables the account with improved error handling, input validation, and logging suitable for production use.
    *   **Example Usage:**
        ```powershell
        .\Scripts\UserManagement\Disable-ADUser-ProductionReady.ps1 -UserIdentity "retireuser1"
        ```
    *   **Notes:** Requires Active Directory PowerShell module, administrative privileges, logs to `C:\Logs\ADUserScriptLogs`, includes input validation.

## Getting Started

To use these scripts, you will need to meet the following prerequisites and follow the setup steps:

### Prerequisites

*   **Active Directory Environment:** Access to an Active Directory domain is required for these scripts to function.
*   **PowerShell with Active Directory Module:** Ensure you have PowerShell installed on a Windows machine joined to the Active Directory domain, with the Active Directory PowerShell module installed. You can install it using: `Install-Module -Name ActiveDirectory`
*   **Administrative Privileges:** You need to run these scripts with an account that has appropriate administrative privileges in the Active Directory domain to perform user and group management tasks.
*   **Execution Policy:**  Your PowerShell execution policy might need to be adjusted to allow running scripts. Check your current policy with `Get-ExecutionPolicy` and consider setting it to `RemoteSigned` or a more restrictive policy as per your organization's security guidelines.

### Setup

1.  **Download the Scripts:** Clone or download this repository to your local machine.
2.  **Review Scripts:** Carefully review the code of each script to understand its functionality and ensure it meets your requirements. Pay attention to the `NOTES` section in each script's header for important considerations and warnings.
3.  **Configure Logging Path (Optional):**  The script logs are written to `C:\Logs\ADUserScriptLogs` by default.  You can modify the `$LogFolderPath` variable at the beginning of each script to change the log file location if needed. Ensure the script execution account has write access to the specified log folder.
4.  **Test in a Test Environment:** **Crucially, before running these scripts in a production Active Directory environment, thoroughly test them in a dedicated test environment or a test Organizational Unit (OU).** Verify that the scripts function as expected and do not cause unintended side effects.
5.  **Run the Scripts:** Open PowerShell as an administrator, navigate to the directory where you saved the scripts, and execute the desired script using the examples provided in the `Features` section and within each script's header documentation.

## Repository Structure

ActiveDirectory-PowerShell-Automation-Scripts/
├── README.md
├── LICENSE
├── .gitignore
├── Modules/
├── Scripts/
│ ├── UserManagement/
│ │ ├── New-ADUser-ProductionReady.ps1
│ │ ├── Update-ADUser-ProductionReady.ps1
│ │ ├── Disable-ADUser-ProductionReady.ps1
│ ├── GroupManagement/
│ │ ├── Add-ADGroupMember-ProductionReady.ps1
│ ├── PermissionManagement/
│ │ ├── Set-FolderPermission-ProductionReady.ps1
├── Documentation/


*   **`README.md`**: You are here! This file provides an overview of the project and instructions for use.
*   **`LICENSE`**: Contains the license information for this project (MIT License).
*   **`.gitignore`**: Specifies intentionally untracked files that Git should ignore.
*   **`Modules/`**: (Currently Empty)  Future folder for custom PowerShell modules if developed.
*   **`Scripts/`**: Contains all the PowerShell automation scripts, organized by category.
    *   **`Scripts/UserManagement/`**: Scripts for managing user accounts.
    *   **`Scripts/GroupManagement/`**: Scripts for managing group membership.
    *   **`Scripts/PermissionManagement/`**: Scripts for managing folder/file share permissions.
*   **`Documentation/`**: (Currently Empty) Future folder for more detailed documentation if needed.

## Usage

Refer to the `Features` section above for a quick overview of each script and example usage. For detailed information on each script, please read the comments and documentation within the script files themselves (within the `<# ... #>` comment blocks).  These comments provide parameter descriptions, examples, and important notes specific to each script.

**General Script Execution:**

1.  Open PowerShell as an Administrator.
2.  Navigate to the directory where you have saved the scripts (e.g., `cd C:\path\to\ActiveDirectory-PowerShell-Automation-Scripts\Scripts\UserManagement`).
3.  Execute the script using `.\ScriptName.ps1` followed by the required parameters.  For example: `.\New-ADUser-ProductionReady.ps1 -UserName "..." -LastName "..." ...`


## Disclaimer

**Please use these scripts with caution and at your own risk.**  These scripts are provided as examples and are intended to automate common Active Directory tasks. However, Active Directory administration requires careful planning and execution.

*   **Thorough Testing is Mandatory:**  **Always test these scripts thoroughly in a non-production Active Directory environment before using them in a live production system.**
*   **Understand the Scripts:**  Ensure you fully understand what each script does before running it. Review the code and comments carefully.
*   **Administrative Responsibility:** You are responsible for ensuring that the scripts are used in compliance with your organization's policies and security guidelines.
*   **No Warranty:**  These scripts are provided "as is" without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose and noninfringement. In no event shall the authors or copyright holders be liable for any claim, damages or other liability, whether in an action of contract, tort or otherwise, arising from, out of or in connection with the software or the use or other dealings in the software.

---

For any questions or feedback regarding these scripts, please feel free to [coolsu92@gmail.com](mailto:coolsu92@gmail.com). 
