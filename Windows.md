# ThreatHunting-CheatSheat For Windows

Simple usefull threat hunting cheat sheet for Windows environments, keep in mind these notes is usefull in newly enviroments not old windows versions.

This cheatsheet in more usefull when you don't access/not permited to use your tools in the case/eviroment or the time you reach to incidents.

---

**important Registry keys :**

| **Registry Key**                       | **Description**                                                                                                                                     |
|----------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------|
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | Lists applications that run at system startup. Useful for identifying persistence mechanisms.                                                     |
| `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | Similar to the above but for user-specific applications.                                                                                          |
| `HKLM\SYSTEM\CurrentControlSet\Services` | Contains information about services installed on the system, including their startup type and status.                                              |
| `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` | Contains the Local Security Authority settings. Look for any unusual modifications.                                                              |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` | Lists installed applications, which can help identify rogue software.                                                                              |
| `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Licensing Core` | Information about Terminal Services licensing. Modifications here can indicate unauthorized access attempts.                                      |
| `HKU\<SID>\Software\Microsoft\Windows\CurrentVersion\Explorer\Run` | User-specific auto-start programs at login, useful for detecting user-specific persistence mechanisms.                                            |
| `HKLM\SYSTEM\CurrentControlSet\Control\Keyboard Layout\Preload` | Lists keyboard layouts being used. Anomalies can indicate potential compromise in scenarios involving keyloggers.                                    |
| `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\ImagePath` | Contains the path to the executable for each service. Unusual paths can indicate malicious activity.                                               |
| `HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers` | Contains settings related to code integrity policies. Check for any unauthorized changes.                                                          |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` | Includes settings for Windows logon behavior. Look for keys like `AutoAdminLogon` for unusual logon configurations.                               |
| `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management` | Includes settings affecting how memory management is executed, can reveal tampering.                                                             |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI` | Contains settings for the logon user interface. Changes here may indicate unauthorized access attempts.                                           |
| `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies` | User-specific security policies that can reveal suspicious configurations when modified.                                                         |

---

### ThreatHunting with Powershell

**WebshellHunting**

```powershell
Get-Childitem -Path "<Files_path>" -Include *.aspx,*.asp -Recurse | Select-String -Pattern "IOC_Pattern" | Select-Object LineNumber,FileName,Path,Pattern 
```

_Recommended patterns for ebove command :_

<Files_path> = IIS web hosted enviroment path

IOC_Pattern  = cmd, System.Io, shell, password= , XOR, decode, base64, sha256, \\^, powershell, System.Diagnostics etc...

Common webshell imports in .aspx (Use as IOC_pattern) : 

| **Library/Namespace**                      | **Description**                                                                                   |
|--------------------------------------------|---------------------------------------------------------------------------------------------------|
| `System.IO`                                | Provides functionality for file and directory manipulation (e.g., reading/writing files).       |
| `System.Diagnostics`                        | Allows execution of external processes, useful for command-line execution.                       |
| `System.Net`                               | Contains classes for network operations, including HTTP requests and responses.                  |
| `System.Web`                               | Includes classes for web applications, handling HTTP requests, and sessions.                      |
| `System.Security`                           | Provides access to security-related functions and classes, sometimes used for bypassing security restrictions. |
| `System.Reflection`                        | Allows inspection of types in managed assemblies; often used for dynamic code loading.          |
| `Microsoft.AspNet`                        | Part of the ASP.NET framework for accessing web application functionalities.                     |
| `System.Text`                              | Used for text manipulation, commonly for encoding and decoding data.                             |
| `System.Threading`                         | Provides classes and interfaces for managing concurrent operations and threading.                |


Common file extensions associated with ASP.NET web applications : 

| **File Extension** | **Description**                                                                          |
|--------------------|------------------------------------------------------------------------------------------|
| `.aspx`            | ASP.NET Web Forms page; contains server-side code to render HTML dynamically.           |
| `.ascx`           | ASP.NET User Control; reusable components that can be embedded in .aspx pages.         |
| `.ashx`            | ASP.NET HTTP handler; processes HTTP requests and can return custom responses.          |
| `.asmx`            | ASP.NET Web Service; used to expose methods over HTTP, commonly for SOAP services.      |
| `.asax`            | ASP.NET Application file; contains event handlers for application-level events.         |
| `.config`          | Configuration files for ASP.NET applications, often used to store settings.            |
| `.axd`            | ASP.NET HTTP handler for various services, commonly used for web resources.             |
| `.dll`             | Compiled .NET assemblies used in ASP.NET applications; can contain server-side logic.   |
| `.svc`             | WCF Service file; defines services for web service calls in .NET.                       |
| `.json`            | Often used for configuration or data interchange, could be targeted in attacks.         |


**File signing check :** 

```powershell
Get-AuthenticodeSignature -FilePath "C:\Windows\system32\*"

#for ignoring errors like "The process cannot access the file because it is being usedby another process."
Get-ChildItem "C:\Windows\system32\*" | ForEach-Object { try { Get-AuthenticodeSignature -FilePath $_.FullName -ErrorAction Stop } catch {} }

```

**common directories that malware typically uses to store files, execute malicious code, or maintain persistence:**

**recommendation:** check These pathes for suspicous files if you see some executables dlls check the sign

_A Quick trick:_ you can use sort by "Access Modified" when viewing files by hand or script, many .dmp files like the ones mimikatz generates can found quickly because user often doesn't access these types of files. time is the key but keep in mind is not important in first look cause can be edited easily by attackers and should be checked more detailed in forensic and specific tools.

| **Directory**                                       | **Description**                                                                                         |
|----------------------------------------------------|---------------------------------------------------------------------------------------------------------|
| **`%TEMP%` or `%TMP%`**                            | Temporary directories used by the operating system where malware can store or execute temporary files.  |
| **`%APPDATA%`**                                    | Commonly used by malware to store configuration files and executable payloads, hiding in user profiles. |
| **`%PROGRAMDATA%`**                                | A shared space for applications to store data; malware often uses it for persistence across users.      |
| **`C:\Windows\System32`**                          | System directory where some malware places malicious DLLs or executable files to blend in with legitimate files. |
| **`C:\Windows\Temp`**                              | Similar to the TEMP directory, often used for temporary file storage by malware.                       |
| **`C:\Users\<Username>\AppData\Local\Temp`**      | User-specific temp folder commonly exploited for dropping malicious files that are executed.              |
| **`C:\Program Files`**                             | Malware may hide its payloads among legitimate software installations.                                 |
| **`C:\Users\<Username>\Documents`**                | Some malware uses user documents folders to disguise their presence or store harmful scripts.            |
| **`C:\Users\<Username>\Downloads`**                | Frequently used for dropping malicious executables disguised as legitimate downloads.                    |
| **`C:\Windows\Installer`**                         | Malware may manipulate or place files within this directory to execute during software installation processes. |
| **`C:\Windows\INF`**                               | Contains driver installation files; can be manipulated to install malicious drivers.                    |
| **`C:\Windows\System32\drivers`**                  | Directory for system drivers; malware may place malicious drivers here to gain low-level access.       |
| **`C:\Program Files (x86)`**                       | Similar to the Program Files directory, used for 32-bit applications on 64-bit systems; malware may hide here. |
| **`C:\Users\<Username>\AppData\Roaming`**         | Often used for storing application settings; can be exploited by malware to maintain persistence.      |
| **`C:\Windows\SysWOW64`**                          | Used for 32-bit binaries on 64-bit systems; similar threats as System32, where malware may reside.    |
| **`C:\Program Files\Microsoft Office\root\OfficeXX`** | Default installation path for Microsoft Outlook (replace "XX" with the version number, e.g., Office16 for Outlook 2016). |
| **`C:\Program Files\Microsoft\Exchange\`**        | Default installation path for Microsoft Exchange Server.                                              |
| **`C:\Windows\`**									| Malicious software often disguises itself as legitimate files here. |


**Users and Groups information**

```powershell

# Get local users and groups :

Get-LocalUser -SID s-1-5-21-xxx
# show local users
Net User
# See specific Local Groups
Get-LocalGroup "Remote Desktop Users"

#For Domain Users:

# show domain users
Net user /domain
# show details about specific domain user (Check for last password set for ciritical accounts)
Net user /domain <username>
# show domain groups
Net Groups /domain
```

**Checking Processes**
```powershell
Get-process
tasklist
```
common indicators for identifying suspicious processes in Windows using the `tasklist` and `Get-Process` commands in PowerShell:

| **Indicator**                    | **Description**                                                                                                           |
|----------------------------------|---------------------------------------------------------------------------------------------------------------------------|
| **Unusual Process Names**        | Look for processes with names that seem out of context or are similar to legitimate processes but slightly altered.        |
| **High CPU or Memory Usage**     | Processes that consume an unusually high percentage of CPU or memory resources may indicate malicious activity.            |
| **Unexpected Parent Processes**  | Processes spawned by unfamiliar or suspicious parent processes can indicate exploitation or injection.                    |
| **Running from Uncommon Paths**  | Processes located in temporary directories (`%TEMP%`, `%APPDATA%`) or non-standard folders may be suspect.               |
| **No Digital Signature**         | Check if the process is unsigned or has an invalid signature, especially for system-critical processes.                    |
| **Network Activity**             | Processes initiating unexpected network connections (identified by using `Netstat` alongside process information).        |
| **Unexpected User Context**      | Processes running under unfamiliar user accounts or SYSTEM privileges can be suspicious.                                  |
| **File Modifications**           | Processes modifying system files or registry entries unexpectedly can indicate malicious behavior.                        |
| **High I/O Operations**          | High disk input/output activity from a process may suggest unauthorized data exfiltration or system compromise.           |
| **Multiple Instances**           | Multiple instances of the same process running simultaneously can be a sign of malware behavior.                         |


**Network Auditing**

You can use `Netstat -ano` command on powershell for check connections Established/listening ports and check IP addresses for suspicous connections,ports etc...

common indicators of suspicious connections that may warrant further investigation in a network environment:

| **Connection Type**             | **Description**                                                                                   |
|---------------------------------|---------------------------------------------------------------------------------------------------|
| **Unusual Remote IP Addresses** | Connections to known malicious IPs, suspicious geolocations, or previously unauthorized addresses.|
| **High Frequency Connections**   | Rapid or excessive outbound connections to the same or different IPs, indicating possible exfiltration or scanning activities.|
| **Uncommon Ports**              | Traffic on non-standard ports (not typical for HTTP, HTTPS, FTP) can signify bypass attempts or exploitation.                     |
| **Peer-to-Peer Traffic**        | Connections involving P2P protocols may indicate the use of file-sharing malware or unauthorized data transfer.                  |
| **Connections to Known C2 Servers** | Traffic to command and control (C2) servers known for distributing malware or controlling compromised systems.               |
| **Frequent DNS Lookups**       | Excessive DNS queries to specific domains, especially by a single application, can indicate the presence of DNS tunneling or malware. |
| **Localhost Connections**       | Unexpected connections from external IPs to localhost (127.0.0.1) can indicate loopback exploitation or tunneling. |
| **Unencrypted Traffic**         | Sensitive information transmitted over unencrypted connections (HTTP instead of HTTPS) can lead to data leaks or man-in-the-middle attacks. |
| **Connections During Odd Hours** | Traffic during unusual times (outside of normal operating hours) can signify malicious activity or unauthorized access attempts. |
| **Suspicious User-Agent Strings** | Unexpected or uncommon user-agent strings in HTTP traffic might indicate automated scripts or malware attempting to communicate. |


**EventID**

Keep in mind This is one of the most important parts of threat hunting in windows evniroments.

```powershell
# Detecting RDP BruteForce using 4625 EventID from Security logs (Also check this on SIEM)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} | Measure-Object
Get-WinEvent -LogName Security -InstanceId 4625 | Select-Object * | Measure-Object

# Check for encoded powershell commands
Get-Winevent -LogName 'Windows Powershell' | Where-Object { $_.Message -match '(--EncodedCommand| -enc| FromBase64String| Encoded)' | Select-Object *

# Check for script downloaders
Get-winevent -LogName 'Windows Powershell' | Where-Object { $_.Message -match 'Invoke-WebRequest| Invoke-RestMethod| curl| wget' } | Select-Object *
```
**Top Common EventIDs you can check :**

| **EVENT ID** | **Description**                                                                                         |
|--------------|---------------------------------------------------------------------------------------------------------|
| `1100`       | The audit log was cleared.                                                                              |
| `1102`       | The audit log was cleared.                                                                              |
| `4103`       | The security event log was cleared.                                                                     |
| `4104`       | A script block was logged.                                                                               |
| `4105`       | A script block was executed.                                                                             |
| `4106`       | Windows PowerShell received a suspicious command.                                                        |
| `4624`       | An account was successfully logged on.                                                                    |
| `4625`       | An account failed to log on.                                                                             |
| `4634`       | An account was logged off.                                                                               |
| `4648`       | A logon attempt was made using explicit credentials.                                                    |
| `4672`       | Special privileges assigned to new logon.                                                               |
| `4698`       | A scheduled task was created.                                                                            |
| `4719`       | System audit policy was changed.                                                                         |
| `4720`       | A user account was created.                                                                              |
| `4722`       | A user account was enabled.                                                                              |
| `4723`       | An attempt was made to change an account's password.                                                    |
| `4724`       | An attempt was made to reset an account's password.                                                     |
| `4725`       | A user account was disabled.                                                                             |
| `4726`       | A user account was deleted.                                                                              |
| `4728`       | A user was added to a group.                                                                             |
| `4732`       | A member was added to a security-enabled local group.                                                    |
| `4756`       | A security-enabled universal group was modified.                                                        |
| `5140`       | A network share was accessed.                                                                            |
| `5145`       | A network share object was accessed.                                                                     |
| `5156`       | Windows Filtering Platform blocked a connection.                                                         |
| `7045`       | A service was installed on the system.                                                                   |
| `4656`       | A handle to an object was requested.                                                                    |
| `4663`       | An attempt was made to access an object.                                                                |
| `4702`       | A scheduled task was updated.                                                                            |
| `4703`       | The permissions on an object were changed.                                                               |
| `4704`       | A job was created.                                                                                      |
| `4729`       | A member was removed from a security-enabled global group.                                              |
| `4767`       | A user account's password was changed.                                                                  |
| `4871`       | A security-enabled global group was modified.                                                           |
| `4740`       | A user account was locked out.                                                                           |
| `4735`       | A security-enabled local group was changed.                                                             |
| `4731`       | A security-enabled local group was created.                                                              |
| `4647`       | User initiated logoff.                                                                                  |


**More in SYSMON**

| **Sysmon EVENT ID** | **Description**                                                                                         |
|----------------------|---------------------------------------------------------------------------------------------------------|
| `1`                  | Process creation, useful for detecting unusual or malicious processes.                                  |
| `3`                  | Network connection detected, valuable for identifying unauthorized network activity.                    |
| `5`                  | Process terminated, important for monitoring unexpected terminations.                                   |
| `6`                  | Driver loaded, useful for detecting malicious drivers.                                                 |
| `7`                  | Image loaded, helps identify suspicious or malicious DLLs.                                             |
| `11`                 | File created, crucial for detecting suspicious file creation.                                          |
| `12`                 | Registry object added or modified, useful for identifying persistence mechanisms and configuration changes. |
| `15`                 | File deleted, important for tracking suspicious deletions.                                             |
| `21`                 | Process command line changed, useful for identifying attempts to modify running command lines.         |
| `22`                 | Driver unloaded, helpful for monitoring the removal of potentially malicious drivers.                   |
| `23`                 | Process tampering, indicates unauthorized changes to processes.                                        |
| `24`                 | DNS query, valuable for identifying suspicious DNS activity, such as lookups related to C2 servers.   |

---

**Note that You can Check Many scenarios using these mentioned commands, as a hacker/hunter use your Creativity here too :)**










